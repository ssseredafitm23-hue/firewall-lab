import select
import socket
import socketserver
import threading
import time
import uuid


CONNECT_TIMEOUT = 3
IDLE_TIMEOUT = 10
UDP_TIMEOUT = 3
MAX_WORKERS = 32
BUFFER_SIZE = 65535


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = False
    block_on_close = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.events.emit(
                "proxy.rejected",
                src_ip=client_address[0],
                src_port=client_address[1],
                dst_ip=self.target[0],
                dst_port=self.target[1],
                protocol=self.proto,
                direction=self.direction,
                reason="resource_limit"
            )
            self.shutdown_request(request)
            return

        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(
                request, client_address
            )
        finally:
            self.slots.release()


class TCPProxyServer(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = True


class UDPProxyServer(BoundedThreads, socketserver.UDPServer):
    max_packet_size = BUFFER_SIZE


def traffic_decision(server, client_address, **extra):
    src_ip, src_port = client_address
    dst_ip, dst_port = server.target

    action, rule_id, reason, version = server.manager.decide(
        src_ip, src_port,
        dst_ip, dst_port,
        server.proto, server.direction
    )

    fields = {
        "connection_id": uuid.uuid4().hex,
        "direction": server.direction,
        "protocol": server.proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "listen_port": server.server_address[1],
        "rule_id": rule_id,
        "rules_version": version
    }

    server.events.emit(
        "traffic.allowed" if action == "ALLOW"
        else "traffic.denied",
        action=action,
        reason=reason,
        **fields,
        **extra
    )

    return action, fields


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        client = self.request

        action, fields = traffic_decision(
            server, self.client_address
        )

        if action == "DENY":
            return

        transferred = 0

        try:
            with socket.create_connection(
                server.target,
                timeout=CONNECT_TIMEOUT
            ) as upstream:

                client.settimeout(CONNECT_TIMEOUT)
                upstream.settimeout(CONNECT_TIMEOUT)

                peers = {
                    client: upstream,
                    upstream: client
                }

                active = [client, upstream]
                last_activity = time.monotonic()

                while active and not server.stopping.is_set():

                    if time.monotonic() - last_activity > IDLE_TIMEOUT:
                        break

                    readable, _, _ = select.select(
                        active, [], [], 0.5
                    )

                    for source in readable:
                        data = source.recv(BUFFER_SIZE)
                        destination = peers[source]

                        if not data:
                            active.remove(source)

                            try:
                                destination.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass

                            continue

                        destination.sendall(data)
                        transferred += len(data)
                        last_activity = time.monotonic()

        except OSError as exc:
            server.events.emit(
                "proxy.error",
                reason=type(exc).__name__,
                **fields
            )

        finally:
            server.events.emit(
                "tcp.closed",
                bytes_transferred=transferred,
                **fields
            )


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        data, listener = self.request

        action, fields = traffic_decision(
            server,
            self.client_address,
            bytes_received=len(data)
        )

        if action == "DENY":
            return

        try:
            with socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM
            ) as upstream:

                upstream.settimeout(UDP_TIMEOUT)
                upstream.connect(server.target)
                upstream.send(data)

                response = upstream.recv(BUFFER_SIZE)

                listener.sendto(
                    response, self.client_address
                )

            server.events.emit(
                "udp.forwarded",
                bytes_sent=len(data),
                bytes_returned=len(response),
                **fields
            )

        except OSError as exc:
            server.events.emit(
                "proxy.error",
                reason=type(exc).__name__,
                **fields
            )


def create_proxy(service, manager, events):
    proto = service["proto"].upper()
    direction = service.get("direction", "IN").upper()

    if proto not in ("TCP", "UDP"):
        raise ValueError("Unsupported protocol")

    if direction not in ("IN", "OUT"):
        raise ValueError("Invalid service direction")

    listen = (
        service["listen_host"],
        service["listen_port"]
    )

    if proto == "TCP":
        server = TCPProxyServer(listen, TCPHandler)
    else:
        server = UDPProxyServer(listen, UDPHandler)

    server.manager = manager
    server.events = events
    server.proto = proto
    server.direction = direction

    server.target = (
        service["target_host"],
        service["target_port"]
    )

    server.slots = threading.BoundedSemaphore(MAX_WORKERS)
    server.stopping = threading.Event()

    return server
