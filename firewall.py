import argparse
import os
import re
import signal
import threading

from pathlib import Path
from ipaddress import IPv4Address

from core.config_manager import RuleManager
from core.logger import EventLogger
from core.proxy import create_proxy
from api.admin import create_admin


def main():
    os.umask(0o077)

    parser = argparse.ArgumentParser(
        description="Lab 7 Software Firewall"
    )
    parser.add_argument(
        "--config", default="config/runtime.json"
    )
    parser.add_argument(
        "--token-file", default="config/admin.key"
    )
    args = parser.parse_args()

    token = Path(args.token_file).read_text().strip()

    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Invalid admin token")

    manager = RuleManager(args.config)
    cfg = manager.static

    for service in cfg["services"]:
        for key in ("listen_host", "target_host"):
            if not IPv4Address(service[key]).is_loopback:
                raise ValueError(
                    "Only local laboratory routes are allowed"
                )

    events = EventLogger(cfg["logging"]["path"])

    servers = []
    threads = []
    stop = threading.Event()

    signal.signal(
        signal.SIGTERM,
        lambda *_: stop.set()
    )

    try:
        for service in cfg["services"]:
            servers.append(
                create_proxy(service, manager, events)
            )

        admin = create_admin(
            cfg["admin"], manager, events, token
        )
        servers.append(admin)

        for server in servers:
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.2},
                daemon=True
            )
            thread.start()
            threads.append((server, thread))

        events.emit(
            "firewall.started",
            pid=os.getpid(),
            rules_version=manager.version,
            services=len(cfg["services"]),
            default_policy="DENY"
        )

        print("=== LAB 7 SOFTWARE FIREWALL ===")
        print("PID:", os.getpid())
        print("Run ID:", events.run_id)
        print("Default policy: DENY")
        print("Active rules:", len(manager.list_rules()))

        for service in cfg["services"]:
            print(
                service["direction"],
                service["proto"],
                service["listen_port"],
                "->",
                service["target_port"]
            )

        print("Admin API: 127.0.0.1:8081")
        print("Press Ctrl+C to stop", flush=True)

        stop.wait()

    except KeyboardInterrupt:
        pass

    finally:
        print("\nStopping firewall...", flush=True)

        for server in servers:
            if hasattr(server, "stopping"):
                server.stopping.set()

        for server, thread in threads:
            server.shutdown()
            thread.join()

        for server in servers:
            server.server_close()

        events.emit("firewall.stopped")
        events.close()

        print("Firewall stopped", flush=True)


if __name__ == "__main__":
    main()
