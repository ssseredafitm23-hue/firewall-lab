import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1", 9000))
    print("UDP Echo server: 127.0.0.1:9000", flush=True)

    try:
        while True:
            data, addr = server.recvfrom(65535)
            print(f"Received {len(data)} bytes from {addr}", flush=True)
            server.sendto(data, addr)
    except KeyboardInterrupt:
        pass
