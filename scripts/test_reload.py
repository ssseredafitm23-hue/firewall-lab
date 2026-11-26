import json
import socket
import http.client
import time
import os

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

TOKEN = Path("config/admin.key").read_text().strip()
PATH = Path("config/runtime.json")
LOG = Path("logs/events.jsonl")
passed = 0


def check(name, condition):
    global passed
    assert condition, name
    passed += 1
    print("[PASS]", name, flush=True)


def api(method, path, expected=200):
    conn = http.client.HTTPConnection(
        "127.0.0.1", 8081, timeout=5
    )

    try:
        conn.request(method, path, headers={
            "Authorization": "Bearer " + TOKEN
        })

        response = conn.getresponse()
        data = json.loads(response.read())

        assert response.status == expected, data
        return data
    finally:
        conn.close()


def tcp(port):
    conn = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=3
    )

    try:
        conn.request("GET", "/health")
        response = conn.getresponse()
        return response.status == 200 and (
            json.loads(response.read())["status"] == "ok"
        )
    except (ConnectionResetError, BrokenPipeError,
            http.client.RemoteDisconnected):
        return False
    finally:
        conn.close()


def udp(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.send(b"PARALLEL TEST")
        return s.recv(65535) == b"PARALLEL TEST"


def write_config(text):
    tmp = PATH.with_suffix(".test.tmp")
    tmp.write_text(text)
    tmp.chmod(0o600)
    os.replace(tmp, PATH)


original = PATH.read_text()
cfg = json.loads(original)
initial = api("GET", "/health")

assert len(cfg["rules"]) == 4

for rule in cfg["rules"]:
    if rule["proto"] == "TCP" and rule["direction"] == "IN":
        rule["enabled"] = False

print("=== HOT RELOAD AND CONTINUITY ===")

try:
    with socket.create_connection(
        ("127.0.0.1", 8080), timeout=3
    ) as existing:

        existing.sendall(b"GET /health HTTP/1.0\r\n")
        source_port = existing.getsockname()[1]

        accepted = False
        deadline = time.monotonic() + 2

        while time.monotonic() < deadline:
            for line in LOG.read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue

                if (
                    event.get("event") == "traffic.allowed"
                    and event.get("run_id") == initial["run_id"]
                    and event.get("src_port") == source_port
                    and event.get("listen_port") == 8080
                ):
                    accepted = True
                    break

            if accepted:
                break

            time.sleep(0.05)

        check("Existing TCP connection accepted", accepted)

        write_config(json.dumps(cfg, indent=2))
        result = api("POST", "/reload")

        check("Hot reload applied",
              result["version"] > initial["rules_version"])

        check("New TCP IN connection denied", not tcp(8080))

        existing.sendall(b"\r\n")
        response = existing.makefile("rb")

        check("Existing TCP connection remains active",
              b"200 OK" in response.readline())

        response.close()

    print("\n=== PARALLEL TRAFFIC ===")

    with ThreadPoolExecutor(max_workers=6) as pool:
        tasks = [
            pool.submit(tcp, 8082),
            pool.submit(udp, 5353),
            pool.submit(udp, 5354),
            pool.submit(tcp, 8082),
            pool.submit(udp, 5353),
            pool.submit(udp, 5354)
        ]

        health = api("GET", "/health")

        check("Admin API available",
              health["status"] == "ok")

        check("Six parallel network requests",
              all(task.result() for task in tasks))

    print("\n=== INVALID RELOAD ===")

    previous = api("GET", "/health")
    write_config("{invalid json")

    api("POST", "/reload", expected=400)
    check("Invalid configuration rejected", True)

    current = api("GET", "/health")

    check("Previous rules version preserved",
          previous["rules_version"] == current["rules_version"])

    check("Active policy preserved",
          not tcp(8080) and tcp(8082))

finally:
    write_config(original)
    api("POST", "/reload")

print("\n=== FINAL STATE ===")

check("Original policy restored", tcp(8080))

final = api("GET", "/health")

check("Process PID and run ID unchanged",
      final["pid"] == initial["pid"]
      and final["run_id"] == initial["run_id"])

print("PID:", final["pid"])
print("Rules version:", initial["rules_version"],
      "->", final["rules_version"])

print(f"\nALL {passed} CHECKS PASSED")
