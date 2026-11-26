import json
import socket
import http.client

from pathlib import Path


TOKEN = Path("config/admin.key").read_text().strip()
passed = 0


def check(name, condition):
    global passed
    assert condition, name
    passed += 1
    print("[PASS]", name, flush=True)


def api(method, path, body=None, expected=200):
    conn = http.client.HTTPConnection(
        "127.0.0.1", 8081, timeout=5
    )

    try:
        conn.request(
            method, path,
            body=json.dumps(body) if body is not None else None,
            headers={
                "Authorization": "Bearer " + TOKEN,
                "Content-Type": "application/json"
            }
        )

        response = conn.getresponse()
        data = json.loads(response.read())

        assert response.status == expected, (
            response.status, data
        )

        return data

    finally:
        conn.close()


def tcp(port=8080, source="127.0.0.1"):
    conn = http.client.HTTPConnection(
        "127.0.0.1", port,
        timeout=3,
        source_address=(source, 0)
    )

    try:
        conn.request("GET", "/health")
        response = conn.getresponse()
        body = json.loads(response.read())

        return response.status == 200 and body["status"] == "ok"

    except (ConnectionResetError, BrokenPipeError,
            http.client.RemoteDisconnected):
        return False

    finally:
        conn.close()


def udp(port=5353):
    message = b"LAB7 DEMO UDP"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1.5)
        s.connect(("127.0.0.1", port))
        s.send(message)

        try:
            return s.recv(65535) == message
        except socket.timeout:
            return False


def add(**fields):
    return api("POST", "/rules", fields, 201)["id"]


def allow(proto, direction, port):
    return add(
        action="ALLOW",
        proto=proto,
        direction=direction,
        src_ip_cidr="127.0.0.0/8",
        dst_ip_cidr="127.0.0.1/32",
        dst_port=port,
        priority=20
    )


initial = api("GET", "/health")

assert api("GET", "/rules") == [], "Expected empty rule table"

print("=== DEFAULT POLICY ===")
print("PID:", initial["pid"])

check("Default deny TCP", not tcp())
check("Default deny UDP", not udp())

print("\n=== DYNAMIC RULE MANAGEMENT ===")

tcp_id = allow("TCP", "IN", 8000)
udp_id = allow("UDP", "IN", 9000)

check("TCP IN allowed", tcp())
check("UDP IN allowed", udp())
check("TCP OUT still denied", not tcp(8082))
check("UDP OUT still denied", not udp(5354))

out_tcp = allow("TCP", "OUT", 8000)
out_udp = allow("UDP", "OUT", 9000)

check("TCP OUT allowed", tcp(8082))
check("UDP OUT allowed", udp(5354))

print("\n=== IP FILTERING ===")

deny_id = add(
    action="DENY",
    proto="TCP",
    direction="IN",
    src_ip_cidr="127.0.0.2/32",
    dst_port=8000,
    priority=10
)

check("Source 127.0.0.1 allowed", tcp())
check("Source 127.0.0.2 denied", not tcp(source="127.0.0.2"))

api("PATCH", f"/rules/{deny_id}", {"enabled": False})
check("Disabled deny rule", tcp(source="127.0.0.2"))

api("PATCH", f"/rules/{deny_id}", {"enabled": True})
check("Re-enabled deny rule", not tcp(source="127.0.0.2"))

api("DELETE", f"/rules/{deny_id}")
check("Deleted deny rule", tcp(source="127.0.0.2"))

print("\n=== PORT FILTERING ===")

api("PATCH", f"/rules/{tcp_id}", {"dst_port": 8001})
check("Modified destination port", not tcp())
check("UDP unaffected by TCP rule", udp())

api("PATCH", f"/rules/{tcp_id}", {"dst_port": 8000})
check("Restored destination port", tcp())

print("\n=== CONFLICT HANDLING ===")

rule = api("GET", f"/rules/{tcp_id}")
rule.pop("id")

result = api("POST", "/rules", rule, 409)

check("Duplicate rejected",
      any(f["type"] == "DUPLICATE"
          for f in result["findings"]))

result = api(
    "POST", "/rules",
    {**rule, "action": "DENY"},
    409
)

check("Conflicting rule rejected",
      any(f["type"] == "CONFLICT"
          for f in result["findings"]))

api("POST", "/rules",
    {"action": "ALLOW", "dst_port": 70000}, 400)

check("Invalid port rejected", True)

check("Traffic remains operational", tcp() and udp())

print("\n=== PERSISTENCE AND CONTINUITY ===")

final = api("GET", "/health")

check("Same process PID", final["pid"] == initial["pid"])
check("Same run ID", final["run_id"] == initial["run_id"])
check("Rules version increased",
      final["rules_version"] > initial["rules_version"])

saved = json.loads(
    Path("config/runtime.json").read_text()
)["rules"]

check("Rules saved to disk",
      saved == api("GET", "/rules"))

print("Final PID:", final["pid"])
print("Rules version:", initial["rules_version"],
      "->", final["rules_version"])

print("\n=== FIREWALL STATISTICS ===")
print(json.dumps(api("GET", "/stats"), indent=2))

print(f"\nALL {passed} CHECKS PASSED")
