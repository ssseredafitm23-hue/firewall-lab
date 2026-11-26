import argparse
import csv
import json

from collections import Counter, defaultdict, deque
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path


TRAFFIC = {"traffic.allowed", "traffic.denied"}


def timestamp(value):
    result = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )
    if result.tzinfo is None:
        raise ValueError("Timezone required")
    return result


def load_events(path):
    events = []
    malformed = 0

    files = [
        path.with_name(path.name + f".{i}")
        for i in range(3, 0, -1)
    ] + [path]

    for file in files:
        if not file.is_file():
            continue

        for line in file.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("Invalid event")
                timestamp(event["timestamp"])
                if not isinstance(event["event"], str):
                    raise ValueError("Invalid event type")
                events.append(event)

            except (ValueError, TypeError, KeyError, AttributeError):
                malformed += 1

    events.sort(key=lambda e: timestamp(e["timestamp"]))
    return events, malformed


def detect_anomalies(events, threshold, window):
    histories = defaultdict(deque)
    alerts = []

    for event in events:
        if event["event"] != "traffic.denied":
            continue

        ip = event["src_ip"]
        now = timestamp(event["timestamp"]).timestamp()
        queue = histories[(event.get("run_id"), ip)]

        while queue and now - queue[0] > window:
            queue.popleft()

        queue.append(now)

        if len(queue) == threshold:
            alerts.append({
                "event": "DENY_ANOMALY",
                "severity": "ALERT",
                "timestamp": event["timestamp"],
                "src_ip": ip,
                "denied_count": len(queue),
                "window_seconds": window
            })

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Firewall event analyzer"
    )

    parser.add_argument(
        "path", nargs="?", default="logs/events.jsonl"
    )

    parser.add_argument("--action", choices=["ALLOW", "DENY"])
    parser.add_argument("--proto", choices=["TCP", "UDP"])
    parser.add_argument("--direction", choices=["IN", "OUT"])
    parser.add_argument("--src")
    parser.add_argument("--dst")
    parser.add_argument("--src-port", type=int)
    parser.add_argument("--port", type=int)
    parser.add_argument("--rule-id", type=int)
    parser.add_argument("--reason")
    parser.add_argument("--since", type=timestamp)
    parser.add_argument("--until", type=timestamp)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=60)
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--csv")

    args = parser.parse_args()

    if args.threshold < 1 or args.window < 1:
        parser.error("Invalid anomaly parameters")

    try:
        src = ip_network(args.src, strict=False) if args.src else None
        dst = ip_network(args.dst, strict=False) if args.dst else None
    except ValueError as exc:
        parser.error(str(exc))

    events, malformed = load_events(Path(args.path))

    traffic = [e for e in events if e["event"] in TRAFFIC]

    print("=== FIREWALL SECURITY ANALYSIS ===")
    print("Total records:", len(events))
    print("Malformed records:", malformed)
    print("Traffic decisions:", len(traffic))

    print("\n=== EVENT TYPES ===")
    for key, count in Counter(e["event"] for e in events).most_common():
        print(f"{key}: {count}")

    print("\n=== TRAFFIC STATISTICS ===")

    for field in ("action", "protocol", "direction", "reason", "rule_id"):
        print(field + ":")
        for key, count in Counter(
            str(e.get(field)) for e in traffic
        ).most_common():
            print(f"  {key}: {count}")

    denied = [e for e in traffic if e["action"] == "DENY"]

    print("\n=== TOP DENIED SOURCES ===")
    for ip, count in Counter(
        e["src_ip"] for e in denied
    ).most_common(5):
        print(f"{ip}: {count}")

    print("\n=== ANOMALY DETECTION ===")
    alerts = detect_anomalies(
        traffic, args.threshold, args.window
    )

    print("Threshold:", args.threshold)
    print("Window:", args.window, "seconds")
    print("Detected anomalies:", len(alerts))

    for alert in alerts:
        print("SECURITY ALERT:", json.dumps(alert))

    print("\n=== FILTERED TRAFFIC ===")

    criteria = {
        "action": args.action,
        "protocol": args.proto,
        "direction": args.direction,
        "src_port": args.src_port,
        "dst_port": args.port,
        "rule_id": args.rule_id,
        "reason": args.reason
    }

    selected = []

    for event in traffic:
        if any(
            value is not None and event.get(key) != value
            for key, value in criteria.items()
        ):
            continue

        if src and ip_address(event["src_ip"]) not in src:
            continue

        if dst and ip_address(event["dst_ip"]) not in dst:
            continue

        ts = timestamp(event["timestamp"])

        if args.since and ts < args.since:
            continue

        if args.until and ts > args.until:
            continue

        selected.append(event)

    print("Matching records:", len(selected))

    if args.show:
        for event in selected:
            print(json.dumps(event, ensure_ascii=False))

    if args.csv:
        fields = [
            "timestamp", "run_id", "connection_id",
            "event", "direction", "protocol",
            "src_ip", "src_port", "dst_ip", "dst_port",
            "action", "rule_id", "reason", "rules_version"
        ]

        path = Path(args.csv)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
            )
            writer.writeheader()
            writer.writerows(selected)

        print("CSV exported:", path)

    print("\nAnalysis completed")


if __name__ == "__main__":
    main()
