from ipaddress import IPv4Network


def field_overlap(a, b, wildcard):
    return a == b or a == wildcard or b == wildcard


def field_covers(a, b, wildcard):
    return a == wildcard or a == b


def overlaps(a, b):
    return (
        IPv4Network(a.src_ip_cidr).overlaps(
            IPv4Network(b.src_ip_cidr)
        )
        and IPv4Network(a.dst_ip_cidr).overlaps(
            IPv4Network(b.dst_ip_cidr)
        )
        and field_overlap(a.src_port, b.src_port, 0)
        and field_overlap(a.dst_port, b.dst_port, 0)
        and field_overlap(a.proto, b.proto, "ANY")
        and field_overlap(a.direction, b.direction, "ANY")
    )


def covers(a, b):
    return (
        IPv4Network(b.src_ip_cidr).subnet_of(
            IPv4Network(a.src_ip_cidr)
        )
        and IPv4Network(b.dst_ip_cidr).subnet_of(
            IPv4Network(a.dst_ip_cidr)
        )
        and field_covers(a.src_port, b.src_port, 0)
        and field_covers(a.dst_port, b.dst_port, 0)
        and field_covers(a.proto, b.proto, "ANY")
        and field_covers(a.direction, b.direction, "ANY")
    )


def detect_conflicts(rules):
    active = sorted(
        (r for r in rules if r.enabled),
        key=lambda r: (r.priority, r.id)
    )
    findings = []

    for i, a in enumerate(active):
        for b in active[i + 1:]:
            if not overlaps(a, b):
                continue

            same_scope = covers(a, b) and covers(b, a)

            if same_scope and a.action == b.action:
                kind, severity = "DUPLICATE", "ERROR"

            elif a.action != b.action and a.priority == b.priority:
                kind, severity = "CONFLICT", "ERROR"

            elif covers(a, b):
                kind, severity = "SHADOWING", "WARNING"

            elif a.action != b.action:
                kind, severity = "OVERLAP", "WARNING"

            else:
                continue

            findings.append({
                "type": kind,
                "severity": severity,
                "rule_ids": [a.id, b.id],
                "effective_rule": a.id if severity == "WARNING" else None
            })

    return findings
