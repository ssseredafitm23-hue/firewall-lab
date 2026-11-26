from dataclasses import dataclass, asdict
from ipaddress import IPv4Address, IPv4Network


def check_int(name, value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")
    return value


def check_choice(name, value, choices):
    if not isinstance(value, str):
        raise ValueError(f"Invalid {name}")
    value = value.upper()
    if value not in choices:
        raise ValueError(f"Invalid {name}")
    return value


def check_cidr(value):
    if not isinstance(value, str):
        raise ValueError("Invalid IPv4 CIDR")
    return str(IPv4Network(value, strict=False))


@dataclass(frozen=True)
class Rule:
    id: int
    action: str
    src_ip_cidr: str = "0.0.0.0/0"
    dst_ip_cidr: str = "0.0.0.0/0"
    src_port: int = 0
    dst_port: int = 0
    proto: str = "ANY"
    direction: str = "ANY"
    priority: int = 100
    enabled: bool = True

    def __post_init__(self):
        check_int("id", self.id, 1, 2147483647)
        check_int("src_port", self.src_port, 0, 65535)
        check_int("dst_port", self.dst_port, 0, 65535)
        check_int("priority", self.priority, 1, 65535)

        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")

        object.__setattr__(
            self, "action",
            check_choice("action", self.action, {"ALLOW", "DENY"})
        )
        object.__setattr__(
            self, "proto",
            check_choice("proto", self.proto, {"TCP", "UDP", "ANY"})
        )
        object.__setattr__(
            self, "direction",
            check_choice("direction", self.direction, {"IN", "OUT", "ANY"})
        )
        object.__setattr__(
            self, "src_ip_cidr", check_cidr(self.src_ip_cidr)
        )
        object.__setattr__(
            self, "dst_ip_cidr", check_cidr(self.dst_ip_cidr)
        )

    def to_dict(self):
        return asdict(self)

    def matches(self, src_ip, src_port, dst_ip, dst_port,
                proto, direction):
        return (
            self.enabled
            and IPv4Address(src_ip) in IPv4Network(self.src_ip_cidr)
            and IPv4Address(dst_ip) in IPv4Network(self.dst_ip_cidr)
            and self.src_port in (0, src_port)
            and self.dst_port in (0, dst_port)
            and self.proto in ("ANY", proto.upper())
            and self.direction in ("ANY", direction.upper())
        )


def evaluate(rules, src_ip, src_port, dst_ip, dst_port,
             proto, direction):

    for rule in sorted(rules, key=lambda r: (r.priority, r.id)):
        if rule.matches(
            src_ip, src_port, dst_ip, dst_port, proto, direction
        ):
            return rule.action, rule.id, "matched_rule"

    return "DENY", None, "default_deny"
