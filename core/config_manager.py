import json
import os
import tempfile
from pathlib import Path
from threading import RLock

from core.rules import Rule, evaluate
from core.conflicts import detect_conflicts


class ConflictError(ValueError):
    def __init__(self, findings):
        self.findings = findings
        super().__init__("Conflicting rules")


class RuleManager:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = RLock()

        cfg = self._read()
        self.static = {
            k: v for k, v in cfg.items() if k != "rules"
        }

        self.rules, _ = self._validate(cfg["rules"])
        self.version = 1
        self.next_id = max(
            (r.id for r in self.rules), default=0
        ) + 1

    def _read(self):
        cfg = json.loads(
            self.path.read_text(encoding="utf-8")
        )

        if not isinstance(cfg, dict) or "rules" not in cfg:
            raise ValueError("Invalid configuration")

        return cfg

    def _validate(self, rows):
        if not isinstance(rows, list) or len(rows) > 256:
            raise ValueError("Invalid rule list")

        try:
            rules = tuple(Rule(**row) for row in rows)
        except TypeError as exc:
            raise ValueError("Invalid rule fields") from exc

        ids = [r.id for r in rules]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate rule IDs")

        findings = detect_conflicts(rules)

        if any(f["severity"] == "ERROR" for f in findings):
            raise ConflictError(findings)

        return rules, findings

    def _save(self, rules):
        cfg = {
            **self.static,
            "rules": [r.to_dict() for r in rules]
        }

        fd, name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=".rules-",
            suffix=".tmp"
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, allow_nan=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())

            os.replace(name, self.path)

        finally:
            Path(name).unlink(missing_ok=True)

    def _commit(self, rows):
        rules, findings = self._validate(rows)

        self._save(rules)

        self.rules = rules
        self.version += 1

        self.next_id = max(
            self.next_id,
            max((r.id for r in rules), default=0) + 1
        )

        return {
            "version": self.version,
            "warnings": findings
        }

    def snapshot(self):
        with self.lock:
            return self.rules, self.version

    def list_rules(self):
        rules, _ = self.snapshot()
        return [r.to_dict() for r in rules]

    def decide(self, src_ip, src_port, dst_ip,
               dst_port, proto, direction):

        rules, version = self.snapshot()

        action, rule_id, reason = evaluate(
            rules, src_ip, src_port, dst_ip,
            dst_port, proto, direction
        )

        return action, rule_id, reason, version

    def add(self, data):
        with self.lock:
            if not isinstance(data, dict) or "id" in data:
                raise ValueError("Invalid rule data")

            rule_id = self.next_id

            rows = self.list_rules()
            rows.append({"id": rule_id, **data})

            result = self._commit(rows)
            return {"id": rule_id, **result}

    def patch(self, rule_id, changes):
        with self.lock:
            if not isinstance(changes, dict) or "id" in changes:
                raise ValueError("Invalid changes")

            rows = self.list_rules()

            for row in rows:
                if row["id"] == rule_id:
                    row.update(changes)
                    return self._commit(rows)

            raise KeyError(rule_id)

    def delete(self, rule_id):
        with self.lock:
            rows = self.list_rules()
            updated = [
                row for row in rows
                if row["id"] != rule_id
            ]

            if len(updated) == len(rows):
                raise KeyError(rule_id)

            return self._commit(updated)

    def reload(self):
        with self.lock:
            cfg = self._read()

            static = {
                k: v for k, v in cfg.items()
                if k != "rules"
            }

            if static != self.static:
                raise ValueError(
                    "Only rules can be hot-reloaded"
                )

            return self._commit(cfg["rules"])

    def conflicts(self):
        rules, _ = self.snapshot()
        return detect_conflicts(rules)
