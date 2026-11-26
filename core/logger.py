import json
import logging
import uuid

from collections import Counter
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock


class EventLogger:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        self.lock = RLock()
        self.run_id = uuid.uuid4().hex
        self.counters = Counter()

        self.logger = logging.Logger("firewall")

        self.handler = RotatingFileHandler(
            path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )

        path.chmod(0o600)

        self.handler.setFormatter(
            logging.Formatter("%(message)s")
        )

        self.logger.addHandler(self.handler)

    def emit(self, event, **fields):
        record = {
            **fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event": event
        }

        with self.lock:
            self.logger.info(
                json.dumps(record, ensure_ascii=False, allow_nan=False)
            )

            self.counters[event] += 1

            if event in ("traffic.allowed", "traffic.denied"):
                self.counters[fields["action"]] += 1

    def stats(self):
        with self.lock:
            return dict(self.counters)

    def close(self):
        with self.lock:
            self.logger.removeHandler(self.handler)
            self.handler.close()
