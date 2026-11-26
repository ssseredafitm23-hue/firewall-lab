import os
import json
import hmac
import re

from http.server import BaseHTTPRequestHandler, HTTPServer
from core.config_manager import ConflictError


MAX_BODY = 16384


class AdminServer(HTTPServer):
    allow_reuse_address = True

    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(3)
        return conn, addr


class AdminHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def respond(self, status, data):
        body = json.dumps(
            data, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def audit(self, event, **fields):
        self.server.events.emit(
            event,
            src_ip=self.client_address[0],
            method=self.command,
            **fields
        )

    def authorized(self):
        supplied = self.headers.get(
            "Authorization", ""
        ).encode("utf-8")

        expected = (
            "Bearer " + self.server.token
        ).encode("utf-8")

        return hmac.compare_digest(supplied, expected)

    def read_json(self):
        length = int(
            self.headers.get("Content-Length", "0")
        )

        if not 0 < length <= MAX_BODY:
            raise ValueError("Invalid request size")

        raw = self.rfile.read(length)

        if len(raw) != length:
            raise ValueError("Incomplete request")

        data = json.loads(raw.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("JSON object required")

        return data

    def dispatch(self):
        manager = self.server.manager

        if not self.authorized():
            self.audit(
                "admin.auth_failed",
                reason="invalid_token"
            )
            return 401, {"error": "Unauthorized"}

        path = self.path
        method = self.command

        match = re.fullmatch(
            r"/rules/([1-9][0-9]{0,9})", path
        )

        rule_id = int(match.group(1)) if match else None

        if method == "GET":
            if path == "/health":
                rules, version = manager.snapshot()
                return 200, {
                    "status": "ok",
                    "pid": os.getpid(),
                    "run_id": self.server.events.run_id,
                    "rules_version": version,
                    "rules_count": len(rules),
                    "default_policy": "DENY"
                }

            if path == "/rules":
                return 200, manager.list_rules()

            if path == "/conflicts":
                return 200, manager.conflicts()

            if path == "/stats":
                return 200, self.server.events.stats()

            if rule_id is not None:
                for rule in manager.list_rules():
                    if rule["id"] == rule_id:
                        return 200, rule
                raise KeyError(rule_id)

        if method == "POST" and path == "/rules":
            result = manager.add(self.read_json())
            self.audit("admin.rule_added", **result)
            return 201, result

        if method == "PATCH" and rule_id is not None:
            result = manager.patch(
                rule_id, self.read_json()
            )
            self.audit(
                "admin.rule_updated",
                rule_id=rule_id,
                **result
            )
            return 200, result

        if method == "DELETE" and rule_id is not None:
            result = manager.delete(rule_id)
            self.audit(
                "admin.rule_deleted",
                rule_id=rule_id,
                **result
            )
            return 200, result

        if method == "POST" and path == "/reload":
            result = manager.reload()
            self.audit("admin.rules_reloaded", **result)
            return 200, result

        return 404, {"error": "Not found"}

    def handle_api(self):
        try:
            status, result = self.dispatch()

        except ConflictError as exc:
            self.audit(
                "admin.conflict_rejected",
                findings=exc.findings
            )
            status = 409
            result = {
                "error": "Conflicting rules",
                "findings": exc.findings
            }

        except KeyError:
            status = 404
            result = {"error": "Rule not found"}

        except (ValueError, TypeError, RecursionError):
            self.audit(
                "admin.request_rejected",
                reason="invalid_data"
            )
            status = 400
            result = {"error": "Invalid request or configuration"}

        except OSError:
            self.audit(
                "admin.error",
                reason="io_error"
            )
            status = 500
            result = {"error": "Operation failed"}

        try:
            self.respond(status, result)
        except OSError:
            pass

    do_GET = handle_api
    do_POST = handle_api
    do_PATCH = handle_api
    do_DELETE = handle_api


def create_admin(config, manager, events, token):
    if config["host"] != "127.0.0.1":
        raise ValueError("Admin API must use loopback")

    server = AdminServer(
        (config["host"], config["port"]),
        AdminHandler
    )

    server.manager = manager
    server.events = events
    server.token = token

    return server
