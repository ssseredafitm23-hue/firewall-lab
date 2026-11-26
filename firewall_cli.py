import argparse
import json

from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError, URLError


def main():
    parser = argparse.ArgumentParser(
        description="Firewall administration CLI"
    )

    parser.add_argument(
        "command",
        choices=[
            "health", "rules", "get", "add",
            "patch", "delete", "reload",
            "conflicts", "stats"
        ]
    )
    parser.add_argument("args", nargs="*")
    args = parser.parse_args()

    command = args.command
    values = args.args

    expected = {
        "get": 1, "add": 1,
        "patch": 2, "delete": 1
    }.get(command, 0)

    if len(values) != expected:
        parser.error("Invalid number of arguments")

    method = "GET"
    body = None
    path = "/" + command

    if command == "get":
        path = "/rules/" + str(int(values[0]))

    elif command == "add":
        method, path = "POST", "/rules"
        body = json.loads(values[0])

    elif command == "patch":
        method = "PATCH"
        path = "/rules/" + str(int(values[0]))
        body = json.loads(values[1])

    elif command == "delete":
        method = "DELETE"
        path = "/rules/" + str(int(values[0]))

    elif command == "reload":
        method = "POST"

    token = Path("config/admin.key").read_text().strip()

    request = Request(
        "http://127.0.0.1:8081" + path,
        method=method,
        data=json.dumps(body).encode()
        if body is not None else None,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
        }
    )

    opener = build_opener(ProxyHandler({}))

    try:
        with opener.open(request, timeout=5) as response:
            print("HTTP", response.status)
            print(json.dumps(
                json.load(response),
                indent=2,
                ensure_ascii=False
            ))

    except HTTPError as exc:
        print("HTTP", exc.code)
        print(exc.read().decode())
        return 1

    except URLError:
        print("Admin API unavailable")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
