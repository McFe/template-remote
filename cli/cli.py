import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import socket
import sys
from pathlib import Path
from urllib import error, request


CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
TIMEOUT_SECONDS = 10
NO_PROXY_OPENER = request.build_opener(request.ProxyHandler({}))


class RelayRequestError(Exception):
    def __init__(self, message, *, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def load_relay_url():
    relay_url = os.environ.get("RELAY_URL", "").strip()
    if relay_url:
        return relay_url.rstrip("/")

    if CONFIG_PATH.exists():
        try:
            config_data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except OSError as exc:
            print(f"Failed to read config file at {CONFIG_PATH}: {exc}", file=sys.stderr)
            raise SystemExit(1)
        except json.JSONDecodeError as exc:
            print(f"Failed to parse JSON in {CONFIG_PATH}: {exc}", file=sys.stderr)
            raise SystemExit(1)

        relay_url = str(config_data.get("relay_url", "")).strip()
        if relay_url:
            return relay_url.rstrip("/")

    print(
        f"Relay URL is not configured. Set RELAY_URL or update {CONFIG_PATH}.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def load_pull_token():
    pull_token = os.environ.get("PULL_TOKEN", "").strip()
    if pull_token:
        return pull_token

    if CONFIG_PATH.exists():
        try:
            config_data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except OSError as exc:
            print(f"Failed to read config file at {CONFIG_PATH}: {exc}", file=sys.stderr)
            raise SystemExit(1)
        except json.JSONDecodeError as exc:
            print(f"Failed to parse JSON in {CONFIG_PATH}: {exc}", file=sys.stderr)
            raise SystemExit(1)

        pull_token = str(config_data.get("pull_token", "")).strip()
        if pull_token:
            return pull_token

    return ""


def get_relay_http_error_message(exc):
    error_body = exc.read().decode("utf-8", errors="replace")

    try:
        error_data = json.loads(error_body)
    except json.JSONDecodeError:
        error_data = None

    if isinstance(error_data, dict):
        detail = error_data.get("detail")
        if isinstance(detail, dict):
            message = detail.get("message")
            if message:
                return message

    message = error_body or exc.reason
    return f"Relay returned HTTP {exc.code}: {message}"


def relay_request(method, base_url, path, payload=None, extra_headers=None):
    data = None
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    relay_request = request.Request(
        url=f"{base_url}{path}",
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with NO_PROXY_OPENER.open(relay_request, timeout=TIMEOUT_SECONDS) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raise RelayRequestError(
            get_relay_http_error_message(exc),
            status_code=exc.code,
        ) from exc
    except (TimeoutError, socket.timeout):
        raise RelayRequestError(
            f"Timed out reaching relay at {base_url}. "
            "Check RELAY_URL or cli/config.json and confirm the server is reachable."
        )
    except error.URLError as exc:
        raise RelayRequestError(f"Failed to reach relay at {base_url}: {exc.reason}") from exc

    if not response_body:
        return {}

    try:
        return json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RelayRequestError(f"Relay returned invalid JSON: {exc}") from exc


def build_target_payload(target):
    target = target.strip()
    if "://" in target:
        return {"url": target}
    return {"domain": target}


def extract_target_label(response_data, fallback):
    if not isinstance(response_data, dict):
        return fallback

    domain = str(response_data.get("domain", "")).strip()
    if domain:
        return domain

    url = str(response_data.get("url", "")).strip()
    if url:
        return url

    return fallback


def process_single_target(base_url, path, target):
    try:
        response_data = relay_request("POST", base_url, path, build_target_payload(target))
    except RelayRequestError as exc:
        return target, exc, None

    return target, None, response_data


def process_targets(base_url, path, targets, success_prefix):
    had_errors = False
    max_workers = min(len(targets), 8)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                lambda target: process_single_target(base_url, path, target),
                targets,
            )
        )

    for original_target, exc, response_data in results:
        if exc is not None:
            print(f"{original_target}: {exc}", file=sys.stderr)
            had_errors = True
            continue

        print(f"{success_prefix}: {extract_target_label(response_data, original_target)}")

    if had_errors:
        raise SystemExit(1)


def handle_block(args, base_url):
    process_targets(base_url, "/block", args.targets, "Blocked")


def handle_unblock(args, base_url):
    process_targets(base_url, "/unblock", args.targets, "Unblocked")


def handle_list(_args, base_url):
    try:
        response_data = relay_request("GET", base_url, "/list")
    except RelayRequestError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)

    domains = response_data.get("domains")
    if not isinstance(domains, list):
        domains = response_data.get("urls", [])

    if not domains:
        print("No hostnames are currently blocked.")
        return

    for domain in domains:
        print(domain)


def handle_refresh(_args, base_url):
    try:
        response_data = relay_request("POST", base_url, "/refresh")
    except RelayRequestError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)

    domain_count = response_data.get("domain_count")
    if not isinstance(domain_count, int):
        domain_count = response_data.get("url_count")

    if isinstance(domain_count, int):
        print(f"Refreshed hosts file from relay list ({domain_count} hostname(s)).")
        return

    print("Refreshed hosts file from relay list.")


def handle_erase(_args, base_url):
    try:
        response_data = relay_request("POST", base_url, "/erase")
    except RelayRequestError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)

    cleared_count = response_data.get("cleared_domain_count")
    if not isinstance(cleared_count, int):
        cleared_count = response_data.get("cleared_url_count")

    if isinstance(cleared_count, int):
        print(f"Erased hosts file and cleared {cleared_count} saved hostname(s).")
        return

    print("Erased hosts file.")


def handle_pull(_args, base_url):
    extra_headers = {}
    pull_token = load_pull_token()
    if pull_token:
        extra_headers["X-Pull-Token"] = pull_token

    try:
        response_data = relay_request("POST", base_url, "/pull", extra_headers=extra_headers)
    except RelayRequestError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)

    output = str(response_data.get("output", "")).strip()
    if output:
        print(output)
        return

    print(str(response_data.get("message", "git pull completed successfully.")))


def handle_run(args, base_url):
    arguments = list(args.arguments)
    timeout = None

    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    else:
        if len(arguments) >= 2 and arguments[0] == "--timeout":
            try:
                timeout = int(arguments[1])
            except ValueError:
                print("--timeout must be an integer.", file=sys.stderr)
                raise SystemExit(1)
            arguments = arguments[2:]
        elif arguments and arguments[0].startswith("--timeout="):
            try:
                timeout = int(arguments[0].split("=", 1)[1])
            except ValueError:
                print("--timeout must be an integer.", file=sys.stderr)
                raise SystemExit(1)
            arguments = arguments[1:]

    if not arguments:
        print("Provide at least one argument to pass to the selected shell.", file=sys.stderr)
        raise SystemExit(1)

    payload = {
        "shell": args.shell,
        "arguments": arguments,
    }
    if timeout is not None:
        payload["timeout_seconds"] = timeout

    try:
        response_data = relay_request("POST", base_url, "/run", payload)
    except RelayRequestError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)

    command_status = str(response_data.get("command_status", "failed"))
    exit_code = response_data.get("exit_code")
    message = str(response_data.get("message", "Command completed."))
    request_id = str(response_data.get("request_id", "")).strip()

    status_line = f"{args.shell} command {command_status}"
    if isinstance(exit_code, int):
        status_line += f" with exit code {exit_code}"
    if request_id:
        status_line += f" (request {request_id})"

    if command_status == "succeeded":
        print(f"{status_line}. {message}")
        return

    print(f"{status_line}. {message}", file=sys.stderr)
    raise SystemExit(1)


def build_parser():
    parser = argparse.ArgumentParser(description="CLI for managing blocked hostnames via the relay.")
    subparsers = parser.add_subparsers(dest="command")

    block_parser = subparsers.add_parser("block", help="Block one or more hostnames or URLs.")
    block_parser.add_argument("targets", nargs="+", help="Hostname(s) or URL(s) to block.")
    block_parser.set_defaults(handler=handle_block)

    unblock_parser = subparsers.add_parser("unblock", help="Unblock one or more hostnames or URLs.")
    unblock_parser.add_argument("targets", nargs="+", help="Hostname(s) or URL(s) to unblock.")
    unblock_parser.set_defaults(handler=handle_unblock)

    list_parser = subparsers.add_parser("list", help="List blocked hostnames.")
    list_parser.set_defaults(handler=handle_list)

    refresh_parser = subparsers.add_parser(
        "refresh",
        aliases=["sync"],
        help="Reapply the relay block list to the hosts file.",
    )
    refresh_parser.set_defaults(handler=handle_refresh)

    erase_parser = subparsers.add_parser(
        "erase",
        help="Erase the hosts file and clear the relay block list.",
    )
    erase_parser.set_defaults(handler=handle_erase)

    pull_parser = subparsers.add_parser(
        "pull",
        help="Trigger relay-side git pull --ff-only.",
    )
    pull_parser.set_defaults(handler=handle_pull)

    run_parser = subparsers.add_parser(
        "run",
        help="Run a hidden cmd.exe or powershell.exe command through the SYSTEM agent.",
    )
    run_parser.add_argument("shell", choices=["cmd", "powershell"], help="Shell to launch on the agent.")
    run_parser.add_argument(
        "arguments",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to the selected shell.",
    )
    run_parser.set_defaults(handler=handle_run)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return 1

    relay_url = load_relay_url()
    args.handler(args, relay_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
