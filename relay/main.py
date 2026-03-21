from __future__ import annotations

import asyncio
import ctypes
from datetime import datetime
import json
import logging
import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

import h11
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel


DATA_FILE = Path(__file__).parent / "blocked_urls.json"
AGENT_LOG_FILE = Path(__file__).parent / "agent_logs.log"
COMMAND_LOG_FILE = Path(__file__).parent / "command_output.log"
REPO_ROOT = Path(__file__).resolve().parents[1]
URLS_LOCK = asyncio.Lock()
PULL_LOCK = asyncio.Lock()
relay_logger = logging.getLogger("site_blocker.relay")
ACTION_ACK_TIMEOUT_SECONDS = 5
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
COMMAND_WAIT_GRACE_SECONDS = 5
HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LOG_TIMESTAMP_FORMAT = "%H:%M - %d.%m.%y"
LEGACY_AGENT_LOG_PREFIX_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} [A-Z]+ \S+ (?P<message>.+)$"
)


class StorageError(RuntimeError):
    pass


class PullError(RuntimeError):
    pass


def patch_uvicorn_h11_bad_request_handling() -> None:
    try:
        from uvicorn.protocols.http.h11_impl import H11Protocol
    except Exception:
        return

    if getattr(H11Protocol, "_site_block_bad_request_patch", False):
        return

    original_send_400_response = H11Protocol.send_400_response

    def send_400_response(self, msg):
        try:
            return original_send_400_response(self, msg)
        except h11.LocalProtocolError:
            if self.transport is not None:
                self.transport.close()
            return None

    H11Protocol.send_400_response = send_400_response
    H11Protocol._site_block_bad_request_patch = True


def set_process_title() -> None:
    if sys.platform != "win32":
        return

    ctypes.windll.kernel32.SetConsoleTitleW("relay")


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False

    labels = hostname.split(".")
    return all(HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)


def normalize_hostname(raw_value: object) -> str:
    if not isinstance(raw_value, str):
        return ""

    value = raw_value.strip()
    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"http://{value}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not is_valid_hostname(hostname):
        return ""

    return hostname


def require_hostname(raw_value: object, *, field_name: str) -> str:
    hostname = normalize_hostname(raw_value)
    if hostname:
        return hostname

    raise_api_error(
        400,
        "invalid_domain",
        f"{field_name} must be a hostname or a URL containing a valid hostname.",
    )
    return ""


def canonicalize_domains(domains: list[str]) -> list[str]:
    canonical_domains: list[str] = []
    seen: set[str] = set()

    for raw_domain in domains:
        domain = normalize_hostname(raw_domain)
        if not domain:
            raise StorageError(f"Blocked domains include an invalid hostname entry: {raw_domain!r}")
        if domain in seen:
            continue
        seen.add(domain)
        canonical_domains.append(domain)

    return canonical_domains


def load_blocked_domains() -> list[str]:
    if not DATA_FILE.exists():
        return []

    try:
        raw_text = DATA_FILE.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise StorageError(f"Failed to read blocked domains file at {DATA_FILE}: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise StorageError(f"Blocked domains file at {DATA_FILE} contains invalid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise StorageError(f"Blocked domains file at {DATA_FILE} must contain a JSON array.")

    domains: list[str] = []
    seen: set[str] = set()

    for item in data:
        if not isinstance(item, str):
            raise StorageError("Blocked domains file entries must all be strings.")

        stripped_item = item.strip().lower()
        domain = normalize_hostname(item)
        if not domain or domain != stripped_item:
            raise StorageError(
                "Blocked domains file contains a non-canonical entry. Reset or rewrite it to lowercase hostnames."
            )

        if domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    return domains


def save_blocked_domains(domains: list[str]) -> None:
    canonical_domains = canonicalize_domains(domains)
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None

    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=DATA_FILE.parent,
            prefix=f"{DATA_FILE.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(canonical_domains, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, DATA_FILE)
    except OSError as exc:
        raise StorageError(f"Failed to write blocked domains file at {DATA_FILE}: {exc}") from exc
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def format_log_timestamp(created: object = None) -> str:
    if isinstance(created, (int, float)):
        try:
            return datetime.fromtimestamp(float(created)).strftime(LOG_TIMESTAMP_FORMAT)
        except (OverflowError, OSError, ValueError):
            pass

    return datetime.now().strftime(LOG_TIMESTAMP_FORMAT)


def collapse_log_message(message: object) -> str:
    parts = [line.strip() for line in str(message).splitlines() if line.strip()]
    return " | ".join(parts)


def sanitize_agent_log_message(message: object) -> str:
    sanitized_message = collapse_log_message(message)
    legacy_match = LEGACY_AGENT_LOG_PREFIX_RE.fullmatch(sanitized_message)
    if legacy_match:
        return legacy_match.group("message").strip()

    return sanitized_message


def build_agent_log_line(
    *,
    agent_name: str,
    level_name: str,
    message: str,
    created: object = None,
) -> str:
    return f"[{format_log_timestamp(created)}] [{agent_name}] {level_name} {sanitize_agent_log_message(message)}"


def append_agent_log(entry: str) -> None:
    AGENT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AGENT_LOG_FILE.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry.rstrip("\r\n") + "\n")


def append_command_log(entry: str) -> None:
    COMMAND_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with COMMAND_LOG_FILE.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry.rstrip("\r\n") + "\n")


def read_recent_agent_logs(limit: int = 500) -> list[str]:
    if not AGENT_LOG_FILE.exists():
        return []

    recent_lines: list[str] = []
    with AGENT_LOG_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped_line = line.rstrip("\r\n")
            if not stripped_line:
                continue
            recent_lines.append(stripped_line)
            if len(recent_lines) > limit:
                recent_lines.pop(0)

    return recent_lines


def read_recent_command_logs(limit: int = 500) -> list[str]:
    if not COMMAND_LOG_FILE.exists():
        return []

    recent_lines: list[str] = []
    with COMMAND_LOG_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped_line = line.rstrip("\r\n")
            if not stripped_line:
                continue
            recent_lines.append(stripped_line)
            if len(recent_lines) > limit:
                recent_lines.pop(0)

    return recent_lines


def build_command_log_line(
    *,
    agent_name: str,
    request_id: str,
    shell: str,
    stream: str,
    message: str,
    created: object = None,
) -> str:
    return (
        f"[{format_log_timestamp(created)}] "
        f"[{agent_name}] [{request_id}] [{shell}] {stream.upper()} {collapse_log_message(message)}"
    )


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[WebSocket, AgentState] = {}
        self.pending_actions: dict[str, PendingAction] = {}

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active_connections[ws] = AgentState()

    def disconnect(self, ws: WebSocket) -> None:
        self.active_connections.pop(ws, None)
        for request_id, pending_action in tuple(self.pending_actions.items()):
            if ws not in pending_action.expected_connections or pending_action.future.done():
                continue

            pending_action.results[ws] = {
                "status": "error",
                "code": "agent_disconnected",
                "message": "The connected agent disconnected before confirming the action.",
            }
            pending_action.future.set_result(pending_action.results[ws])
            self.pending_actions.pop(request_id, None)

    def mark_agent_status(
        self,
        ws: WebSocket,
        *,
        status: str,
        error_code: str | None = None,
        message: str | None = None,
        domains: list[str] | None = None,
        agent_name: str | None = None,
    ) -> None:
        if ws not in self.active_connections:
            return

        self.active_connections[ws] = AgentState(
            status=status,
            error_code=error_code,
            message=message,
            domains=tuple(domains or ()),
            agent_name=agent_name or self.active_connections[ws].agent_name,
        )

    async def broadcast_to(self, connections: tuple[WebSocket, ...], message: dict[str, object]) -> None:
        payload = json.dumps(message)
        stale_connections: list[WebSocket] = []

        for connection in connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(connection)

    def create_pending_action(
        self,
        request_id: str,
        connections: tuple[WebSocket, ...],
    ) -> asyncio.Future[dict[str, object]] | None:
        if not connections:
            return None

        future: asyncio.Future[dict[str, object]] = asyncio.get_running_loop().create_future()
        self.pending_actions[request_id] = PendingAction(
            expected_connections=set(connections),
            future=future,
        )
        return future

    def resolve_pending_action(
        self,
        ws: WebSocket,
        *,
        request_id: str,
        status: str,
        error_code: str | None = None,
        message: str | None = None,
        extra_fields: dict[str, object] | None = None,
    ) -> None:
        pending_action = self.pending_actions.get(request_id)
        if pending_action is None or ws not in pending_action.expected_connections:
            return

        result: dict[str, object] = {
            "status": status,
            "code": error_code or ("ok" if status == "ok" else "agent_error"),
            "message": message or ("Agent applied the action." if status == "ok" else "Agent failed the action."),
        }
        if extra_fields:
            result.update(extra_fields)
        pending_action.results[ws] = result

        if status != "ok":
            if not pending_action.future.done():
                pending_action.future.set_result(result)
            self.pending_actions.pop(request_id, None)
            return

        if pending_action.expected_connections.issubset(pending_action.results):
            if not pending_action.future.done():
                pending_action.future.set_result(result)
            self.pending_actions.pop(request_id, None)


@dataclass
class AgentState:
    status: str = "unknown"
    error_code: str | None = None
    message: str | None = None
    domains: tuple[str, ...] = ()
    agent_name: str | None = None


@dataclass
class PendingAction:
    expected_connections: set[WebSocket]
    future: asyncio.Future[dict[str, object]]
    results: dict[WebSocket, dict[str, object]] = field(default_factory=dict)


manager = ConnectionManager()
patch_uvicorn_h11_bad_request_handling()
app = FastAPI()
set_process_title()


class TargetPayload(BaseModel):
    url: str | None = None
    domain: str | None = None


class CommandPayload(BaseModel):
    shell: str
    arguments: list[str] | None = None
    timeout_seconds: int | None = None


def raise_api_error(status_code: int, code: str, message: str) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def load_blocked_domains_or_raise_api() -> list[str]:
    try:
        return load_blocked_domains()
    except StorageError as exc:
        relay_logger.error("%s", exc)
        raise_api_error(500, "storage_unavailable", str(exc))
        return []


def load_pull_token() -> str:
    return os.environ.get("PULL_TOKEN", "").strip()


def require_pull_authorization(provided_token: str | None) -> None:
    expected_token = load_pull_token()
    if not expected_token:
        return

    if str(provided_token or "").strip() != expected_token:
        raise_api_error(403, "invalid_pull_token", "Missing or invalid pull token.")


def get_required_target_connection() -> WebSocket:
    active_connections = tuple(manager.active_connections.items())
    if not active_connections:
        raise_api_error(503, "agent_not_connected", "No blocker agent is connected to the relay.")

    if len(active_connections) > 1:
        raise_api_error(
            503,
            "multiple_agents_connected",
            "Exactly one blocker agent must be connected to the relay.",
        )

    connection, state = active_connections[0]
    if state.status == "error":
        raise_api_error(
            503,
            state.error_code or "agent_unavailable",
            state.message or "The connected agent is unavailable.",
        )

    return connection


def normalize_reported_domains(domains: object) -> list[str]:
    if not isinstance(domains, list):
        return []

    normalized_domains: list[str] = []
    seen: set[str] = set()
    for item in domains:
        domain = normalize_hostname(item)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        normalized_domains.append(domain)

    return normalized_domains


def get_requested_domain(payload: TargetPayload) -> str:
    normalized_domains: list[str] = []

    if payload.domain is not None and str(payload.domain).strip():
        normalized_domains.append(require_hostname(payload.domain, field_name="domain"))

    if payload.url is not None and str(payload.url).strip():
        normalized_domains.append(require_hostname(payload.url, field_name="url"))

    if not normalized_domains:
        raise_api_error(400, "invalid_domain", "Provide either 'domain' or 'url'.")

    first_domain = normalized_domains[0]
    if any(domain != first_domain for domain in normalized_domains[1:]):
        raise_api_error(
            400,
            "conflicting_target",
            "The provided 'domain' and 'url' values refer to different hostnames.",
        )

    return first_domain


def build_sync_message(action: str, domains: list[str], request_id: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "domains": domains,
        "urls": domains,
    }
    if request_id is not None:
        payload["request_id"] = request_id
    return payload


def build_single_domain_message(
    action: str,
    domain: str,
    request_id: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "domain": domain,
        "url": domain,
    }
    if request_id is not None:
        payload["request_id"] = request_id
    return payload


def build_run_message(
    *,
    shell: str,
    arguments: list[str],
    timeout_seconds: int,
    request_id: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": "run",
        "shell": shell,
        "arguments": arguments,
        "timeout_seconds": timeout_seconds,
    }
    if request_id is not None:
        payload["request_id"] = request_id
    return payload


async def wait_for_agent_action(
    request_id: str,
    connection: WebSocket,
    message: dict[str, object],
    *,
    timeout_seconds: int = ACTION_ACK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    pending_action = manager.create_pending_action(request_id, (connection,))
    await manager.broadcast_to((connection,), message)
    if pending_action is None:
        raise_api_error(503, "agent_not_connected", "No blocker agent is connected to the relay.")

    try:
        return await asyncio.wait_for(pending_action, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        manager.pending_actions.pop(request_id, None)
        raise_api_error(
            504,
            "agent_timeout",
            "Timed out waiting for the blocker agent to confirm the action.",
        )
        return {"status": "error", "code": "agent_timeout", "message": "Timed out waiting for the blocker agent."}


def build_list_response(domains: list[str]) -> dict[str, list[str]]:
    return {"domains": domains, "urls": domains}


def build_single_target_response(domain: str) -> dict[str, object]:
    return {
        "status": "ok",
        "domain": domain,
        "url": domain,
        "delivery": {"status": "applied"},
    }


def build_ack_error(result: dict[str, object]) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "code": str(result.get("code", "agent_error")),
            "message": str(result.get("message", "The blocker agent failed to apply the action.")),
        },
    )


def normalize_command_shell(raw_value: object) -> str:
    shell = str(raw_value or "").strip().lower()
    if shell in {"cmd", "cmd.exe"}:
        return "cmd"
    if shell in {"powershell", "powershell.exe"}:
        return "powershell"
    return ""


def normalize_command_arguments(raw_value: object) -> list[str]:
    if raw_value is None:
        return []
    if not isinstance(raw_value, list):
        raise_api_error(400, "invalid_arguments", "Command arguments must be a JSON array of strings.")

    arguments: list[str] = []
    for item in raw_value:
        if not isinstance(item, str):
            raise_api_error(400, "invalid_arguments", "Command arguments must be a JSON array of strings.")
        arguments.append(item)

    return arguments


def get_requested_command(payload: CommandPayload) -> tuple[str, list[str], int]:
    shell = normalize_command_shell(payload.shell)
    if not shell:
        raise_api_error(400, "invalid_shell", "Shell must be 'cmd' or 'powershell'.")

    arguments = normalize_command_arguments(payload.arguments)
    if not arguments:
        raise_api_error(400, "missing_arguments", "Provide at least one argument for the selected shell.")

    timeout_seconds = payload.timeout_seconds
    if timeout_seconds is None:
        timeout_seconds = DEFAULT_COMMAND_TIMEOUT_SECONDS
    elif timeout_seconds <= 0:
        raise_api_error(400, "invalid_timeout", "timeout_seconds must be greater than 0.")

    return shell, arguments, timeout_seconds


def run_git_pull(repo_root: Path) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise PullError(f"Failed to execute git pull in {repo_root}: {exc}") from exc

    combined_output = "\n".join(
        part.strip()
        for part in (result.stdout, result.stderr)
        if isinstance(part, str) and part.strip()
    ).strip()
    if not combined_output:
        combined_output = "git pull completed with no output."

    if result.returncode != 0:
        raise PullError(combined_output)

    return {"output": combined_output}


async def rollback_agent_domains(connection: WebSocket, domains: list[str]) -> str | None:
    request_id = str(uuid.uuid4())

    try:
        result = await wait_for_agent_action(
            request_id,
            connection,
            build_sync_message("refresh", domains, request_id),
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        return str(detail.get("message", "Agent rollback failed."))

    if result.get("status") != "ok":
        return str(result.get("message", "Agent rollback failed."))

    return None


async def persist_domains_with_rollback(
    *,
    connection: WebSocket,
    previous_domains: list[str],
    next_domains: list[str],
) -> None:
    try:
        save_blocked_domains(next_domains)
    except StorageError as exc:
        relay_logger.error("Failed to persist blocked domains: %s", exc)
        rollback_error = await rollback_agent_domains(connection, previous_domains)
        message = str(exc)
        if rollback_error:
            relay_logger.error("Failed to restore agent state after storage failure: %s", rollback_error)
            message = f"{message} Agent rollback also failed: {rollback_error}"
        raise_api_error(500, "storage_unavailable", message)


def get_agent_name(websocket: WebSocket, payload_agent_name: str | None = None) -> str:
    agent_name = str(payload_agent_name or "").strip()
    if agent_name:
        return agent_name

    state = manager.active_connections.get(websocket)
    if state and state.agent_name:
        return state.agent_name

    client = getattr(websocket, "client", None)
    if client is not None and getattr(client, "host", None):
        return str(client.host)

    return "unknown-agent"


def record_agent_log(websocket: WebSocket, message: dict[str, object]) -> None:
    agent_name = get_agent_name(websocket, str(message.get("agent_name") or ""))
    level_name = str(message.get("level", "INFO")).upper()
    log_message = sanitize_agent_log_message(message.get("message", ""))
    created = message.get("created")

    if not log_message:
        return

    append_agent_log(
        build_agent_log_line(
            agent_name=agent_name,
            level_name=level_name,
            message=log_message,
            created=created,
        )
    )

    level = getattr(logging, level_name, logging.INFO)
    relay_logger.log(level, "[%s] %s", agent_name, log_message)


def record_agent_exit(websocket: WebSocket, message: dict[str, object]) -> None:
    agent_name = get_agent_name(websocket, str(message.get("agent_name") or ""))
    error_code = str(message.get("error_code", "agent_exit")).strip() or "agent_exit"
    raw_exit_code = message.get("exit_code")
    exit_code = raw_exit_code if isinstance(raw_exit_code, int) else None
    exit_message = str(message.get("message", "")).strip() or "The blocker agent exited due to a fatal error."
    created = message.get("created")
    full_message = exit_message if exit_code is None else f"{exit_message} (exit code {exit_code})"

    manager.mark_agent_status(
        websocket,
        status="error",
        error_code=error_code,
        message=full_message,
        domains=[],
        agent_name=agent_name,
    )
    append_agent_log(
        build_agent_log_line(
            agent_name=agent_name,
            level_name="ERROR",
            message=full_message,
            created=created,
        )
    )
    relay_logger.error("[%s] %s", agent_name, full_message)


def record_agent_command_output(websocket: WebSocket, message: dict[str, object]) -> None:
    agent_name = get_agent_name(websocket, str(message.get("agent_name") or ""))
    request_id = str(message.get("request_id") or "").strip() or "unknown-request"
    shell = normalize_command_shell(message.get("shell")) or "unknown-shell"
    stream = str(message.get("stream") or "output").strip() or "output"
    output_message = collapse_log_message(message.get("message", ""))
    created = message.get("created")

    if not output_message:
        return

    append_command_log(
        build_command_log_line(
            agent_name=agent_name,
            request_id=request_id,
            shell=shell,
            stream=stream,
            message=output_message,
            created=created,
        )
    )


async def reconcile_agent_domains(websocket: WebSocket, domains: list[str]) -> None:
    expected_domains = load_blocked_domains()
    reported_domains = set(domains)

    if reported_domains == set(expected_domains):
        return

    await websocket.send_text(json.dumps(build_sync_message("init", expected_domains)))


@app.get("/list")
async def list_domains() -> dict[str, list[str]]:
    return build_list_response(load_blocked_domains_or_raise_api())


@app.get("/agent-logs")
async def list_agent_logs() -> dict[str, list[str]]:
    return {"logs": read_recent_agent_logs()}


@app.post("/pull")
async def pull_repository(x_pull_token: str | None = Header(default=None, alias="X-Pull-Token")) -> dict[str, str]:
    require_pull_authorization(x_pull_token)

    async with PULL_LOCK:
        try:
            result = await asyncio.to_thread(run_git_pull, REPO_ROOT)
        except PullError as exc:
            relay_logger.error("git pull failed: %s", exc)
            raise_api_error(500, "pull_failed", str(exc))
            return {"status": "error", "message": str(exc), "output": ""}

    output = result["output"]
    relay_logger.info("git pull completed: %s", output.replace("\n", " | "))
    return {
        "status": "ok",
        "message": "git pull completed successfully.",
        "output": output,
    }


@app.get("/command-logs")
async def list_command_logs() -> dict[str, list[str]]:
    return {"logs": read_recent_command_logs()}


@app.post("/block")
async def block_domain(payload: TargetPayload) -> dict[str, object]:
    domain = get_requested_domain(payload)

    async with URLS_LOCK:
        current_domains = load_blocked_domains_or_raise_api()
        if domain in current_domains:
            raise_api_error(409, "site_already_blocked", f"Site is already blocked: {domain}")

        connection = get_required_target_connection()
        request_id = str(uuid.uuid4())
        result = await wait_for_agent_action(
            request_id,
            connection,
            build_single_domain_message("block", domain, request_id),
        )
        if result["status"] != "ok":
            raise build_ack_error(result)

        await persist_domains_with_rollback(
            connection=connection,
            previous_domains=current_domains,
            next_domains=[*current_domains, domain],
        )

    return build_single_target_response(domain)


@app.post("/unblock")
async def unblock_domain(payload: TargetPayload) -> dict[str, object]:
    domain = get_requested_domain(payload)

    async with URLS_LOCK:
        current_domains = load_blocked_domains_or_raise_api()
        if domain not in current_domains:
            raise_api_error(409, "site_not_blocked", f"Site is not currently blocked: {domain}")

        connection = get_required_target_connection()
        request_id = str(uuid.uuid4())
        result = await wait_for_agent_action(
            request_id,
            connection,
            build_single_domain_message("unblock", domain, request_id),
        )
        if result["status"] != "ok":
            raise build_ack_error(result)

        next_domains = [blocked_domain for blocked_domain in current_domains if blocked_domain != domain]
        await persist_domains_with_rollback(
            connection=connection,
            previous_domains=current_domains,
            next_domains=next_domains,
        )

    return build_single_target_response(domain)


@app.post("/refresh")
async def refresh_hosts() -> dict[str, object]:
    async with URLS_LOCK:
        current_domains = load_blocked_domains_or_raise_api()
        connection = get_required_target_connection()
        request_id = str(uuid.uuid4())
        result = await wait_for_agent_action(
            request_id,
            connection,
            build_sync_message("refresh", current_domains, request_id),
        )
        if result.get("status") != "ok":
            raise build_ack_error(result)

    return {
        "status": "ok",
        "message": "Relay state was reapplied to the hosts file.",
        "domain_count": len(current_domains),
        "url_count": len(current_domains),
    }


@app.post("/erase")
async def erase_hosts() -> dict[str, object]:
    async with URLS_LOCK:
        current_domains = load_blocked_domains_or_raise_api()
        connection = get_required_target_connection()
        request_id = str(uuid.uuid4())
        result = await wait_for_agent_action(
            request_id,
            connection,
            {"action": "erase", "request_id": request_id},
        )
        if result.get("status") != "ok":
            raise build_ack_error(result)

        await persist_domains_with_rollback(
            connection=connection,
            previous_domains=current_domains,
            next_domains=[],
        )

    return {
        "status": "ok",
        "message": "Hosts file was erased and the relay block list was cleared.",
        "cleared_domain_count": len(current_domains),
        "cleared_url_count": len(current_domains),
    }


@app.post("/run")
async def run_command(payload: CommandPayload) -> dict[str, object]:
    shell, arguments, timeout_seconds = get_requested_command(payload)

    connection = get_required_target_connection()
    request_id = str(uuid.uuid4())
    result = await wait_for_agent_action(
        request_id,
        connection,
        build_run_message(
            shell=shell,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            request_id=request_id,
        ),
        timeout_seconds=timeout_seconds + COMMAND_WAIT_GRACE_SECONDS,
    )
    if result.get("status") != "ok":
        raise build_ack_error(result)  # type: ignore[arg-type]

    command_status = str(result.get("command_status", "failed"))
    exit_code = result.get("exit_code")
    if not isinstance(exit_code, int):
        exit_code = None

    return {
        "status": "ok",
        "command_status": command_status,
        "shell": shell,
        "arguments": arguments,
        "timeout_seconds": timeout_seconds,
        "exit_code": exit_code,
        "message": str(result.get("message", "Command completed.")),
        "request_id": request_id,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)

    try:
        await websocket.send_text(json.dumps(build_sync_message("init", load_blocked_domains())))

        while True:
            raw_message = await websocket.receive_text()

            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                continue

            message_type = message.get("type")

            if message_type == "agent_log":
                if isinstance(message, dict):
                    record_agent_log(websocket, message)
                continue

            if message_type == "agent_command_output":
                if isinstance(message, dict):
                    record_agent_command_output(websocket, message)
                continue

            if message_type == "agent_action_result":
                if isinstance(message, dict):
                    extra_fields: dict[str, object] = {}
                    if isinstance(message.get("exit_code"), int):
                        extra_fields["exit_code"] = message["exit_code"]
                    if isinstance(message.get("command_status"), str):
                        extra_fields["command_status"] = message["command_status"]
                    manager.resolve_pending_action(
                        websocket,
                        request_id=str(message.get("request_id", "")),
                        status=str(message.get("status", "error")),
                        error_code=message.get("error_code") if isinstance(message.get("error_code"), str) else None,
                        message=message.get("message") if isinstance(message.get("message"), str) else None,
                        extra_fields=extra_fields,
                    )
                continue

            if message_type == "agent_exit":
                if isinstance(message, dict):
                    record_agent_exit(websocket, message)
                continue

            if message_type != "agent_status" or not isinstance(message, dict):
                continue

            reported_domains = normalize_reported_domains(message.get("domains"))
            manager.mark_agent_status(
                websocket,
                status=str(message.get("status", "unknown")),
                error_code=message.get("error_code") if isinstance(message.get("error_code"), str) else None,
                message=message.get("message") if isinstance(message.get("message"), str) else None,
                domains=reported_domains,
                agent_name=message.get("agent_name") if isinstance(message.get("agent_name"), str) else None,
            )

            if str(message.get("status", "unknown")) != "error":
                await reconcile_agent_domains(websocket, reported_domains)
    except WebSocketDisconnect:
        pass
    except StorageError as exc:
        relay_logger.error("Disconnecting blocker agent because relay storage is unavailable: %s", exc)
        try:
            await websocket.close(code=1011, reason="Relay storage unavailable.")
        except Exception:
            pass
    finally:
        manager.disconnect(websocket)
