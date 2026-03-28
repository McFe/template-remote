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


DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
MAX_COMMAND_TIMEOUT_SECONDS = 3600
SELF_UPDATE_FETCH_TIMEOUT_SECONDS = 30
LOG_TIMESTAMP_FORMAT = "%H:%M - %d.%m.%y"
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
SELF_PATH = Path(__file__).resolve()
BLOCK_IP = "127.0.0.1"
INSTANCE_MUTEX_NAME = "Global\\RemoteAgent"
HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
PENDING_LOG_MESSAGES: deque[dict[str, object]] = deque(maxlen=1000)
VALID_LOG_LEVEL_NAMES = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "VERBOSE"}
EXIT_CODE_FATAL = 1
EXIT_CODE_RELAY_CONNECTION_FAILURE = 10
EXIT_CODE_INVALID_RELAY_MESSAGE = 11
EXIT_CODE_INVALID_ACTION_PAYLOAD = 12
EXIT_CODE_HOSTS_NOT_FOUND = 20
EXIT_CODE_HOSTS_UNAVAILABLE = 21
CONSECUTIVE_HOSTS_FAILURES = 0


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
        raise RuntimeError(f"Blocker config not found at {CONFIG_PATH}")

    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid blocker config at {CONFIG_PATH}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Invalid blocker config at {CONFIG_PATH}: expected a JSON object.")

    return data


def _require_config_string(config: dict, key: str, *, allow_empty: bool = False) -> str:
    if key not in config:
        raise RuntimeError(f"Blocker config at {CONFIG_PATH} is missing '{key}'.")

    value = config[key]
    if not isinstance(value, str):
        raise RuntimeError(f"Blocker config key '{key}' must be a string.")

    stripped_value = value.strip()
    if not stripped_value and not allow_empty:
        raise RuntimeError(f"Blocker config key '{key}' must not be empty.")

    return stripped_value


def _require_config_positive_int(config: dict, key: str) -> int:
    if key not in config:
        raise RuntimeError(f"Blocker config at {CONFIG_PATH} is missing '{key}'.")

    value = config[key]
    if not isinstance(value, int) or value <= 0:
        raise RuntimeError(f"Blocker config key '{key}' must be a positive integer.")

    return value


def _require_config_non_negative_int(config: dict, key: str) -> int:
    if key not in config:
        raise RuntimeError(f"Blocker config at {CONFIG_PATH} is missing '{key}'.")

    value = config[key]
    if not isinstance(value, int) or value < 0:
        raise RuntimeError(f"Blocker config key '{key}' must be a non-negative integer.")

    return value


def load_agent_name() -> str:
    config = _load_config()
    configured_name = _require_config_string(config, "agent_name", allow_empty=True)
    if configured_name:
        return configured_name

    return socket.gethostname()


def load_log_level_name() -> str:
    config = _load_config()
    raw_value = _require_config_string(config, "log_level")

    log_level_name = raw_value.upper()
    if log_level_name not in VALID_LOG_LEVEL_NAMES:
        raise RuntimeError(
            f"Blocker config key 'log_level' must be one of {sorted(VALID_LOG_LEVEL_NAMES)!r}."
        )

    return log_level_name


def configure_relay_log_buffering() -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_LEVEL_NAME))
    if any(isinstance(handler, RelayLogBufferHandler) for handler in root_logger.handlers):
        return

    handler = RelayLogBufferHandler()
    handler.setLevel(logging.NOTSET)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(handler)


def _log_verbose(message: str, *args, **kwargs) -> None:
    logging.getLogger().log(logging.VERBOSE, message, *args, **kwargs)


def _serialize_for_log(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    except Exception:
        return repr(value)


def _should_log_wire_payload(payload: dict[str, object]) -> bool:
    return str(payload.get("type", "")).strip() != "agent_log"


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
    config = _load_config()
    return _coerce_ws_url(_require_config_string(config, "relay_ws_url"))


def load_self_update_url() -> str:
    config = _load_config()
    return _require_config_string(config, "agent_update_url", allow_empty=True)


def load_hosts_file() -> str:
    config = _load_config()
    return _require_config_string(config, "hosts_file")


def load_status_report_interval_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "status_report_interval_seconds")


def load_self_update_interval_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "agent_update_interval_seconds")


def load_relay_reconnect_delay_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "relay_reconnect_delay_seconds")


def load_keepalive_interval_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "keepalive_interval_seconds")


def load_keepalive_timeout_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "keepalive_timeout_seconds")


def load_hosts_recovery_retry_count() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "hosts_recovery_retry_count")


def load_hosts_recovery_retry_delay_seconds() -> int:
    config = _load_config()
    return _require_config_positive_int(config, "hosts_recovery_retry_delay_seconds")


def load_hosts_failure_restart_threshold() -> int:
    config = _load_config()
    return _require_config_non_negative_int(config, "hosts_failure_restart_threshold")


AGENT_NAME = load_agent_name()
LOG_LEVEL_NAME = load_log_level_name()
RELAY_WS_URL = load_relay_ws_url()
SELF_UPDATE_URL = load_self_update_url()
HOSTS_FILE = load_hosts_file()
STATUS_REPORT_INTERVAL_SECONDS = load_status_report_interval_seconds()
SELF_UPDATE_INTERVAL_SECONDS = load_self_update_interval_seconds()
RELAY_RECONNECT_DELAY_SECONDS = load_relay_reconnect_delay_seconds()
KEEPALIVE_INTERVAL_SECONDS = load_keepalive_interval_seconds()
KEEPALIVE_TIMEOUT_SECONDS = load_keepalive_timeout_seconds()
HOSTS_RECOVERY_RETRY_COUNT = load_hosts_recovery_retry_count()
HOSTS_RECOVERY_RETRY_DELAY_SECONDS = load_hosts_recovery_retry_delay_seconds()
HOSTS_FAILURE_RESTART_THRESHOLD = load_hosts_failure_restart_threshold()


configure_relay_log_buffering()


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


def _require_hosts_file() -> None:
    if not os.path.exists(HOSTS_FILE):
        raise FileNotFoundError(f"Hosts file not found at {HOSTS_FILE}")


def _reset_hosts_failure_state() -> None:
    global CONSECUTIVE_HOSTS_FAILURES
    CONSECUTIVE_HOSTS_FAILURES = 0


def _record_hosts_failure() -> int:
    global CONSECUTIVE_HOSTS_FAILURES
    CONSECUTIVE_HOSTS_FAILURES += 1
    return CONSECUTIVE_HOSTS_FAILURES


def _recreate_hosts_file() -> None:
    hosts_path = Path(HOSTS_FILE)
    hosts_path.parent.mkdir(parents=True, exist_ok=True)
    hosts_path.touch(exist_ok=True)


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
    should_log_wire_payload = _should_log_wire_payload(payload)
    if should_log_wire_payload:
        _log_verbose("Sending relay payload: %s", _serialize_for_log(payload))

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

    if should_log_wire_payload:
        _log_verbose(
            "Sent relay payload type=%s",
            str(payload.get("type", "unknown")).strip() or "unknown",
        )


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


def _build_self_restart_script(
    *,
    script_path: Path,
    current_pid: int,
    executable_path: str,
    argv: list[str],
) -> str:
    argv_json = json.dumps(argv)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$scriptPath = {_powershell_literal(script_path)}\n"
        f"$pythonPath = {_powershell_literal(executable_path)}\n"
        f"$workingDirectory = {_powershell_literal(str(SELF_PATH.parent))}\n"
        "$argumentList = @()\n"
        "$argvJson = @'\n"
        f"{argv_json}\n"
        "'@\n"
        "$parsedArguments = ConvertFrom-Json -InputObject $argvJson\n"
        "if ($parsedArguments) { $argumentList = [string[]]$parsedArguments }\n"
        "try {\n"
        f"    while (Get-Process -Id {current_pid} -ErrorAction SilentlyContinue) {{ Start-Sleep -Milliseconds 500 }}\n"
        "    Start-Process -FilePath $pythonPath -WorkingDirectory $workingDirectory -ArgumentList $argumentList -WindowStyle Hidden | Out-Null\n"
        "} finally {\n"
        "    if (Test-Path -LiteralPath $scriptPath) { Remove-Item -LiteralPath $scriptPath -Force }\n"
        "}\n"
    )


def _launch_background_powershell_script(script_path: Path) -> None:
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


def _launch_temp_powershell_script(*, prefix: str, build_script) -> None:
    script_path: Path | None = None

    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            suffix=".ps1",
            prefix=prefix,
            delete=False,
        ) as handle:
            script_path = Path(handle.name)
            handle.write(build_script(script_path))

        _launch_background_powershell_script(script_path)
    except Exception:
        if script_path is not None and script_path.exists():
            try:
                script_path.unlink()
            except OSError:
                pass
        raise


def _schedule_self_update(update_url: str) -> None:
    _launch_temp_powershell_script(
        prefix="site_block_agent_update_",
        build_script=lambda script_path: _build_self_update_script(
            target_path=SELF_PATH,
            update_url=update_url,
            script_path=script_path,
            current_pid=os.getpid(),
            executable_path=sys.executable,
            argv=sys.argv[1:],
        ),
    )


def _schedule_self_restart() -> None:
    _launch_temp_powershell_script(
        prefix="site_block_agent_restart_",
        build_script=lambda script_path: _build_self_restart_script(
            script_path=script_path,
            current_pid=os.getpid(),
            executable_path=sys.executable,
            argv=sys.argv[1:],
        ),
    )


async def _check_for_self_update() -> None:
    update_url = SELF_UPDATE_URL
    if not update_url:
        _log_verbose("Skipping self-update check because no update URL is configured.")
        return

    _log_verbose("Checking for self-update at %s", update_url)
    try:
        remote_source = await asyncio.to_thread(_fetch_remote_agent_source, update_url)
        local_source = await asyncio.to_thread(_load_local_agent_source)
    except Exception as exc:
        logging.warning("Self-update check failed for %s: %s", update_url, exc)
        return

    if remote_source == local_source:
        _log_verbose("No self-update available from %s", update_url)
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
    _log_verbose(
        "Starting self-update loop interval_seconds=%s",
        SELF_UPDATE_INTERVAL_SECONDS,
    )
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
    _log_verbose("Printing hosts file from %s", HOSTS_FILE)
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8-sig") as handle:
            sys.stdout.write(handle.read())
    except OSError as exc:
        print(f"Failed to read hosts file at {HOSTS_FILE}: {exc}", file=sys.stderr)
        return 1

    return 0


def _write_hosts_lines(lines: list[str]) -> None:
    _log_verbose("Writing %s hosts line(s) to %s", len(lines), HOSTS_FILE)
    with open(HOSTS_FILE, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
        if lines:
            handle.write("\n")
    _log_verbose("Wrote hosts file to %s", HOSTS_FILE)


def _erase_hosts_file() -> None:
    _log_verbose("Erasing hosts file at %s", HOSTS_FILE)
    _require_hosts_writable()
    with open(HOSTS_FILE, "r+", encoding="utf-8-sig", newline="\n") as handle:
        handle.seek(0)
        handle.truncate(0)
    _flush_dns()
    _log_verbose("Erased hosts file at %s", HOSTS_FILE)


def _blocked_domain_from_line(line: str) -> str | None:
    stripped_line = line.strip()
    if not stripped_line or stripped_line.startswith("#"):
        return None

    tokens = stripped_line.split()
    if len(tokens) < 2:
        return None

    return tokens[1].lower()


def _managed_domains_from_hosts() -> list[str]:
    return sorted(
        {
            domain
            for line in _read_hosts_lines()
            if (domain := _blocked_domain_from_line(line)) is not None
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
        managed_domain = _blocked_domain_from_line(line)
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
    _log_verbose("Flushing DNS cache with ipconfig /flushdns")
    result = subprocess.run(
        ["ipconfig", "/flushdns"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    _log_verbose("Finished DNS flush with return code %s", result.returncode)


def _require_hosts_writable() -> None:
    _log_verbose("Checking write access for hosts file at %s", HOSTS_FILE)
    _require_hosts_file()
    with open(HOSTS_FILE, "r+", encoding="utf-8-sig"):
        pass
    _log_verbose("Confirmed write access for hosts file at %s", HOSTS_FILE)


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
        _log_verbose("Skipping hosts update because there are no add/remove domains.")
        return

    _log_verbose(
        "Updating hosts blocks add=%s remove=%s",
        sorted(normalized_add_domains),
        sorted(normalized_remove_domains),
    )
    _require_hosts_writable()
    lines = _read_hosts_lines()
    current_managed_domains = {
        domain
        for line in lines
        if (domain := _blocked_domain_from_line(line)) is not None
    }
    desired_domains = (current_managed_domains | normalized_add_domains) - normalized_remove_domains
    reconciled_lines, changed = _reconcile_managed_lines(lines, desired_domains)

    if not changed:
        _log_verbose("Hosts update produced no changes. Desired domains: %s", sorted(desired_domains))
        return

    _write_hosts_lines(reconciled_lines)
    _flush_dns()
    _log_verbose("Hosts update applied. Desired domains: %s", sorted(desired_domains))


def _add_block(domain: str) -> None:
    domain = domain.lower()
    if not domain:
        logging.warning("Skipping empty domain for block")
        return

    _log_verbose("Adding block for domain %s", domain)
    _update_blocks(add_domains=[domain])
    _log_verbose("Finished block for domain %s", domain)


def _remove_block(domain: str) -> None:
    domain = domain.lower()
    if not domain:
        logging.warning("Skipping empty domain for unblock")
        return

    _log_verbose("Removing block for domain %s", domain)
    _update_blocks(remove_domains=[domain])
    _log_verbose("Finished unblock for domain %s", domain)


def _apply_domains(domains: list[str]) -> None:
    _log_verbose("Applying full domain set from relay: %s", domains)
    _require_hosts_writable()
    desired_domains = {domain.lower() for domain in domains if domain}
    lines = _read_hosts_lines()
    reconciled_lines, changed = _reconcile_managed_lines(lines, desired_domains)

    if not changed:
        _log_verbose("Full domain apply produced no changes. Desired domains: %s", sorted(desired_domains))
        return

    _write_hosts_lines(reconciled_lines)
    _flush_dns()
    _log_verbose("Applied full domain set. Desired domains: %s", sorted(desired_domains))


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


async def _send_recoverable_error_status(
    ws,
    *,
    error_code: str,
    message: str,
    request_id: str | None = None,
) -> None:
    logging.error("%s", message)

    if request_id is not None:
        await _send_action_result(
            ws,
            request_id=request_id,
            status="error",
            error_code=error_code,
            message=message,
        )


async def _schedule_restart_after_recovery_failure(
    ws,
    *,
    exit_code: int,
    error_code: str,
    message: str,
) -> None:
    restart_message = f"{message} Scheduling agent self-restart after repeated recovery failures."

    try:
        await asyncio.to_thread(_schedule_self_restart)
    except Exception as exc:
        logging.error("Failed to schedule agent self-restart: %s", exc)
        return

    await _send_agent_exit(
        ws,
        exit_code=exit_code,
        error_code=error_code,
        message=restart_message,
    )
    raise AgentRestartRequested("Agent self-restart scheduled after repeated recovery failures.")


async def _handle_invalid_action_payload(
    ws,
    *,
    message: str,
    request_id: str | None = None,
) -> None:
    await _send_recoverable_error_status(
        ws,
        error_code="invalid_action_payload",
        message=message,
        request_id=request_id,
    )

    if request_id is None:
        await _send_agent_status(
            ws,
            status="error",
            error_code="invalid_action_payload",
            message=message,
        )

    await _report_current_status(ws)


async def _run_hosts_operation_with_recovery(operation, *, operation_name: str):
    last_exc: OSError | None = None

    for attempt in range(1, HOSTS_RECOVERY_RETRY_COUNT + 1):
        _log_verbose(
            "Starting hosts operation operation=%s attempt=%s/%s",
            operation_name,
            attempt,
            HOSTS_RECOVERY_RETRY_COUNT,
        )
        try:
            result = operation()
            _reset_hosts_failure_state()
            _log_verbose(
                "Completed hosts operation operation=%s attempt=%s/%s",
                operation_name,
                attempt,
                HOSTS_RECOVERY_RETRY_COUNT,
            )
            return result
        except FileNotFoundError as exc:
            last_exc = exc
            logging.warning(
                "%s failed on attempt %s/%s: %s",
                operation_name,
                attempt,
                HOSTS_RECOVERY_RETRY_COUNT,
                exc,
            )
            try:
                _recreate_hosts_file()
            except OSError as repair_exc:
                last_exc = repair_exc
                logging.warning("Failed to recreate hosts file at %s: %s", HOSTS_FILE, repair_exc)
        except OSError as exc:
            last_exc = exc
            logging.warning(
                "%s failed on attempt %s/%s: %s",
                operation_name,
                attempt,
                HOSTS_RECOVERY_RETRY_COUNT,
                exc,
            )

        if attempt < HOSTS_RECOVERY_RETRY_COUNT:
            _log_verbose(
                "Sleeping %s seconds before retrying hosts operation %s",
                HOSTS_RECOVERY_RETRY_DELAY_SECONDS,
                operation_name,
            )
            await asyncio.sleep(HOSTS_RECOVERY_RETRY_DELAY_SECONDS)

    if last_exc is None:
        raise OSError(f"{operation_name} failed without a captured exception.")

    raise last_exc


async def _handle_hosts_failure(
    ws,
    *,
    request_id: str | None,
    error_code: str,
    exit_code: int,
    message: str,
) -> None:
    await _send_recoverable_error_status(
        ws,
        error_code=error_code,
        message=message,
        request_id=request_id,
    )

    failure_count = _record_hosts_failure()
    threshold = HOSTS_FAILURE_RESTART_THRESHOLD
    status_message = message
    if threshold > 0:
        status_message = f"{message} Consecutive hosts failures: {failure_count}/{threshold}."

    await _send_agent_status(
        ws,
        status="error",
        error_code=error_code,
        message=status_message,
    )

    if threshold > 0 and failure_count >= threshold:
        await _schedule_restart_after_recovery_failure(
            ws,
            exit_code=exit_code,
            error_code=error_code,
            message=message,
        )


async def _handle_invalid_relay_message(ws, *, message: str) -> None:
    await _send_recoverable_error_status(
        ws,
        error_code="invalid_relay_message",
        message=message,
    )
    await _send_agent_status(
        ws,
        status="error",
        error_code="invalid_relay_message",
        message=message,
    )
    await _report_current_status(ws)


async def _perform_keepalive_ping(ws) -> None:
    ping_payload = f"{AGENT_NAME}:{time.monotonic_ns()}"
    _log_verbose("Sending keepalive ping payload=%s", ping_payload)

    try:
        pong_waiter = await ws.ping(ping_payload)
        latency_seconds = await asyncio.wait_for(pong_waiter, timeout=KEEPALIVE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise AgentProcessError(
            exit_code=EXIT_CODE_RELAY_CONNECTION_FAILURE,
            error_code="relay_connection_failed",
            message=f"Keepalive ping timed out after {KEEPALIVE_TIMEOUT_SECONDS} seconds.",
        ) from exc
    except Exception as exc:
        if _is_relay_transport_error(exc):
            raise AgentProcessError(
                exit_code=EXIT_CODE_RELAY_CONNECTION_FAILURE,
                error_code="relay_connection_failed",
                message=f"Keepalive ping failed: {exc}",
            ) from exc
        raise

    _log_verbose(
        "Received keepalive pong payload=%s latency_seconds=%s",
        ping_payload,
        latency_seconds,
    )


async def _periodic_keepalive(ws) -> None:
    _log_verbose(
        "Starting keepalive loop interval_seconds=%s timeout_seconds=%s",
        KEEPALIVE_INTERVAL_SECONDS,
        KEEPALIVE_TIMEOUT_SECONDS,
    )

    while True:
        await asyncio.sleep(KEEPALIVE_INTERVAL_SECONDS)
        await _perform_keepalive_ping(ws)


def _require_run_payload(data: dict) -> tuple[str, list[str], int]:
    raw_shell = str(data.get("shell") or "").strip().lower()
    if raw_shell in {"cmd", "cmd.exe"}:
        shell = "cmd"
    elif raw_shell in {"powershell", "powershell.exe"}:
        shell = "powershell"
    else:
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
    _log_verbose(
        "Preparing background command request_id=%s shell=%s command=%s timeout_seconds=%s",
        request_id or "",
        shell,
        display_command,
        timeout_seconds,
    )

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
        _log_verbose(
            "Started background command request_id=%s pid=%s command=%s",
            request_id or "",
            process.pid,
            display_command,
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
    _log_verbose(
        "Completed background command request_id=%s status=%s exit_code=%s",
        request_id or "",
        command_status,
        exit_code,
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
    _log_verbose("Reporting current agent status to relay.")

    def read_domains() -> list[str]:
        _require_hosts_writable()
        return _managed_domains_from_hosts()

    try:
        domains = await _run_hosts_operation_with_recovery(
            read_domains,
            operation_name="Hosts status check",
        )
    except FileNotFoundError as exc:
        await _handle_hosts_failure(
            ws,
            request_id=None,
            error_code="hosts_not_found",
            exit_code=EXIT_CODE_HOSTS_NOT_FOUND,
            message=str(exc),
        )
        return
    except OSError as exc:
        await _handle_hosts_failure(
            ws,
            request_id=None,
            error_code="hosts_unavailable",
            exit_code=EXIT_CODE_HOSTS_UNAVAILABLE,
            message=f"Failed to update hosts file at {HOSTS_FILE}: {exc}",
        )
        return

    _log_verbose("Current managed domains: %s", domains)
    await _send_agent_status(ws, status="ready", domains=domains)


async def _handle_relay_message(ws, data: dict) -> None:
    action = data.get("action")
    request_id = str(data.get("request_id", "")).strip() or None
    _log_verbose(
        "Handling relay action action=%s request_id=%s payload=%s",
        action,
        request_id or "",
        _serialize_for_log(data),
    )

    try:
        if action in {"init", "refresh"}:
            domains = _require_message_domains(data)
            await _run_hosts_operation_with_recovery(
                lambda: _apply_domains(domains),
                operation_name=f"Apply relay {action}",
            )
        elif action == "erase":
            await _run_hosts_operation_with_recovery(
                _erase_hosts_file,
                operation_name="Erase hosts file",
            )
        elif action in {"block", "unblock"}:
            domain = _require_message_domain(data)
            operation = _add_block if action == "block" else _remove_block
            operation_label = "Block" if action == "block" else "Unblock"
            await _run_hosts_operation_with_recovery(
                lambda: operation(domain),
                operation_name=f"{operation_label} {domain}",
            )
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
        await _handle_invalid_action_payload(
            ws,
            request_id=request_id,
            message=str(exc),
        )
        return
    except FileNotFoundError as exc:
        await _handle_hosts_failure(
            ws,
            request_id=request_id,
            error_code="hosts_not_found",
            exit_code=EXIT_CODE_HOSTS_NOT_FOUND,
            message=str(exc),
        )
        return
    except OSError as exc:
        await _handle_hosts_failure(
            ws,
            request_id=request_id,
            error_code="hosts_unavailable",
            exit_code=EXIT_CODE_HOSTS_UNAVAILABLE,
            message=f"Failed to update hosts file at {HOSTS_FILE}: {exc}",
        )
        return

    await _send_action_result(
        ws,
        request_id=request_id,
        status="ok",
        message="Agent applied the action.",
    )
    _log_verbose("Finished relay action action=%s request_id=%s", action, request_id or "")
    await _report_current_status(ws)


async def _periodic_status_report(ws) -> None:
    _log_verbose(
        "Starting periodic status report loop interval_seconds=%s",
        STATUS_REPORT_INTERVAL_SECONDS,
    )
    while True:
        await asyncio.sleep(STATUS_REPORT_INTERVAL_SECONDS)
        _log_verbose("Periodic status report tick.")
        await _report_current_status(ws)


async def listen() -> None:
    relay_ws_url = RELAY_WS_URL
    _log_verbose(
        "Attempting relay connection url=%s keepalive_interval_seconds=%s keepalive_timeout_seconds=%s",
        relay_ws_url,
        KEEPALIVE_INTERVAL_SECONDS,
        KEEPALIVE_TIMEOUT_SECONDS,
    )

    try:
        async with websockets.connect(
            relay_ws_url,
            ping_interval=None,
            ping_timeout=None,
        ) as ws:
            logging.info("Connected to relay: %s", relay_ws_url)
            try:
                status_task = None
                log_task = None
                keepalive_task = None
                self_update_task = None
                receive_task = None
                await _report_current_status(ws)
                status_task = asyncio.create_task(_periodic_status_report(ws))
                log_task = asyncio.create_task(_forward_log_messages(ws))
                keepalive_task = asyncio.create_task(_periodic_keepalive(ws))
                if SELF_UPDATE_URL:
                    self_update_task = asyncio.create_task(_periodic_self_update_check())
                receive_task = asyncio.create_task(ws.recv())
                try:
                    while True:
                        done, _pending = await asyncio.wait(
                            {
                                task
                                for task in (status_task, log_task, keepalive_task, self_update_task, receive_task)
                                if task is not None
                            },
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        if status_task in done:
                            await status_task

                        if log_task in done:
                            await log_task

                        if keepalive_task in done:
                            await keepalive_task

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

                            if isinstance(raw_message, str):
                                _log_verbose("Received relay text frame: %s", raw_message)
                            else:
                                _log_verbose("Received non-text relay frame: %r", raw_message)

                            if not isinstance(raw_message, str):
                                await _handle_invalid_relay_message(
                                    ws,
                                    message="Relay sent a non-text WebSocket message.",
                                )
                                receive_task = asyncio.create_task(ws.recv())
                                continue

                            try:
                                data = json.loads(raw_message)
                            except json.JSONDecodeError as exc:
                                await _handle_invalid_relay_message(
                                    ws,
                                    message=f"Relay sent malformed JSON: {exc}",
                                )
                                receive_task = asyncio.create_task(ws.recv())
                                continue

                            _log_verbose("Parsed relay message: %s", _serialize_for_log(data))
                            if not isinstance(data, dict):
                                await _handle_invalid_relay_message(
                                    ws,
                                    message="Relay sent a non-object JSON message.",
                                )
                                receive_task = asyncio.create_task(ws.recv())
                                continue

                            await _handle_relay_message(ws, data)
                            receive_task = asyncio.create_task(ws.recv())
                finally:
                    tasks = [
                        task
                        for task in (status_task, log_task, keepalive_task, self_update_task, receive_task)
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
                logging.exception("Agent encountered a fatal runtime error: %s", exc)
                raise AgentProcessError(
                    exit_code=EXIT_CODE_FATAL,
                    error_code="agent_runtime_failure",
                    message=f"Agent encountered a fatal runtime error: {exc}",
                ) from exc
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
    _log_verbose("Starting agent main loop.")
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
    if getattr(args, "relay_url", None):
        globals()["RELAY_WS_URL"] = _coerce_ws_url(str(args.relay_url).strip())

    if getattr(args, "self_update_url", None) is not None:
        globals()["SELF_UPDATE_URL"] = str(args.self_update_url).strip()

    if getattr(args, "hosts_file", None):
        globals()["HOSTS_FILE"] = str(args.hosts_file).strip()

    for arg_name, option_name, global_name in (
        ("status_report_interval", "--status-report-interval", "STATUS_REPORT_INTERVAL_SECONDS"),
        ("self_update_interval", "--self-update-interval", "SELF_UPDATE_INTERVAL_SECONDS"),
        ("relay_reconnect_delay", "--relay-reconnect-delay", "RELAY_RECONNECT_DELAY_SECONDS"),
        ("keepalive_interval", "--keepalive-interval", "KEEPALIVE_INTERVAL_SECONDS"),
        ("keepalive_timeout", "--keepalive-timeout", "KEEPALIVE_TIMEOUT_SECONDS"),
        ("hosts_recovery_retry_count", "--hosts-recovery-retry-count", "HOSTS_RECOVERY_RETRY_COUNT"),
        ("hosts_recovery_retry_delay", "--hosts-recovery-retry-delay", "HOSTS_RECOVERY_RETRY_DELAY_SECONDS"),
    ):
        value = getattr(args, arg_name, None)
        if value is None:
            continue
        if value <= 0:
            raise SystemExit(f"{option_name} must be greater than 0.")
        globals()[global_name] = value

    threshold = getattr(args, "hosts_failure_restart_threshold", None)
    if threshold is not None:
        if threshold < 0:
            raise SystemExit("--hosts-failure-restart-threshold must be 0 or greater.")
        globals()["HOSTS_FAILURE_RESTART_THRESHOLD"] = threshold

    if getattr(args, "log_level", None):
        logging.getLogger().setLevel(getattr(logging, str(args.log_level).upper()))

    if getattr(args, "agent_name", None):
        globals()["AGENT_NAME"] = str(args.agent_name).strip()


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
        "--keepalive-interval",
        type=int,
        metavar="SECONDS",
        help="Override the keepalive ping interval for this run.",
    )
    parser.add_argument(
        "--keepalive-timeout",
        type=int,
        metavar="SECONDS",
        help="Override the keepalive ping timeout for this run.",
    )
    parser.add_argument(
        "--hosts-recovery-retry-count",
        type=int,
        metavar="COUNT",
        help="Override the number of hosts recovery attempts before giving up for this run.",
    )
    parser.add_argument(
        "--hosts-recovery-retry-delay",
        type=int,
        metavar="SECONDS",
        help="Override the delay between hosts recovery attempts for this run.",
    )
    parser.add_argument(
        "--hosts-failure-restart-threshold",
        type=int,
        metavar="COUNT",
        help="Override the consecutive hosts failure threshold before self-restart for this run. Use 0 to disable self-restart.",
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
    _log_verbose(
        "Starting agent with configuration agent_name=%s relay_ws_url=%s hosts_file=%s "
        "status_report_interval_seconds=%s self_update_interval_seconds=%s "
        "relay_reconnect_delay_seconds=%s keepalive_interval_seconds=%s keepalive_timeout_seconds=%s "
        "hosts_recovery_retry_count=%s hosts_recovery_retry_delay_seconds=%s "
        "hosts_failure_restart_threshold=%s self_update_url_configured=%s",
        AGENT_NAME,
        RELAY_WS_URL,
        HOSTS_FILE,
        STATUS_REPORT_INTERVAL_SECONDS,
        SELF_UPDATE_INTERVAL_SECONDS,
        RELAY_RECONNECT_DELAY_SECONDS,
        KEEPALIVE_INTERVAL_SECONDS,
        KEEPALIVE_TIMEOUT_SECONDS,
        HOSTS_RECOVERY_RETRY_COUNT,
        HOSTS_RECOVERY_RETRY_DELAY_SECONDS,
        HOSTS_FAILURE_RESTART_THRESHOLD,
        bool(SELF_UPDATE_URL),
    )

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
