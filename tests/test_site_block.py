import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from json import loads
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
RELAY_PATH = ROOT / "relay" / "main.py"
AGENT_PATH = ROOT / "blocker" / "agent.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


relay_main = load_module("site_block_relay_main", RELAY_PATH)
blocker_agent = load_module("site_block_blocker_agent", AGENT_PATH)


class RelayContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_file = relay_main.DATA_FILE
        self.original_agent_log_file = relay_main.AGENT_LOG_FILE
        self.original_command_log_file = relay_main.COMMAND_LOG_FILE
        self.original_active_connections = relay_main.manager.active_connections.copy()
        self.original_pending_actions = relay_main.manager.pending_actions.copy()
        self.original_wait_for_agent_action = relay_main.wait_for_agent_action
        self.client = TestClient(relay_main.app)

        relay_main.DATA_FILE = Path(self.temp_dir.name) / "blocked_urls.json"
        relay_main.AGENT_LOG_FILE = Path(self.temp_dir.name) / "agent_logs.log"
        relay_main.COMMAND_LOG_FILE = Path(self.temp_dir.name) / "command_output.log"
        relay_main.manager.active_connections.clear()
        relay_main.manager.pending_actions.clear()
        relay_main.wait_for_agent_action = AsyncMock(
            return_value={"status": "ok", "code": "ok", "message": "ok"}
        )

    def tearDown(self) -> None:
        relay_main.DATA_FILE = self.original_data_file
        relay_main.AGENT_LOG_FILE = self.original_agent_log_file
        relay_main.COMMAND_LOG_FILE = self.original_command_log_file
        relay_main.manager.active_connections.clear()
        relay_main.manager.active_connections.update(self.original_active_connections)
        relay_main.manager.pending_actions.clear()
        relay_main.manager.pending_actions.update(self.original_pending_actions)
        relay_main.wait_for_agent_action = self.original_wait_for_agent_action
        self.temp_dir.cleanup()

    def test_block_normalizes_to_canonical_hostname(self) -> None:
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")

        response = self.client.post("/block", json={"url": "https://Reddit.com/r/python"})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(relay_main.load_blocked_domains(), ["reddit.com"])
        self.assertEqual(
            response.json(),
            {
                "status": "ok",
                "domain": "reddit.com",
                "url": "reddit.com",
                "delivery": {"status": "applied"},
            },
        )

    def test_invalid_target_does_not_mutate_storage(self) -> None:
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")

        response = self.client.post("/block", json={"url": "https:///broken"})

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(relay_main.load_blocked_domains(), [])

    def test_multiple_agents_are_rejected(self) -> None:
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")

        response = self.client.post("/block", json={"domain": "reddit.com"})

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(relay_main.load_blocked_domains(), [])

    def test_invalid_storage_is_a_server_error(self) -> None:
        relay_main.DATA_FILE.write_text("{ invalid", encoding="utf-8")

        response = self.client.get("/list")

        self.assertEqual(response.status_code, 500, response.text)

    def test_save_happens_only_after_agent_ack(self) -> None:
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")
        relay_main.wait_for_agent_action = AsyncMock(
            return_value={
                "status": "error",
                "code": "hosts_unavailable",
                "message": "hosts unavailable",
            }
        )

        response = self.client.post("/block", json={"domain": "reddit.com"})

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(relay_main.load_blocked_domains(), [])

    def test_agent_exit_marks_agent_error_state(self) -> None:
        websocket = object()
        relay_main.manager.active_connections[websocket] = relay_main.AgentState(status="ready")

        relay_main.record_agent_exit(
            websocket,
            {
                "agent_name": "agent-1",
                "error_code": "hosts_unavailable",
                "exit_code": 21,
                "message": "Hosts file write failed.",
            },
        )

        state = relay_main.manager.active_connections[websocket]
        self.assertEqual(state.status, "error")
        self.assertEqual(state.error_code, "hosts_unavailable")
        self.assertIn("exit code 21", state.message or "")

    def test_agent_logs_are_plain_text_with_uniform_timestamps(self) -> None:
        websocket = object()
        relay_main.manager.active_connections[websocket] = relay_main.AgentState(
            status="ready",
            agent_name="agent-1",
        )

        with patch.object(relay_main, "format_log_timestamp", return_value="07:40 - 20.03.26"):
            relay_main.record_agent_log(
                websocket,
                {
                    "agent_name": "agent-1",
                    "level": "INFO",
                    "message": "Connected to relay:\nws://example.test/ws",
                    "created": 1774017642.943216,
                },
            )

        self.assertEqual(
            relay_main.read_recent_agent_logs(),
            ["[07:40 - 20.03.26] [agent-1] INFO Connected to relay: | ws://example.test/ws"],
        )

    def test_agent_logs_append_in_write_order(self) -> None:
        relay_main.append_agent_log("[07:40 - 20.03.26] [agent-1] INFO first")
        relay_main.append_agent_log("[07:41 - 20.03.26] [agent-1] INFO second")

        self.assertEqual(
            relay_main.read_recent_agent_logs(),
            [
                "[07:40 - 20.03.26] [agent-1] INFO first",
                "[07:41 - 20.03.26] [agent-1] INFO second",
            ],
        )

    def test_legacy_agent_log_prefix_is_stripped(self) -> None:
        websocket = object()
        relay_main.manager.active_connections[websocket] = relay_main.AgentState(
            status="ready",
            agent_name="agent-1",
        )

        with patch.object(relay_main, "format_log_timestamp", return_value="07:40 - 20.03.26"):
            relay_main.record_agent_log(
                websocket,
                {
                    "agent_name": "agent-1",
                    "level": "INFO",
                    "message": "2026-03-20 07:40:42,943 INFO root Connected to relay: ws://example.test/ws",
                    "created": 1774017642.943216,
                },
            )

        self.assertEqual(
            relay_main.read_recent_agent_logs(),
            ["[07:40 - 20.03.26] [agent-1] INFO Connected to relay: ws://example.test/ws"],
        )

    def test_command_output_is_logged_to_separate_file(self) -> None:
        websocket = object()
        relay_main.manager.active_connections[websocket] = relay_main.AgentState(
            status="ready",
            agent_name="agent-1",
        )

        with patch.object(relay_main, "format_log_timestamp", return_value="07:40 - 20.03.26"):
            relay_main.record_agent_command_output(
                websocket,
                {
                    "agent_name": "agent-1",
                    "request_id": "req-1",
                    "shell": "powershell",
                    "stream": "stdout",
                    "message": "whoami",
                    "created": 1774017642.943216,
                },
            )

        self.assertEqual(
            relay_main.read_recent_command_logs(),
            ["[07:40 - 20.03.26] [agent-1] [req-1] [powershell] STDOUT whoami"],
        )
        self.assertEqual(relay_main.read_recent_agent_logs(), [])

    def test_run_returns_command_result(self) -> None:
        relay_main.manager.active_connections[object()] = relay_main.AgentState(status="ready")
        relay_main.wait_for_agent_action = AsyncMock(
            return_value={
                "status": "ok",
                "command_status": "failed",
                "exit_code": 1,
                "message": "Command exited with code 1.",
            }
        )

        response = self.client.post(
            "/run",
            json={"shell": "cmd", "arguments": ["/c", "exit", "1"], "timeout_seconds": 30},
        )

        self.assertEqual(response.status_code, 200, response.text)
        response_data = response.json()
        self.assertEqual(response_data["status"], "ok")
        self.assertEqual(response_data["command_status"], "failed")
        self.assertEqual(response_data["exit_code"], 1)
        self.assertEqual(response_data["shell"], "cmd")
        self.assertEqual(response_data["arguments"], ["/c", "exit", "1"])

    def test_pull_endpoint_returns_git_output(self) -> None:
        with patch.object(relay_main, "run_git_pull", return_value={"output": "Already up to date."}):
            response = self.client.post("/pull")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json(),
            {
                "status": "ok",
                "message": "git pull completed successfully.",
                "output": "Already up to date.",
            },
        )

    def test_pull_endpoint_requires_token_when_configured(self) -> None:
        with patch.dict(os.environ, {"PULL_TOKEN": "secret-token"}, clear=False):
            response = self.client.post("/pull")
            self.assertEqual(response.status_code, 403, response.text)

            with patch.object(relay_main, "run_git_pull", return_value={"output": "Already up to date."}):
                authorized_response = self.client.post(
                    "/pull",
                    headers={"X-Pull-Token": "secret-token"},
                )

        self.assertEqual(authorized_response.status_code, 200, authorized_response.text)


class AgentCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_hosts_file = blocker_agent.HOSTS_FILE
        self.original_relay_reconnect_delay_seconds = blocker_agent.RELAY_RECONNECT_DELAY_SECONDS
        self.original_self_update_url_override = blocker_agent.SELF_UPDATE_URL_OVERRIDE
        self.original_self_update_interval_seconds = blocker_agent.SELF_UPDATE_INTERVAL_SECONDS
        fd, hosts_path = tempfile.mkstemp(prefix="site_block_hosts_", text=True)
        os.close(fd)
        self.hosts_path = hosts_path
        Path(self.hosts_path).write_text("127.0.0.1 localhost\n", encoding="utf-8")
        blocker_agent.HOSTS_FILE = self.hosts_path

    def tearDown(self) -> None:
        blocker_agent.HOSTS_FILE = self.original_hosts_file
        blocker_agent.RELAY_RECONNECT_DELAY_SECONDS = self.original_relay_reconnect_delay_seconds
        blocker_agent.SELF_UPDATE_URL_OVERRIDE = self.original_self_update_url_override
        blocker_agent.SELF_UPDATE_INTERVAL_SECONDS = self.original_self_update_interval_seconds
        if os.path.exists(self.hosts_path):
            os.unlink(self.hosts_path)
        blocker_agent.PENDING_LOG_MESSAGES.clear()

    def test_agent_accepts_domain_and_url_payloads(self) -> None:
        class FakeWs:
            def __init__(self) -> None:
                self.messages: list[str] = []

            async def send(self, payload: str) -> None:
                self.messages.append(payload)

        async def run_checks() -> None:
            ws = FakeWs()
            await blocker_agent._handle_relay_message(
                ws,
                {"action": "block", "domain": "Reddit.com", "request_id": "1"},
            )
            self.assertIn("reddit.com", Path(self.hosts_path).read_text(encoding="utf-8"))

            await blocker_agent._handle_relay_message(
                ws,
                {"action": "refresh", "domains": ["chatgpt.com"], "request_id": "2"},
            )
            content = Path(self.hosts_path).read_text(encoding="utf-8")
            self.assertIn("chatgpt.com", content)
            self.assertNotIn("reddit.com", content)

            await blocker_agent._handle_relay_message(
                ws,
                {"action": "unblock", "url": "chatgpt.com", "request_id": "3"},
            )
            self.assertNotIn("chatgpt.com", Path(self.hosts_path).read_text(encoding="utf-8"))

        asyncio.run(run_checks())

    def test_log_buffer_is_bounded(self) -> None:
        handler = blocker_agent.RelayLogBufferHandler()

        for index in range(1100):
            record = blocker_agent.logging.LogRecord(
                name="bounded-test",
                level=blocker_agent.logging.INFO,
                pathname=__file__,
                lineno=index + 1,
                msg="message %s",
                args=(index,),
                exc_info=None,
            )
            handler.emit(record)

        self.assertLessEqual(len(blocker_agent.PENDING_LOG_MESSAGES), 1000)
        self.assertEqual(blocker_agent.PENDING_LOG_MESSAGES[-1]["message"], "message 1099")

    def test_fatal_payload_notifies_relay_before_exit(self) -> None:
        class FakeWs:
            def __init__(self) -> None:
                self.messages: list[str] = []

            async def send(self, payload: str) -> None:
                self.messages.append(payload)

        async def run_failure() -> None:
            ws = FakeWs()
            with self.assertRaises(blocker_agent.AgentProcessError) as context:
                await blocker_agent._handle_relay_message(
                    ws,
                    {"action": "block", "domain": "not a valid host name", "request_id": "123"},
                )

            self.assertEqual(context.exception.exit_code, blocker_agent.EXIT_CODE_INVALID_ACTION_PAYLOAD)
            payloads = [loads(message) for message in ws.messages]
            self.assertEqual(payloads[0]["type"], "agent_action_result")
            self.assertEqual(payloads[0]["status"], "error")
            self.assertEqual(payloads[1]["type"], "agent_exit")
            self.assertEqual(payloads[1]["exit_code"], blocker_agent.EXIT_CODE_INVALID_ACTION_PAYLOAD)

        asyncio.run(run_failure())

    def test_run_action_reports_command_output_and_result(self) -> None:
        class FakeWs:
            def __init__(self) -> None:
                self.messages: list[str] = []

            async def send(self, payload: str) -> None:
                self.messages.append(payload)

        async def fake_run_background_command(ws, **kwargs):
            await blocker_agent._send_command_output(
                ws,
                request_id=kwargs["request_id"],
                shell=kwargs["shell"],
                stream="stdout",
                message="hello from system",
            )
            return {
                "command_status": "succeeded",
                "exit_code": 0,
                "message": "Command exited with code 0.",
            }

        async def run_command() -> None:
            ws = FakeWs()
            with patch.object(blocker_agent, "_run_background_command", side_effect=fake_run_background_command):
                await blocker_agent._handle_relay_message(
                    ws,
                    {
                        "action": "run",
                        "shell": "powershell",
                        "arguments": ["-Command", "Write-Output", "hello from system"],
                        "timeout_seconds": 30,
                        "request_id": "run-1",
                    },
                )

            payloads = [loads(message) for message in ws.messages]
            self.assertEqual(payloads[0]["type"], "agent_command_output")
            self.assertEqual(payloads[0]["message"], "hello from system")
            self.assertEqual(payloads[1]["type"], "agent_action_result")
            self.assertEqual(payloads[1]["command_status"], "succeeded")
            self.assertEqual(payloads[1]["exit_code"], 0)

        asyncio.run(run_command())

    def test_self_update_script_replaces_agent_and_restarts(self) -> None:
        script = blocker_agent._build_self_update_script(
            target_path=Path("C:/site block/blocker/agent.py"),
            update_url="https://example.test/blocker/agent.py",
            script_path=Path("C:/Temp/update_agent.ps1"),
            current_pid=1234,
            executable_path="C:/Python/pythonw.exe",
            argv=["--relay-url", "ws://example/ws"],
        )

        self.assertIn("Invoke-WebRequest -Uri $updateUrl", script)
        self.assertIn("$downloadPath = [System.IO.Path]::GetTempFileName()", script)
        self.assertIn("Move-Item -LiteralPath $downloadPath -Destination $targetPath -Force", script)
        self.assertIn("Start-Process -FilePath $pythonPath", script)
        self.assertIn('["--relay-url", "ws://example/ws"]', script)
        self.assertIn("Get-Process -Id 1234", script)

    def test_check_for_self_update_schedules_restart(self) -> None:
        blocker_agent.SELF_UPDATE_URL_OVERRIDE = "https://example.test/blocker/agent.py"

        async def run_check() -> None:
            with patch.object(blocker_agent, "_fetch_remote_agent_source", return_value="new version\n") as fetch_source:
                with patch.object(blocker_agent, "_load_local_agent_source", return_value="old version\n"):
                    with patch.object(blocker_agent, "_schedule_self_update") as schedule_update:
                        with self.assertRaises(blocker_agent.AgentRestartRequested):
                            await blocker_agent._check_for_self_update()

            fetch_source.assert_called_once_with("https://example.test/blocker/agent.py")
            schedule_update.assert_called_once_with("https://example.test/blocker/agent.py")

        asyncio.run(run_check())

    def test_periodic_self_update_checks_immediately_on_startup(self) -> None:
        check_mock = AsyncMock(side_effect=blocker_agent.AgentRestartRequested("Agent self-update scheduled."))
        sleep_mock = AsyncMock()

        async def run_check() -> None:
            with patch.object(blocker_agent, "_check_for_self_update", check_mock):
                with patch.object(blocker_agent.asyncio, "sleep", sleep_mock):
                    with self.assertRaises(blocker_agent.AgentRestartRequested):
                        await blocker_agent._periodic_self_update_check()

        asyncio.run(run_check())

        check_mock.assert_awaited_once()
        sleep_mock.assert_not_awaited()

    def test_main_returns_non_zero_on_fatal_error(self) -> None:
        async def failing_run_forever() -> None:
            raise blocker_agent.AgentProcessError(
                exit_code=blocker_agent.EXIT_CODE_INVALID_RELAY_MESSAGE,
                error_code="invalid_relay_message",
                message="Relay sent malformed JSON.",
            )

        parser = Mock()
        parser.parse_args.return_value = Namespace(command=None)

        with patch.object(blocker_agent, "_build_parser", return_value=parser):
            with patch.object(blocker_agent, "acquire_single_instance_lock", return_value="lock-handle"):
                with patch.object(blocker_agent, "release_single_instance_lock") as release_lock:
                    with patch.object(blocker_agent, "run_forever", new=failing_run_forever):
                        exit_code = blocker_agent.main()

        self.assertEqual(exit_code, blocker_agent.EXIT_CODE_INVALID_RELAY_MESSAGE)
        release_lock.assert_called_once_with("lock-handle")

    def test_run_forever_retries_relay_connection_failures(self) -> None:
        blocker_agent.RELAY_RECONNECT_DELAY_SECONDS = 7
        listen_mock = AsyncMock(
            side_effect=[
                blocker_agent.AgentProcessError(
                    exit_code=blocker_agent.EXIT_CODE_RELAY_CONNECTION_FAILURE,
                    error_code="relay_connection_failed",
                    message="Relay connection failed: socket closed",
                ),
                None,
            ]
        )
        sleep_mock = AsyncMock()

        async def run_check() -> None:
            with patch.object(blocker_agent, "listen", listen_mock):
                with patch.object(blocker_agent.asyncio, "sleep", sleep_mock):
                    await blocker_agent.run_forever()

        asyncio.run(run_check())

        self.assertEqual(listen_mock.await_count, 2)
        sleep_mock.assert_awaited_once_with(7)

    def test_run_forever_re_raises_non_relay_failures(self) -> None:
        listen_mock = AsyncMock(
            side_effect=blocker_agent.AgentProcessError(
                exit_code=blocker_agent.EXIT_CODE_HOSTS_UNAVAILABLE,
                error_code="hosts_unavailable",
                message="Hosts file write failed.",
            )
        )
        sleep_mock = AsyncMock()

        async def run_check() -> None:
            with patch.object(blocker_agent, "listen", listen_mock):
                with patch.object(blocker_agent.asyncio, "sleep", sleep_mock):
                    with self.assertRaises(blocker_agent.AgentProcessError) as context:
                        await blocker_agent.run_forever()

            self.assertEqual(context.exception.error_code, "hosts_unavailable")

        asyncio.run(run_check())

        sleep_mock.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
