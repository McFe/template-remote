# Site Block

Site Block is a private Windows site-blocking system with three parts:

- `relay/` exposes HTTP and WebSocket endpoints and stores the canonical blocked hostname list.
- `blocker/` runs on a Windows machine, owns the entire `hosts` file, and applies relay updates.
- `cli/` provides a dependency-free command-line client for managing the relay.

## Repository Layout

```text
site block/
|-- blocker/
|   |-- agent.py
|   |-- install.bat
|   `-- requirements.txt
|-- cli/
|   |-- cli.py
|   `-- config.json
`-- relay/
    |-- blocked_urls.json
    |-- main.py
    `-- requirements.txt
```

## How It Works

1. A client sends `block`, `unblock`, `refresh`, `erase`, or `run` requests to the relay.
2. The relay requires exactly one connected, non-error blocker agent for mutating operations.
3. The relay sends the requested action to the agent and waits for the agent to confirm it.
4. Only after confirmation does the relay persist the new hostname list to `relay/blocked_urls.json`.
5. On connect, the relay sends the full canonical hostname list so the agent can reconcile the local `hosts` file.
6. If the agent hits a fatal runtime, relay, or hosts-file error, it exits so the Windows scheduled task can restart it cleanly.

The relay stores only lowercase hostnames. Inputs such as `reddit.com`, `https://reddit.com`, and `https://reddit.com/r/python` all normalize to `reddit.com`.

## Components

### Relay

The relay is a FastAPI app in `relay/main.py`. It serves:

- `GET /list`
- `GET /agent-logs`
- `GET /command-logs`
- `POST /block`
- `POST /unblock`
- `POST /refresh`
- `POST /erase`
- `POST /run`
- `WS /ws`

Important relay behavior:

- `relay/blocked_urls.json` stores canonical lowercase hostnames only.
- `relay/agent_logs.log` stores agent logs as plain text lines formatted like `[HH:MM - DD.MM.YY] [agent-name] LEVEL message`.
- `relay/command_output.log` stores command output lines as plain text lines formatted like `[HH:MM - DD.MM.YY] [agent-name] [request-id] [shell] STREAM message`.
- Missing `blocked_urls.json` is treated as an empty block list.
- Invalid or unreadable `blocked_urls.json` is treated as a server error.
- State-changing operations are transactional against the connected agent.
- Batch endpoints are not exposed; callers should issue concurrent single-item requests instead.

### Blocker Agent

The blocker agent in `blocker/agent.py`:

- connects to the relay WebSocket defined by `RELAY_WS_URL`
- treats the entire `hosts` file as blocker-owned
- rewrites the file to match the relay hostname list
- flushes DNS after changes with `ipconfig /flushdns`
- can run hidden `cmd.exe` or `powershell.exe` child processes under the agent's Windows security context and stream their output back to the relay
- exits on fatal runtime, relay, or hosts-file failures
- sends a best-effort `agent_exit` notice to the relay before terminating when the WebSocket is still available
- enforces a single local agent instance with a Windows mutex

The default relay WebSocket URL in code is:

```text
ws://188.195.200.62:8000/ws
```

The agent accepts both legacy `url` / `urls` fields and canonical `domain` / `domains` fields on the WebSocket wire format, but normalizes everything to hostnames before applying it.

### Scheduled Task Installer

`blocker/install.bat` installs the agent as a Windows scheduled task named `remote`. The task:

- requires Administrator privileges to install
- runs at system startup
- runs as `SYSTEM`
- launches `pythonw.exe` with `blocker/agent.py`
- is configured to restart on failure

If you need a relay URL other than the hardcoded default, configure `RELAY_WS_URL` or `RELAY_URL` as a system environment variable before boot, or update the default in `blocker/agent.py` before installing.

### CLI

The CLI in `cli/cli.py` uses only the Python standard library. It supports:

- `block <hostname-or-url> [more ...]`
- `unblock <hostname-or-url> [more ...]`
- `list`
- `refresh`
- `erase`
- `run <cmd|powershell> [arguments ...]`

CLI behavior:

- single-item operations call `/block` or `/unblock`
- multi-item operations fan out concurrent single-item requests client-side
- mixed success is reported item-by-item
- the CLI exits non-zero if any requested item fails
- `run` waits for the command to finish and exits non-zero if the command fails or times out
- `run` command output is written by the relay to `relay/command_output.log`

Relay URL resolution order:

1. `RELAY_URL` environment variable
2. `cli/config.json`

## Requirements

### Relay

- Python 3.10+
- Packages from `relay/requirements.txt`

### Blocker Agent

- Python 3.10+
- Windows
- Administrator access to modify `C:\Windows\System32\drivers\etc\hosts`, or installation through the scheduled task
- Package from `blocker/requirements.txt`

### CLI

- Python 3.10+
- No third-party dependencies

## Setup

### 1. Start the Relay

From `relay/`:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

The relay then exposes:

- `http://<host>:8000/list`
- `http://<host>:8000/block`
- `http://<host>:8000/unblock`
- `http://<host>:8000/refresh`
- `http://<host>:8000/erase`
- `http://<host>:8000/agent-logs`
- `http://<host>:8000/command-logs`
- `ws://<host>:8000/ws`

### 2. Run or Install the Windows Agent

From `blocker/`:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

For a one-off foreground run:

```powershell
$env:RELAY_WS_URL = "ws://your-server:8000/ws"
python agent.py
```

For startup installation as a scheduled task, run PowerShell as Administrator and then:

```powershell
$env:RELAY_WS_URL = "ws://your-server:8000/ws"
.\install.bat
```

### 3. Configure and Use the CLI

Edit `cli/config.json`:

```json
{ "relay_url": "http://localhost:8000" }
```

Then run:

```powershell
python cli\cli.py block https://reddit.com
python cli\cli.py unblock reddit.com
python cli\cli.py list
python cli\cli.py refresh
python cli\cli.py run cmd /c whoami
python cli\cli.py run powershell -Command Get-Date
python cli\cli.py run powershell --timeout 30 -Command Get-Date
```

You can also override the relay URL:

```powershell
$env:RELAY_URL = "http://your-server:8000"
python cli\cli.py list
```

## API Contract

### HTTP

`GET /list`

Response:

```json
{
  "domains": ["reddit.com"],
  "urls": ["reddit.com"]
}
```

`POST /block`

Request:

```json
{ "domain": "reddit.com" }
```

or:

```json
{ "url": "https://reddit.com/r/python" }
```

Response:

```json
{
  "status": "ok",
  "domain": "reddit.com",
  "url": "reddit.com",
  "delivery": { "status": "applied" }
}
```

`POST /unblock`

Request and response follow the same shape as `/block`.

`POST /refresh`

Response:

```json
{
  "status": "ok",
  "message": "Relay state was reapplied to the hosts file.",
  "domain_count": 1,
  "url_count": 1
}
```

`POST /erase`

Response:

```json
{
  "status": "ok",
  "message": "Hosts file was erased and the relay block list was cleared.",
  "cleared_domain_count": 1,
  "cleared_url_count": 1
}
```

`POST /run`

Request:

```json
{
  "shell": "powershell",
  "arguments": ["-Command", "Get-Date"],
  "timeout_seconds": 30
}
```

Response:

```json
{
  "status": "ok",
  "command_status": "succeeded",
  "shell": "powershell",
  "arguments": ["-Command", "Get-Date"],
  "timeout_seconds": 30,
  "exit_code": 0,
  "message": "Command exited with code 0.",
  "request_id": "example-request-id"
}
```

### WebSocket

`WS /ws`

Messages sent by the relay:

```json
{ "action": "init", "domains": ["reddit.com"], "urls": ["reddit.com"] }
```

```json
{ "action": "block", "domain": "reddit.com", "url": "reddit.com" }
```

```json
{ "action": "unblock", "domain": "reddit.com", "url": "reddit.com" }
```

```json
{
  "action": "run",
  "shell": "cmd",
  "arguments": ["/c", "whoami"],
  "timeout_seconds": 30
}
```

## Operational Notes

- The relay has no authentication or authorization. Run it only in a trusted environment unless you add your own controls.
- Only one deployed agent is supported. If multiple agents connect, mutating relay operations fail with `503`.
- The agent intentionally owns the entire `hosts` file. `refresh` and `init` rewrite the file to match the relay state, and `erase` truncates it completely.
- `run` executes hidden child processes through the connected agent. When the agent is installed through the scheduled task, those commands run as `SYSTEM`.
- The agent does not self-heal in-process. Any fatal failure ends the process and is expected to be recovered by the scheduled task restart policy.
- Before deploying this version, ensure `relay/blocked_urls.json` contains canonical lowercase hostnames only.
