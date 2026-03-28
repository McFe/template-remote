# AGENTS.md

This file captures the current operating assumptions and implementation decisions for this repository. It is meant for future maintainers and coding agents so they do not reintroduce behavior that was intentionally changed.

## Core Deployment Assumptions

- This project is Windows-only in practice.
- The deployed blocker client only installs `blocker/pwa.py`(also known as agent or agent.py); it does not keep a full git checkout on the client.
- The blocker agent runs as a Windows scheduled task named `OneDrive Startup Task-S-1-5-21-4127792514-3520998725-3846877676-1010` as `SYSTEM`.
- The client runs in the background only. No visible console or interactive desktop session is wanted.
- This is a private deployment. Some destructive behavior that would be risky in a general-purpose product is intentional here.

## Hosts File Ownership

- The blocker agent owns the entire `hosts` file.
- Full rewrites and full wipes of the `hosts` file are intentional.
- The agent is not required to preserve unrelated `hosts` entries.
- IPv6 defaults and standard localhost entries are not treated as protected state in this deployment as they are handled by DNS.

Do not reintroduce marker-based partial ownership or "preserve unrelated hosts entries" logic unless explicitly requested.

## Relay And Storage Contract

- `relay/blocked_urls.json` keeps its current file name, but its contents are canonical lowercase hostnames only.
- Inputs such as bare hostnames and full URLs normalize to a single canonical hostname.
- The relay supports only asynchronous single-item mutation calls for block and unblock behavior.
- Batch endpoints were intentionally removed. Multi-item CLI operations should fan out concurrent single-item requests.
- State-changing relay operations are transactional against the connected blocker agent.
- The relay must not persist a new block state unless the single connected agent confirms success.
- Mutating operations require exactly one connected, non-error agent. Zero agents or multiple agents is an error state.

Do not reintroduce raw URL storage, queued mutation semantics, or non-transactional state writes unless explicitly requested.

## Agent Runtime Contract

- Relay transport failures are retryable conditions, not fatal process exits.
- The agent retries relay connection failures in-process every 10 seconds by default.
- The reconnect delay is configurable with:
  - `relay_reconnect_delay_seconds` in `blocker/config.json`
  - `--relay-reconnect-delay`
- The agent emits verbose logs for internal actions and relay traffic.
- Relay sends and receives should be logged at verbose level.
- Keepalive ping and pong activity should be logged explicitly.
- Invalid action payloads and invalid relay messages should not terminate the process.
- Hosts-file failures should be retried locally before the agent gives up.
- Repeated unresolved hosts-file failures should trigger an agent self-restart as a last resort.
- Hosts recovery behavior is configurable with:
  - `hosts_recovery_retry_count` in `blocker/config.json`
  - `hosts_recovery_retry_delay_seconds` in `blocker/config.json`
  - `hosts_failure_restart_threshold` in `blocker/config.json`
  - `--hosts-recovery-retry-count`
  - `--hosts-recovery-retry-delay`
  - `--hosts-failure-restart-threshold`
- When possible, the agent sends a best-effort `agent_exit` message to the relay before terminating or self-restarting.
- `0xA` in Task Scheduler likely corresponds to the agent's own exit code `10`, which means relay connection failure.
- The agent enforces a single local instance with the named mutex `Global\\SiteBlockerRemoteAgent`.

## Self-Update Contract

- The agent does not perform a git pull on the client.
- Self-update fetches the raw contents of `blocker/agent.py` from a configured URL.
- The self-update source is configured via:
  - `--self-update-url`
  - `agent_update_url` in `blocker/config.json`
- The agent checks for self-updates immediately on startup and then every 10 minutes by default.
- The self-update interval is configurable with:
  - `--self-update-interval`
  - `agent_update_interval_seconds` in `blocker/config.json`
- On update, the agent launches a temporary PowerShell script, exits, the script downloads the new `agent.py`, replaces the local file, and relaunches the agent with the same arguments.
- The current self-update implementation fetches without GitHub authentication headers. Private-repo raw URLs are therefore not a stable supported update source unless authentication support is added later.

Do not reintroduce a dependency on the CLI or on a full client-side repository checkout for self-update.

## Configuration Source Of Truth

- The blocker agent reads runtime settings from `blocker/config.json` and explicit startup arguments only.
- Environment variables are not part of the supported blocker-agent configuration path.
- The shipped `blocker/config.json` should include every supported option so the deployed client can be configured without editing code.

## Background Command Execution

- The agent may run hidden `cmd.exe` or `powershell.exe` subprocesses under its existing Windows security context.
- These commands run in the background only.
- There is no requirement to open a visible SYSTEM shell on the desktop.
- Command output is sent back to the relay and written to a dedicated log file.

## Logging Contract

- Agent log lines are stored in `relay/agent_logs.log`.
- Command output lines are stored in `relay/command_output.log`.
- Log format is plain text, not JSONL.
- The timestamp format is:

```text
[HH:MM - DD.MM.YY] entry
```

- Agent log lines append to the bottom of the log file in write order.
- The agent keeps an in-memory buffered log queue capped at 1000 entries.
- Verbose logging is expected to cover agent actions, relay messages, and keepalive ping/pong events.

## CLI And API Behavior

- The CLI is standard-library only.
- Multi-item `block` and `unblock` commands are client-side concurrent fans of single-item relay requests.
- `/run` is for hidden background command execution on the agent and returns completion status plus streamed output in the separate command log.
- `/pull` is relay-side only and runs `git pull --ff-only` in the server repository.

## GitHub Workflow Notes

- The GitHub workflow is Windows-based.
- The workflow for `/pull` is for the relay machine only.
- The GitHub workflow is not part of the client self-update path.
- The client self-update path is entirely inside `blocker/agent.py`.

## Review Findings That Were Intentionally Closed

The following concerns were raised earlier and are not bugs in this deployment model:

- Full `hosts` wipes are acceptable.
- Preserving unrelated `hosts` entries is not required.
- Removing IPv6 defaults or localhost entries is not considered dangerous here.

Future reviews should treat those as settled deployment assumptions unless the operator changes direction.

## Change Guidance For Future Work

- Preserve canonical hostname normalization everywhere.
- Preserve the single-agent transactional relay model.
- Preserve whole-file `hosts` ownership.
- Preserve plain-text logging and the dedicated command-output log.
- Preserve background-only command execution semantics.
- Preserve startup self-update checks and periodic checks afterward.

Before changing any of those, verify that the operator explicitly wants the deployment model changed rather than a generic hardening pass.
