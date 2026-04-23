# Native Runtime (C++ / Linux-first)

This directory contains the active native runtime for `agent-safe-guard`.

## Goals

- Move hot-path hook parsing/enforcement out of Bash process chains.
- Keep hook stdin/stdout JSON contract stable.
- Use a daemon + client split so policies run in a long-lived process.
- Keep extension seams for future macOS/Windows backends.

## Binaries

- `sgd`: native daemon.
- `asg-cli`: interactive defense toggle panel (CLI/TUI) with split-view details.
- `asg-statusline`: native Claude Code status line.
- `asg-install`: native installer.
- `asg-uninstall`: native uninstaller.
- `asg-repomap`: tree-sitter-powered repo-map CLI (Phase 7, see [../docs/repomap.md](../docs/repomap.md)).
- `sg-hook-pre-tool-use`: native hook client for `pre-tool-use`.
- `sg-hook-post-tool-use`: native hook client for `post-tool-use`.
- `sg-hook-permission-request`: native hook client for `permission-request`.
- `sg-hook-read-guard`: native hook client for `read-guard`.
- `sg-hook-read-compress`: native hook client for `read-compress`.
- `sg-hook-stop`: native hook client for `stop`.
- `sg-hook-session-start`: native hook client for `session-start`.
- `sg-hook-session-end`: native hook client for `session-end`.
- `sg-hook-pre-compact`: native hook client for `pre-compact`.
- `sg-hook-subagent-start`: native hook client for `subagent-start`.
- `sg-hook-subagent-stop`: native hook client for `subagent-stop`.
- `sg-hook-tool-error`: native hook client for `tool-error`.

## Transport and protocol

- Local IPC: Unix domain `SOCK_SEQPACKET`.
- Framing: custom little-endian binary header + payload.
- Request payload: raw hook JSON.
- Response payload: raw hook output JSON.
- Failure mode: strict fail-closed (`{"continue":false,"stopReason":"..."}`) when daemon/socket path is unavailable.
- Feature/package config: legacy hook booleans and `SG_PACKAGE_*` modes are read from `~/.claude/.safeguard/features.env` (or `$SG_FEATURES_FILE`).
- Policy state lives under `~/.claude/.safeguard/policy/` (`packages.json`, `installed.json`, `catalogs.json`, cached catalogs, `stats/*.json`).
- First-party catalog bootstrap should use an immutable tag/release URL, not `main`; current seed URL is `https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/rules-v0.2.0/rules/catalogs/github-core.json`.
- Installed hook entrypoints: `~/.claude/hooks/asg-*` symlinks to these binaries.

## Event logging

Primary log file:

- `~/.claude/.statusline/events.jsonl`
- Override: `$SG_EVENTS_FILE`
- Temporary retention policy: if `SG_TELEMETRY_ENDPOINT` is unset, `events.jsonl` stops accepting new lines past 1 GiB; local `policy/stats/*.json` still updates

Native clients and policies currently emit:

- `rule_match` / `rule_error` from the native rule engine
- `blocked` from `sg-hook-pre-tool-use`
- `permission_decision` from `sg-hook-permission-request`
- `read_guard` from `sg-hook-read-guard`
- `tool_latency` from `policy_post_tool_use`
- `session_start`, `session_end`, `session_stop`
- `compaction`
- `subagent_start`, `subagent_stop`
- `tool_error`

Current gap:

- Native does not yet emit the old Bash-style `allowed` and `truncated` JSONL audit entries.
- Remote product telemetry is not implemented yet; `SG_TELEMETRY_ENDPOINT` currently only acts as a retention-policy switch for local audit growth.
- Prefer `policy/stats/rules.json` and `policy/stats/packages.json` for future aggregate telemetry instead of shipping raw `events.jsonl`.

False-positive inspection commands:

```bash
rg '"event_type":"rule_match"' ~/.claude/.statusline/events.jsonl
rg '"rule_id":100200' ~/.claude/.statusline/events.jsonl
rg '"event_type":"blocked"' ~/.claude/.statusline/events.jsonl
rg '"event_type":"permission_decision"' ~/.claude/.statusline/events.jsonl
rg '"event_type":"read_guard"' ~/.claude/.statusline/events.jsonl
rg '"session_id":"YOUR_SESSION_ID"' ~/.claude/.statusline/events.jsonl
```

## Systemd

Example units are in `systemd/`:

- `systemd/sgd.socket`: socket activation endpoint.
- `systemd/sgd.service`: daemon service unit (`Type=notify`).
- Installer-managed user units (via `asg-install --enable-systemd-user`):
  - `~/.config/systemd/user/asg.socket`
  - `~/.config/systemd/user/asg.service`

## Fast Dev Loop

- One-shot smoke run: `make test-native-pre-smoke`
- Read guard smoke run: `make test-native-read-guard-smoke`
- Read compress smoke run: `make test-native-read-compress-smoke`
- Stop smoke run: `make test-native-stop-smoke`
- Session-start smoke run: `make test-native-session-start-smoke`
- Session-end smoke run: `make test-native-session-end-smoke`
- Pre-compact smoke run: `make test-native-pre-compact-smoke`
- Subagent-start smoke run: `make test-native-subagent-start-smoke`
- Subagent-stop smoke run: `make test-native-subagent-stop-smoke`
- Tool-error smoke run: `make test-native-tool-error-smoke`
- Repomap CLI smoke run: `make test-native-repomap-smoke`
- Repomap daemon-integration smoke run: `make test-native-repomap-session-smoke`
- Watch mode: `make native-watch`

Policy console:

- Run `asg-cli`
- `Rules` is the default home
- `Tab` switches `Rules`, `Catalog`, and `Settings`
- `Space` cycles package/rule mode, `r` resets rule overrides, `s` saves, `q` quits
- Policy state lives under `~/.claude/.safeguard/policy/`

Watch mode rebuilds, restarts daemon, and reruns selected existing Bats tests against the native client.

## Portability Strategy (Future)

The current backend is Linux-optimized. To expand to other OSs:

1. Keep protocol/policy code independent from transport implementation.
2. Add transport backends by platform (e.g., named pipes/loopback for Windows).
3. Keep hook client CLI and response contract identical across OSs.
4. Add per-platform CI matrix once behavior parity is stable.
