# agent-safe-guard

[![CI](https://github.com/regen-dev/agent-safe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/regen-dev/agent-safe-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Native safety hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) on Linux.

`agent-safe-guard` sits between Claude Code and its tool calls. It blocks destructive commands, trims noisy output, guards large reads, enforces subagent budgets, records audit events, and exposes a native rule/package console.

## Why

AI coding agents execute shell commands, read files, and make permission decisions on your behalf. Without guardrails, a single hallucinated `rm -rf /` or a leaked `.env` read can cause real damage. `agent-safe-guard` adds a fail-closed enforcement layer that runs before every tool call reaches your system.

## Current Release

- Linux-first, native-only runtime (C++20 daemon + hook clients)
- Source install today
- `.deb` and AppImage planned
- Windows and macOS on the roadmap behind a transport abstraction

## What It Does

- Blocks destructive shell patterns (`rm -rf /`, fork bombs, `curl | bash`, force pushes to protected branches)
- Requires quiet flags for commands that would flood context
- Denies bundled, generated, binary, or oversized `Read` targets
- Compresses large `Read` outputs into structural summaries
- Auto-decides safe vs unsafe permission requests
- Masks secrets and credentials in file reads
- Tracks session metrics, rule matches, tool latency, compaction, and subagent usage
- Supports extension packages from remote catalogs (marketplace)
- Lets you inspect and override policy at the package and rule level with `asg-cli`

## Screenshots

### Rules

Browse packages and their rules. Toggle individual rules on/off.

![Rules view](screenshots/console-rules.png)

### Rule Detail

Inspect rule metadata, match stats, and override state.

![Rule detail](screenshots/console-rule-detail.png)

### Catalog

Sync extension packages from remote catalogs and install them.

![Catalog view](screenshots/console-catalog.png)

### Package Detail

View installed package info, version, tags, and contained rules.

![Package detail](screenshots/console-package-detail.png)

### Settings

Toggle defense features and see what each one controls.

![Settings view](screenshots/console-settings.png)

## Quick Start

Requirements:

- Linux (x86_64)
- `jq`
- `coreutils`
- `cmake` 3.20+
- A C++20 compiler (`g++` 10+ or `clang++` 13+)

Installation from source:

```bash
git clone https://github.com/regen-dev/agent-safe-guard.git
cd agent-safe-guard
git submodule update --init --recursive   # needed for tests only
cmake -S . -B build/native -DSG_BUILD_NATIVE=ON
cmake --build build/native -j$(nproc)
./build/native/native/asg-install
```

Notes:

- The installer creates native hook symlinks in `~/.claude/hooks/asg-*`.
- It installs `asg-cli`, `asg-statusline`, `asg-install`, and `asg-uninstall` into `~/.local/bin`.
- It attempts to install and enable user `systemd` socket units for `sgd`.
- `~/.local/bin` should be on your `PATH`.
- Start a new Claude Code session after install.

If your environment does not have a working `systemd --user` session, use the manual daemon path:

```bash
./build/native/native/asg-install --no-enable-systemd-user
./build/native/native/sgd --socket /tmp/agent-safe-guard/sgd.sock
```

The native clients already probe `/tmp/agent-safe-guard/sgd.sock`, so this manual mode works without extra hook changes.

## Verify The Install

Check the installed entrypoints:

```bash
ls -l ~/.claude/hooks/asg-pre-tool-use
ls -l ~/.local/bin/asg-cli ~/.local/bin/asg-install ~/.local/bin/asg-uninstall
```

Check the public CLIs:

```bash
asg-install --help
asg-uninstall --help
asg-cli --print-rules
```

## Everyday Commands

Install or reinstall:

```bash
asg-install
```

Open the policy console:

```bash
asg-cli
```

Print package and rule state non-interactively:

```bash
asg-cli --print-rules
```

Uninstall hooks and launchers while preserving local config/state:

```bash
asg-uninstall
```

## How It Works

Hot-path enforcement is native:

1. Claude Code emits a hook event as JSON on stdin.
2. A native hook client (`sg-hook-*`) forwards the payload to `sgd` over a Unix socket.
3. The daemon evaluates built-in rules and compiled catalog patterns, then returns hook JSON.
4. Claude Code receives the decision (deny, allow, modify output, stop session).

All enforcement is fail-closed: if the daemon is unreachable, hook clients deny the tool call rather than letting it through.

Repository layout:

```text
config.env                  # Default thresholds and limits
native/                     # Native daemon, hook clients, CLI tools
hooks/                      # Legacy/reference Bash implementation, not installed
systemd/                    # User systemd socket + service unit templates
docs/                       # Architecture and roadmap docs
tests/                      # bats-core integration tests (461 tests)
screenshots/                # README assets
```

## Configuration And State

Main config files and state directories:

- `~/.claude/.safeguard/config.env`
- `~/.claude/.safeguard/features.env`
- `~/.claude/.safeguard/policy/packages.json`
- `~/.claude/.safeguard/policy/installed.json`
- `~/.claude/.safeguard/policy/catalogs.json`
- `~/.claude/.safeguard/policy/stats/`
- `~/.claude/.statusline/events.jsonl`

Useful event inspection commands:

```bash
rg '"event_type":"rule_match"' ~/.claude/.statusline/events.jsonl
rg '"event_type":"blocked"' ~/.claude/.statusline/events.jsonl
rg '"event_type":"permission_decision"' ~/.claude/.statusline/events.jsonl
rg '"event_type":"read_guard"' ~/.claude/.statusline/events.jsonl
```

## Testing

Install does not require git submodules. Tests do.

```bash
git submodule update --init --recursive
make native-build
make test
```

Useful test targets:

- `make test` — all 461 tests, parallel
- `make test-unit` — unit tests only
- `make test-integration` — integration tests only
- `make coverage` — with line coverage report
- `make test-native-pre-smoke` — pre-tool-use smoke tests against native daemon
- `make test-native-rule-audit` — verify all rules compile and match expected inputs

The test suite runs in isolated temp homes. It does not touch your real `~/.claude` state.

## Extension Packages (Catalog)

`agent-safe-guard` supports installing additional rule packages from remote catalogs. The default catalog is hosted at [regen-dev/agent-safe-guard-rules](https://github.com/regen-dev/agent-safe-guard-rules).

Sync and install via the `asg-cli` Catalog tab, or non-interactively:

```bash
asg-cli --catalog-sync
asg-cli --catalog-install cloud-defense
```

Catalog packages use SHA256 integrity checks. The daemon compiles catalog rule patterns into regex matchers at startup.

## Roadmap

Distribution and platform planning lives in [docs/distribution-roadmap.md](docs/distribution-roadmap.md).

Current direction:

- Ship a clean source release first
- Add `.deb` packaging for Debian/Ubuntu users
- Add AppImage for portable Linux installs
- Keep Windows and macOS on the roadmap as exploratory work behind a transport/service abstraction checkpoint

## Documentation

- [native/README.md](native/README.md) — native runtime, protocol, event logging
- [docs/rule-engine-architecture.md](docs/rule-engine-architecture.md) — phase model, ModSecurity-style engine
- [docs/policy-catalog-console-plan.md](docs/policy-catalog-console-plan.md) — catalog and console UX design
- [docs/distribution-roadmap.md](docs/distribution-roadmap.md) — packaging and platform plan

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
