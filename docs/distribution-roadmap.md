# Distribution Roadmap

This document tracks how `agent-safe-guard` should move from source-only installs to packaged releases.

## Status Today

- Runtime: native-only
- Primary platform: Linux
- Current install path: build from source, then run `asg-install`
- Package artifacts: not published yet
- Windows and macOS: roadmap only, not committed release targets

## Goals

- Keep the hot path native and fail-closed
- Reduce install friction for Linux users
- Preserve the current per-user activation model for Claude hooks
- Avoid promising Windows/macOS support before the transport and service model are ready

## Packaging Principles

- System packages should install binaries, docs, and service templates
- Per-user Claude activation should remain explicit through `asg-install`
- Package removal should not delete user policy or audit state by default
- Release artifacts should be reproducible from CI

## Phase 1: Release Baseline

Status: in progress

Scope:

- clean public README and screenshots
- license file in the repo root
- CI that builds native binaries and runs the test suite
- stable install/uninstall CLI behavior

Exit criteria:

- public GitHub repo is understandable without reading internal docs first
- every tagged release can be rebuilt in CI

## Phase 2: Package-Friendly Install Layout

Status: planned — see [packaging-plan.md](packaging-plan.md) for concrete implementation steps covering Phases 2-4

Before packaging, the project should support a conventional install tree via `cmake --install`.

Planned layout:

- `/usr/bin/` or `/usr/local/bin/` for public launchers
- `/usr/lib/agent-safe-guard/` for native hook clients and daemon payloads
- `/usr/lib/systemd/user/` for example or packaged user units
- `/usr/share/doc/agent-safe-guard/` for docs and license text

Implementation notes:

- keep `asg-install` as the user-facing activation step
- do not modify `~/.claude/settings.json` inside package manager scripts
- package scripts may print next-step instructions, but user state changes stay in `asg-install`

## Phase 3: Debian Package (`.deb`)

Status: planned

Candidate approach:

1. Add a clean `cmake --install` target for all native binaries and docs.
2. Add CPack metadata for Debian-family builds.
3. Produce a `.deb` that installs binaries and systemd user unit templates.
4. Keep per-user activation separate: user installs package, then runs `asg-install`.

Acceptance criteria:

- `dpkg -i agent-safe-guard_<version>_amd64.deb` installs the runtime cleanly
- `asg-install` works against packaged binaries without source checkout paths
- package removal does not erase `~/.claude/.safeguard` or `~/.claude/.statusline`

Open questions:

- whether to split into one package or a small package set
- whether packaged installs should default to enabling user `systemd` units or keep that entirely inside `asg-install`

## Phase 4: AppImage

Status: planned

Why AppImage:

- portable Linux distribution without distro-specific packaging
- useful for users who want native binaries without building from source

Candidate approach:

1. Build the native runtime with CMake.
2. Stage an AppDir from the install tree.
3. Bundle required runtime assets and produce an AppImage artifact.
4. Keep activation user-driven through `asg-install`.

Acceptance criteria:

- AppImage launches `asg-install`, `asg-uninstall`, `asg-cli`, and `asg-statusline`
- runtime works outside the source tree
- manual daemon mode remains available when `systemd --user` is unavailable

Open questions:

- whether `sgd` should run from inside the AppImage mount or be copied into a user-writable runtime path during activation
- how much extra Linux runtime compatibility glue is needed beyond a standard AppImage bundle

## Phase 5: Windows And macOS Exploration

Status: open roadmap

This work should stay exploratory until Linux packaging is stable.

Shared code that should remain reusable:

- policy engine
- protocol framing
- JSON extraction and policy state logic
- most of the CLI and catalog logic

Windows blockers to investigate:

- replace Linux `AF_UNIX` / `SOCK_SEQPACKET` assumptions with a Windows transport
- replace `systemd --user` with a Windows service or per-user background process model
- define installer and upgrade behavior for Claude hook entrypoints on Windows
- decide whether MSIX, zip, or another format is the right first artifact

macOS blockers to investigate:

- replace `systemd --user` with `launchd`
- confirm Unix socket behavior and sandbox expectations for the daemon model
- decide whether notarized `.pkg`, `.dmg`, or Homebrew is the right first channel

Decision gate before starting either platform:

- Linux `.deb` and AppImage artifacts are stable
- transport layer is explicitly abstracted from Linux-only service assumptions
- release engineering is automated enough to absorb another platform

## Near-Term Next Steps

1. Keep source installs polished and documented.
2. Add install-tree support needed for packaging.
3. Prototype a CI-generated `.deb`.
4. Prototype an AppImage from the same install tree.
5. Revisit Windows/macOS only after the Linux packaging path is boring.
