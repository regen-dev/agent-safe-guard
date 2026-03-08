# Policy Catalog And Console Plan

This document turns the rule-engine direction into an implementation plan for
the next major UX and control-plane migration:

- `asg-cli` stops being a hook toggle panel first and becomes a rule/package
  console.
- policy becomes package/rule/override driven.
- rule/package stats become first-class.
- new rules can be installed from local packages first, then from trusted
  remote catalogs.

It is a companion to
[docs/rule-engine-architecture.md](rule-engine-architecture.md), not a
replacement.

## Source Of Truth

Curated shared rules should be managed in a dedicated GitHub repository, not
primarily authored in local machine state.

Current decision:

- curated rules live in a dedicated `regen-dev` repository
- contributions happen through pull requests
- accepted rule changes are committed to `main`
- local `agent-safe-guard` installations sync committed rule metadata and decide
  locally which packages or rules are active

Repository convention for the rules repo:

- keep authoritative rule content under `./rules`
- organize first by concern inside `rules/`, not by runtime machine state

This keeps governance centralized while preserving local activation and
override control.

## Problem Statement

The current product surface still reflects the bootstrap transport layer more
than the real policy model:

- the main UI is a `SG_FEATURE_*` toggle panel
- package modes exist in the runtime but are not operator-managed in the UI
- individual rules cannot be enabled, disabled, searched, or inspected
- `rule_match` audit exists, but there is no materialized per-rule or per-package
  stats view
- new rules cannot be installed as packages

That is good enough for the native migration, but it is not the right operator
experience for "ModSecurity for agents".

## Product Direction

The operator home screen should become `Rules`, not `Settings`.

Target information hierarchy:

1. `Rules`
   Package list, package modes, recent hits, top blocked rules, rule browser,
   search, and per-rule stats.
2. `Catalog`
   Search available packages and rules, install or update packages, inspect
   package provenance and compatibility.
3. `Overrides`
   Manage global and per-project exceptions.
4. `Settings`
   Runtime and bootstrap concerns such as status line, catalog sources, reload
   behavior, retention, and compatibility aliases.

The old defense panel moves under `Settings` during migration and eventually
becomes a compatibility layer over packages/profiles.

## Design Principles

1. Packages first, rules second.
   Operators usually think in terms of a defense domain, then tune individual
   rules inside that domain.

2. Stable ids are mandatory.
   `rule_id` must be globally unique and never reused for a different rule.

3. Search and stats drive trust.
   A rule system without searchable rule metadata and recent match counts is too
   opaque to tune safely.

4. Catalog installs must be local and auditable.
   Runtime policy should execute only from validated local files.

5. Detection-only is a core operating mode.
   Packages and rules must support `off`, `detection_only`, and `on`.

6. Bootstrap wiring stays fixed.
   Hook registration remains transport. Operators should not manage hook wiring
   as the main policy surface.

## Current State

Today the native rule engine and bridge layer cover the full runtime policy
surface:

- compiled rules still exist natively for `pre_tool_use`, `permission_request`,
  and `read_guard`
- the remaining hooks now run behind package/rule bridge rules, so they obey
  package mode, rule overrides, and `rule_match` stats even where the hook
  logic is still imperative internally
- package mode resolution already supports `off`, `detection_only`, and `on`
- audit already emits `rule_match` and `rule_error`
- runtime now materializes package/rule state under `~/.claude/.safeguard/policy/`
- `asg-cli` now opens on `Rules`, persists package/rule overrides to
  `policy/packages.json`, and keeps the old feature panel under `Settings`
- `asg-cli` now ships a dedicated `Catalog` view for sync/install/remove
  workflows in the interactive console
- `asg-cli` can now load external package manifests from an explicit rules
  directory (`SG_RULES_DIR` / `--rules-dir`) instead of relying only on
  hardcoded package metadata
- local package install/remove is now available, persisting manifests under
  `policy/installed/` and provenance in `installed.json`
- remote catalog source state now lives in `policy/catalogs.json`, with synced
  catalog indexes cached under `policy/catalogs/`
- `asg-cli` now supports explicit remote catalog add/list/sync/search/install,
  with package download cached locally and verified by `sha256` before install
- fresh installs now seed `policy/catalogs.json` with the public first-party
  `github-core` catalog unless the operator overrides the initial source before
  scaffold

Current package coverage:

- `command-defense`
- `output-defense`
- `read-defense`
- `approval-defense`
- `agent-defense`
- `telemetry`
- `memory-defense`

Current gaps that must be fixed before the full migration:

- the bridge-backed hooks still need deeper extraction into reusable compiled
  rule sets where finer-grained rule matching is worth the complexity
- first-party catalog publishing and repo automation in the dedicated rules
  repository still need to be maintained as part of release flow

## Package Model

The system should treat package as the top-level policy unit.

Suggested package set:

- `command-defense`
- `read-defense`
- `output-defense`
- `approval-defense`
- `agent-defense`
- `memory-defense`
- `telemetry`
- `operator-hud`

Packages may span multiple phases. Example:

- `read-defense` owns both `pre_tool_use` read-related safeguards and
  `read_guard` and later `read_compress`
- `command-defense` owns command checks across `pre_tool_use` and
  `permission_request`

## Mapping From The Current Panel

The current `SG_FEATURE_*` panel should be demoted to a compatibility and
bootstrap view. The migration mapping should be:

| Current panel item | Future package or bundle | Notes |
| --- | --- | --- |
| Command Firewall | `command-defense` | Seed current pre-tool rules into core package |
| Output Sanitizer | `output-defense` | Start as a bridge package around current post-tool adapter |
| Read Shield | `read-defense` | Guard rules |
| Read Compressor | `read-defense` | Compression rules under the same package |
| Permission Gate | `approval-defense` | Permission rules |
| Session Tracker | `telemetry` | Bridge package first |
| Session Cleanup | `telemetry` | Bridge package first |
| Subagent Budget Gate | `agent-defense` | Existing subagent rules move here |
| Subagent Reclaimer | `agent-defense` | Bridge package first |
| Stop Summary | `telemetry` | Bridge package first |
| Compact Memory Guard | `memory-defense` | Bridge package first |
| Error Telemetry | `telemetry` | Bridge package first |
| Live Status Bar | `operator-hud` | Not a policy phase, but still operator-managed |

Important:

- not every current panel item should become a single rule
- each current panel item should map to a package or bundle in the default core
  policy profile
- individual rules remain the tuning unit inside those packages

## Rule Model

Each rule should expose:

- `rule_id`
- `name`
- `package`
- `phase`
- `severity`
- `tags`
- `summary`
- `message`
- `mode_override` optional
- `condition`
- `actions`

Rule ids must be globally unique. The migration should reserve ranges per
package and never reuse an id for a different semantic meaning.

Recommended id strategy:

- `100000-149999`: `command-defense`
- `150000-199999`: `agent-defense`
- `200000-249999`: `approval-defense`
- `250000-299999`: `output-defense`
- `300000-349999`: `read-defense`
- `350000-399999`: `memory-defense`
- `400000-449999`: `telemetry`
- `450000-499999`: `operator-hud`
- `900000-949999`: local operator-authored rules

## Rule Stats

The system should track stats only for rule matches, not for non-matches.

Per-rule counters:

- `matched_total`
- `blocked_total`
- `allowed_total`
- `suppressed_total`
- `modified_total`
- `detect_only_total`
- `error_total`
- `last_matched_at`
- `last_blocked_at`
- `last_project`
- `last_session_id`

Per-package counters:

- `matched_total`
- `blocked_total`
- `allowed_total`
- `detect_only_total`
- `error_total`
- `enabled_rules`
- `disabled_rules`
- `recent_24h_matches`

Interpretation:

- `matched_total` means the rule condition matched
- `blocked_total` means the rule matched and produced an enforced disruptive
  deny or fail-closed outcome
- `detect_only_total` means the rule matched but package or rule mode prevented
  enforcement
- "pass" should not mean "the rule did not match"; that number is not useful
  for operators and is expensive to count accurately

## Audit Model Changes

`events.jsonl` remains the append-only audit stream. It is the source of truth.

`rule_match` should be extended with:

- `disposition`
- `enforced`
- `project_root`
- `agent_type`
- `is_subagent`
- `package_version` optional
- `catalog_id` optional

Recommended `disposition` values:

- `blocked`
- `allowed`
- `suppressed`
- `modified`
- `detect_only`
- `observed`

Recommended behavior:

- keep `rule_match` as the canonical rule-level event
- keep legacy events for compatibility during migration
- build a materialized stats index from `rule_match` and `rule_error`

## Materialized Policy State

Target operator-managed state:

```text
~/.claude/.safeguard/
  config.env
  features.env                  # compatibility only during migration
  policy/
    profile.json
    packages.json
    catalogs.json
    installed.json
    packages/
      core/
        command-defense@1.0.0.json
        read-defense@1.0.0.json
      vendor/
        github-core/
          custom-pack@1.2.3.json
    overrides/
      global.json
      projects/
        <project-hash>.json
    stats/
      rules.json
      packages.json
      recent.json
```

Notes:

- `profile.json` defines the active package set and defaults
- `packages.json` stores active package modes and package metadata cache
- `installed.json` tracks installed package versions and source provenance
- `stats/` is a materialized cache, not the source of truth

JSON is sufficient for v1. If stats volume grows, SQLite can be introduced
later behind the same interface.

## Package File Format

Package files should use JSON in v1.

Example:

```json
{
  "version": 1,
  "package_id": "core.command-defense",
  "name": "command-defense",
  "display_name": "Command Defense",
  "package_version": "1.0.0",
  "catalog_id": "core",
  "description": "Command safety checks for Bash and write-like tools.",
  "phases": ["pre_tool_use", "permission_request"],
  "tags": ["command", "bash", "destructive"],
  "rules": [
    {
      "rule_id": 100200,
      "name": "destructive_command",
      "phase": "pre_tool_use",
      "severity": "critical",
      "tags": ["destructive", "filesystem"],
      "message": "Blocked destructive command",
      "condition": {
        "all": [
          {"field": "tool_name", "equals": "Bash"},
          {"field": "tool_input.command", "contains": "rm -rf /"}
        ]
      },
      "actions": [{"type": "deny"}, {"type": "log"}]
    }
  ]
}
```

During migration, some packages will still be "compiled packages". That means:

- package metadata is externalized and operator-managed
- matcher implementation remains native for now
- the runtime exposes those rules exactly like JSON-defined rules

This lets the product ship the new console before every phase adapter is fully
rewritten.

## Catalog Model

V1 should support local package install first, then trusted remote catalogs.

The curated first-party catalog should come from the dedicated GitHub rules
repository managed by `regen-dev`. Generic third-party catalogs can still be
added later, but the default operator experience should start with the
first-party GitHub-backed source of truth.

Catalog manifest example:

```json
{
  "catalog_version": 1,
  "catalog_id": "github-core",
  "display_name": "GitHub Core Catalog",
  "source_url": "https://example.github.io/asg/catalog.json",
  "generated_at": "2026-03-07T00:00:00Z",
  "packages": [
    {
      "package_id": "vendor.owasp-style.command-hardening",
      "package_version": "1.2.0",
      "display_name": "Command Hardening",
      "description": "Additional command safety rules.",
      "download_url": "https://example.github.io/asg/packages/command-hardening-1.2.0.json",
      "sha256": "abc123...",
      "tags": ["command", "shell"],
      "phases": ["pre_tool_use"],
      "min_asg_version": "0.9.0"
    }
  ]
}
```

Catalog operations:

- add catalog by URL
- sync catalog metadata on demand
- search installed and available packages
- install a package into local policy state
- update pinned packages explicitly
- remove a package without deleting its historical stats

Search fields:

- package id
- display name
- description
- rule name
- rule id
- phase
- severity
- tags
- free-text rule message

## Catalog Trust Model

Remote policy must never execute directly from the network.

Required safeguards:

- explicit catalog add by operator
- explicit sync by operator
- download to local cache first
- validate JSON schema before install
- verify declared `sha256`
- reject incompatible package versions
- keep previously installed version on validation failure

Recommended v1 trust policy:

- support `https://` and local file paths
- keep auto-sync disabled by default
- treat catalogs as untrusted until package hash validation succeeds

Possible later additions:

- package signatures
- trusted publisher keys
- signed catalog indexes

GitHub-specific operating model for the first-party catalog:

- `main` is the published branch
- rule changes arrive via pull request review
- sync uses committed artifacts, never unmerged branch state
- local activation still requires explicit package or rule enablement

## Console UX

### Home Screen: Rules

Primary package list:

- package name
- mode
- enabled rule count
- recent match count
- recent block count
- phase coverage
- catalog and package version

Rule browser inside a package:

- rule id
- name
- phase
- severity
- mode
- tags
- recent matches
- recent blocks

Rule details pane:

- summary and message
- action type
- last matched time
- last blocked time
- sample matched field and value
- package version
- source package path
- local overrides affecting the rule

### Catalog Screen

- search box
- installed filter
- available filter
- package provenance
- package compatibility
- package changelog or summary

### Overrides Screen

Supported override scopes:

- global
- project
- package
- rule id
- tool name
- path
- agent type
- session

Supported override operations:

- set mode
- disable rule
- disable package
- replace action
- change threshold
- skip if predicate matches
- attach note and expiry

### Settings Screen

Runtime and compatibility settings:

- feature compatibility toggles
- status line enablement
- catalog sources
- sync behavior
- audit retention
- reload behavior
- migration diagnostics

## CLI Surface

The TUI should have a matching non-interactive CLI.

Suggested command set:

```text
asg rules
asg rules --package command-defense
asg rules --search destructive
asg package list
asg package set-mode command-defense detection_only
asg rule set-mode 100200 off
asg rule stats 100200
asg override add --project . --rule 100200 --mode off --note "false positive"
asg catalog add https://example.github.io/asg/catalog.json
asg catalog sync
asg catalog search shell
asg install vendor.owasp-style.command-hardening
asg remove vendor.owasp-style.command-hardening
asg settings
asg reload
```

The existing `asg-cli` entrypoint can remain, but the user-facing product name
should shift from "defense panel" to "policy console".

## Runtime Loading Model

`sgd` should own policy loading and policy cache invalidation.

Recommended loading steps:

1. load profile and package modes
2. load installed package manifests
3. compile package metadata into runtime rule objects
4. load overrides
5. build phase indexes
6. serve requests

Reload strategy:

- v1: reload on daemon restart and explicit `asg reload`
- later: add guarded hot reload after successful validation

The daemon should reject partial invalid policy updates and keep the last known
good snapshot.

## Migration Strategy

### Phase 0: Stabilize The Current Base

- make `rule_id` globally unique
- preserve unknown keys when writing compatibility config
- stop using `features.env` as the long-term write target for package state
- add package and rule stats materializer from existing audit events

### Phase 1: Policy State And Stats

- introduce `policy/` directory layout
- add `packages.json`, `installed.json`, and `stats/`
- extend `rule_match` with `disposition` and `enforced`
- expose package summaries and per-rule stats in a read-only CLI view

### Phase 2: Package Console Home

- make `Rules` the default TUI screen
- show package mode, phase coverage, recent match counts, and block counts
- move the old feature panel into `Settings`

### Phase 3: Rule Browser And Overrides

- add per-rule browsing and search
- support per-rule mode override
- support global and project overrides
- attach notes and expiry to overrides

### Phase 4: Externalized Core Packages

- externalize current compiled rule metadata into core package manifests
- keep compiled matchers where the generic condition/action vocabulary is not
  ready yet
- seed default profile with core packages mapped from current defenses

### Phase 5: Local Package Install

- validate and install package manifests from local files
- support package enable, disable, update, and remove
- keep package provenance in `installed.json`

### Phase 6: Remote Catalogs

- add catalog manifest support by URL
- sync metadata on demand
- support search across available packages and rules
- install packages only after download, validation, and hash verification

Current status:

- done in CLI/state layer
- pending in TUI as a dedicated `Catalog` screen

### Phase 7: Full Phase Migration

- expand `RulePhase` to all hook phases
- move `post_tool_use`, `read_compress`, `session_*`, `subagent_*`, `stop`,
  `pre_compact`, and `tool_error` behind phase adapters and package-owned rules
- retire feature toggles as the primary control plane

## Deferred: Product Telemetry Backend

- defer remote product telemetry until there is a real backend destination,
  retention policy, and operator-facing consent model
- keep generating local audit and materialized policy stats in the meantime
- current temporary retention policy: if no telemetry backend is configured,
  `~/.claude/.statusline/events.jsonl` should stop growing once it reaches 1 GiB
  and new audit lines should be dropped
- `stats/rules.json` and `stats/packages.json` remain the preferred future input
  for any remote aggregate telemetry so raw command/file payloads do not need to
  leave the machine by default

## Testing Plan

Add coverage in these areas:

- schema validation for package and catalog files
- package install and rollback on failure
- package mode and rule mode precedence
- override precedence by scope
- stats materialization from `rule_match`
- CLI search and filtering
- TUI save behavior preserving unrelated settings
- daemon reload and last-known-good fallback

New integration suites to add:

- `policy_catalog.bats`
- `policy_install.bats`
- `policy_stats.bats`
- `policy_overrides.bats`
- `asg_console.bats`

## Backward Compatibility

During migration:

- existing `SG_FEATURE_*` gates continue to work
- existing `SG_PACKAGE_*` env and config values remain accepted
- legacy audit events continue to coexist with `rule_match`
- installer keeps writing compatibility defaults until the new profile format is
  the default source of truth

Compatibility ends when:

- all phases have package-backed policy
- the operator home screen is rule/package based
- package and rule modes fully replace feature booleans

## Risks

- if `rule_id` reuse is not fixed early, stats and overrides will be corrupted
- if package installs are allowed without validation, remote catalogs become a
  policy injection vector
- if TUI persistence still rewrites unrelated keys, operator trust will drop
- if stats are computed only by rescanning the full audit log every time, the UI
  will become slow on long-lived installations

## Decisions

The migration should make these decisions explicit:

- the home screen becomes `Rules`
- current panel moves to `Settings`
- current defense toggles map to default package/profile state, not to single
  rules
- "rule passed" means "rule matched and produced an allow-like or non-blocking
  disposition", not "rule did not match"
- remote catalogs are opt-in, cached locally, and validated before activation
- the first-party curated rule source lives in a dedicated GitHub repository,
  with content organized under `./rules`

## Immediate Next Steps

Recommended implementation order:

1. fix global `rule_id` uniqueness
2. add `policy/` state files and stats materializer
3. make `asg-cli` read-only package/rule browser before it becomes editable
4. move current feature panel into a `Settings` subview
5. externalize core package metadata
6. add local install
7. add remote catalogs

That order keeps the migration incremental and keeps the runtime auditable the
whole time.
