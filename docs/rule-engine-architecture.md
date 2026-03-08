# Rule Engine Architecture

This document defines the target architecture for turning `agent-safe-guard`
into a rule-based policy engine in the style of ModSecurity/CRS, but for
Claude Code agents.

## Intent

The Claude hook wiring is bootstrap only.

- Claude always calls a fixed set of hook entrypoints.
- Users should not manage those hook activations directly.
- The real control plane must be rules, rule packages, modes, overrides, and
  audit events.

That means:

- `~/.claude/settings.json` is transport/bootstrap.
- `sgd` is the policy engine.
- `asg-cli` becomes the policy console.
- `features.env` is a compatibility layer during migration, not the long-term
  source of truth.

## ModSecurity Mapping

Conceptually, the runtime should map like this:

| ModSecurity concept | agent-safe-guard concept |
| --- | --- |
| Transaction | One Claude hook invocation plus derived context |
| Phase | Claude hook phase (`PreToolUse`, `PostToolUse`, etc.) |
| Rule | One matchable policy unit with stable `rule_id` |
| Rule group / ruleset | Package such as `command-defense` or `read-defense` |
| Disruptive action | `deny`, `fail_closed`, `suppress_output` |
| Non-disruptive action | `log`, `tag`, `set_var`, `append_context`, `modify_output` |
| `DetectionOnly` | Match and audit without blocking |
| `ctl` / exceptions | Per-project, per-tool, per-agent, or per-rule override |
| Audit log | Structured JSONL with `rule_id`, `package`, `phase`, `action`, `match` |

## Core Principles

1. Static hook wiring, dynamic policy.
   Claude integration points stay stable. Behavior changes come from rules and
   profiles, not from editing hook registrations.

2. Phase-based execution.
   Every incoming request executes only the rules registered for its phase.

3. Package-first operations.
   Operators manage defense packages first, individual rules second.

4. Stable rule ids.
   Every actionable rule has a stable `rule_id` so false positives can be
   inspected, suppressed, tuned, and discussed precisely.

5. Auditability before cleverness.
   Every match that matters should emit an audit event with enough context to
   debug the decision later.

6. Detection-only must be first-class.
   Operators need `Off`, `DetectionOnly`, and `On` at package level and, when
   needed, at rule level.

## Runtime Model

### Phase Model

The rule engine runs against the current protocol phases in
[native/include/sg/protocol.hpp](../native/include/sg/protocol.hpp):

- `pre_tool_use`
- `post_tool_use`
- `permission_request`
- `read_guard`
- `read_compress`
- `session_start`
- `session_end`
- `subagent_start`
- `subagent_stop`
- `stop`
- `pre_compact`
- `tool_error`

`statusline` is not a policy phase. It is operator HUD/output and should remain
outside the rule engine.

### Transaction Envelope

Each client should normalize incoming hook JSON into a `Transaction` that
contains:

- `phase`
- `raw_request`
- `tool_name`
- `tool_input`
- `tool_response`
- `session_id`
- `transcript_path`
- `project_root`
- `agent_type`
- `is_subagent`
- derived state paths
- environment-derived config
- mutable transaction variables

The client remains thin. The daemon owns normalization helpers, package/rule
evaluation, and audit emission.

### Evaluation Pipeline

For a transaction:

1. Build normalized `Transaction`.
2. Load active profile and package modes.
3. Collect rules for the current phase.
4. Evaluate rules in deterministic order.
5. Apply non-disruptive actions immediately.
6. Apply disruptive action based on package/rule mode:
   - `Off`: skip
   - `DetectionOnly`: audit only
   - `On`: enforce
7. Translate the resulting decision back into Claude hook JSON.

## Policy Layers

The engine should have four layers.

### 1. Phase Adapters

Phase adapters translate between Claude hook semantics and generic rule-engine
objects.

Examples:

- `PreToolUse` adapter exposes `tool_input.command`, write payload sizes,
  subagent budget state.
- `PostToolUse` adapter exposes output bytes, line count, git/system reminder
  detection, truncation candidates.
- `PermissionRequest` adapter exposes approval command and tool metadata.

### 2. Rule Packages

Packages are what operators think about.

Suggested initial packages:

- `command-defense`
- `read-defense`
- `output-defense`
- `approval-defense`
- `agent-defense`
- `memory-defense`
- `telemetry`
- `operator-hud`

Important: packages may span multiple phases.

Example:

- `command-defense` can own both `pre_tool_use` and `permission_request` rules.
- `read-defense` can own both `read_guard` and `read_compress`.

### 3. Rules

Rules are the real unit of tuning and audit.

Each rule should have:

- `rule_id`
- `name`
- `package`
- `phase`
- `severity`
- `tags`
- `mode_override` optional
- `condition`
- `actions`
- `message`

Recommended v1 action types:

- `deny`
- `fail_closed`
- `suppress_output`
- `modify_output`
- `append_context`
- `log`
- `set_var`
- `increment_score`

Recommended v1 condition operators:

- `equals`
- `contains`
- `regex`
- `starts_with`
- `ends_with`
- `gt` / `gte` / `lt` / `lte`
- `exists`
- `glob`
- boolean combinators `all`, `any`, `not`

### 4. Overrides / Exceptions

Overrides are the equivalent of `ctl` and local exclusions.

Scopes:

- global
- project
- session
- agent type
- tool name
- path
- package
- rule id

Supported exception operations:

- `disable_package`
- `disable_rule`
- `set_mode`
- `replace_action`
- `change_threshold`
- `skip_if`

## Configuration Surface

### Source of Truth

Target operator-managed state:

```text
~/.claude/.safeguard/
  config.env
  policy/
    profile.json
    packages.json
    overrides/
      global.json
      projects/
        <project-hash>.json
    rules/
      core/
        100000-command-defense.json
        200000-read-defense.json
      local/
        local-overrides.json
```

`features.env` remains only as a migration shim that maps legacy toggles to
package modes.

### Rule Format

Use JSON for v1.

Reasons:

- existing tooling already relies on JSON and `jq`
- easy to diff and inspect
- avoids adding YAML/TOML parser surface immediately
- can be compiled into in-memory structures and regex caches by the daemon

Example:

```json
{
  "version": 1,
  "package": "command-defense",
  "phase": "pre_tool_use",
  "rules": [
    {
      "rule_id": 100100,
      "name": "deny_recursive_delete_rootish",
      "severity": "critical",
      "tags": ["destructive", "filesystem"],
      "condition": {
        "all": [
          {"field": "tool_name", "equals": "Bash"},
          {"field": "tool_input.command", "regex": "rm\\s+-rf\\s+(/|~|\\.)"}
        ]
      },
      "actions": [
        {"type": "deny"},
        {"type": "log"}
      ],
      "message": "Destructive recursive delete"
    }
  ]
}
```

## Audit Model

The current `events.jsonl` should evolve into a true audit stream.

Minimum event shape:

```json
{
  "event_type": "rule_match",
  "timestamp": 1772820000,
  "phase": "pre_tool_use",
  "package": "command-defense",
  "rule_id": 100100,
  "mode": "on",
  "action": "deny",
  "severity": "critical",
  "session_id": "abc",
  "tool_name": "Bash",
  "matched_field": "tool_input.command",
  "matched_value": "rm -rf /tmp/foo",
  "message": "Destructive recursive delete",
  "project_root": "/repo"
}
```

Two practical event types are enough for v1:

- `rule_match`
- `rule_error`

Legacy summary events such as `session_start`, `tool_latency`, and `session_end`
can coexist with rule audit events.

## Operator Modes

Package mode must support:

- `off`
- `detection_only`
- `on`

Rule mode may optionally override package mode for surgical tuning.

This is the core operational feature missing today.

Examples:

- enable `command-defense` in `on`
- run `read-defense` in `detection_only` for one project
- disable a single noisy rule while keeping the package active

## UI Direction

`asg-cli` should evolve in layers.

### Level 1: Package Console

The current defense panel becomes package management:

- package mode
- severity summary
- phase coverage
- recent match counts

### Level 2: Rule Browser

Inside a package:

- list rules by id
- show phase, severity, tags, message
- toggle `on` / `detection_only` / `off`

### Level 3: Exception Console

Operators can create local exclusions:

- disable rule for this project
- set package to `detection_only` for this project
- attach expiry/notes to an override

## Implementation Shape

### New Native Components

Suggested files:

- `native/include/sg/rule_types.hpp`
- `native/include/sg/rule_engine.hpp`
- `native/include/sg/rule_loader.hpp`
- `native/include/sg/rule_audit.hpp`
- `native/src/native/rule_engine.cpp`
- `native/src/native/rule_loader.cpp`
- `native/src/native/rule_audit.cpp`
- `native/src/native/transaction.cpp`

### Adapter Refactor

Existing `Evaluate*` functions should become phase adapters, not giant policy
bodies.

Target:

- phase adapter builds transaction fields
- engine evaluates matching rules
- adapter converts final result into Claude hook response

### Backward-Compatible Migration

Phase 1:

- introduce `rule_id`, `package`, `severity`, and `mode`
- wrap current hardcoded checks as internal compiled rules
- emit `rule_match` audit events

Phase 2:

- replace `features.env` booleans with package modes
- add `DetectionOnly`
- keep legacy booleans as compatibility aliases

Phase 3:

- externalize rule definitions into JSON packages
- reload rules on daemon restart and later via explicit reload

Phase 4:

- add per-project overrides
- add rule browser in `asg-cli`

Phase 5:

- break large hardcoded policy functions into rule packages completely

## Explicit Non-Goals For V1

- dynamic user scripting inside the daemon
- arbitrary embedded Lua/JS
- remote policy fetch
- hot reloading from partially invalid rules without validation

V1 should be deterministic, local-only, and easy to audit.

## Decision Summary

The future architecture is:

- fixed Claude hook integration
- rule-engine daemon
- phase adapters
- package/rule/override policy model
- `off` / `detection_only` / `on`
- rule-centric audit events
- UI centered on defenses and rules, not hook toggles

That is the correct model if the goal is “ModSecurity for agents”.
