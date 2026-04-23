#!/usr/bin/env bash
# Shared test setup for agent-safe-guard tests

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BATS_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

load "${BATS_HELPER_DIR}/bats-support/load"
load "${BATS_HELPER_DIR}/bats-assert/load"
load "${BATS_HELPER_DIR}/bats-file/load"

# Create isolated temp environment for each test
setup_isolated_env() {
    TEST_TEMP="$(mktemp -d)"
    export HOME="$TEST_TEMP/home"
    mkdir -p "$HOME/.claude/.safeguard"
    mkdir -p "$HOME/.claude/.statusline"
    mkdir -p "$HOME/.claude/.subagent-state"
    mkdir -p "$HOME/.claude/.session-budgets"
    mkdir -p "$HOME/.claude/.session-times"
    mkdir -p "$HOME/.claude/hooks/lib"

    export SG_STATE_DIR="$HOME/.claude/.statusline"
    export SG_SESSION_BUDGET_DIR="$HOME/.claude/.session-budgets"
    export SG_SUBAGENT_STATE_DIR="$HOME/.claude/.subagent-state"
    export SG_EVENTS_FILE="$SG_STATE_DIR/events.jsonl"

    # Create default config.env
    cat > "$HOME/.claude/.safeguard/config.env" << 'EOF'
SG_TRUNCATE_BYTES=20480
SG_SUBAGENT_READ_BYTES=10240
SG_SUPPRESS_BYTES=524288
SG_READ_GUARD_MAX_MB=2
SG_WRITE_MAX_BYTES=102400
SG_EDIT_MAX_BYTES=51200
SG_NOTEBOOK_MAX_BYTES=51200
SG_DEFAULT_CALL_LIMIT=30
SG_DEFAULT_BYTE_LIMIT=102400
SG_BUDGET_TOTAL=280000
EOF

    # Repomap off by default in isolated tests — otherwise the native
    # session-start client would walk the real HOME filesystem when it
    # tries to render a repomap. Tests that exercise repomap set this
    # explicitly. Env var beats features.env via ReadFeatureSetting.
    export SG_FEATURE_REPOMAP=0

    # Symlink hooks/lib/common.sh so hooks can source it via relative path
    ln -sf "$PROJ_ROOT/hooks/lib/common.sh" "$HOME/.claude/hooks/lib/common.sh"

    # Create mock dir for overriding commands
    MOCK_DIR="$TEST_TEMP/mocks"
    mkdir -p "$MOCK_DIR"
    export ORIGINAL_PATH="$PATH"

    # Coverage tracing: BASH_ENV for child scripts/hooks, set -x for in-process calls
    if [[ -n "${SG_COVERAGE_FILE:-}" ]]; then
        export BASH_ENV="$PROJ_ROOT/tests/coverage-trace.sh"
        export PS4='+${BASH_SOURCE[0]##*/}:${LINENO}: '
        exec {_SG_COV_FD}>>"$SG_COVERAGE_FILE"
        export BASH_XTRACEFD=$_SG_COV_FD
        set -x
    fi
}

teardown_isolated_env() {
    # Restore PATH before cleanup (tests may have clobbered it)
    [[ -n "${ORIGINAL_PATH:-}" ]] && export PATH="$ORIGINAL_PATH"
    if [[ -n "${TEST_TEMP:-}" && -d "${TEST_TEMP:-}" ]]; then
        rm -rf "$TEST_TEMP"
    fi
}

# Run a hook with JSON input from file (avoids all quoting issues)
# Coverage: BASH_ENV from setup_isolated_env handles tracing in child processes
# Usage: run_hook "$HOOK" "$json_input"
run_hook() {
    local hook="$1"
    local input="$2"
    local tmpfile="$TEST_TEMP/hook_input.json"
    printf '%s' "$input" > "$tmpfile"
    run bash -c "cat '$tmpfile' | '$hook'"
}

# Run a hook capturing stderr too
run_hook_all() {
    local hook="$1"
    local input="$2"
    local tmpfile="$TEST_TEMP/hook_input.json"
    printf '%s' "$input" > "$tmpfile"
    run bash -c "cat '$tmpfile' | '$hook' 2>&1"
}

# Build a JSON hook input payload
# Usage: make_hook_input '{"tool_name":"Bash","tool_input":{"command":"ls"}}'
make_hook_input() {
    local json="$1"
    # Add defaults if not present
    printf '%s' "$json" | jq \
        '. + {session_id: (.session_id // "test-session-001"), transcript_path: (.transcript_path // "/home/testuser/.claude/projects/test/main.jsonl")}'
}

# Build a pre-tool-use Bash command input
make_bash_input() {
    local cmd="$1"
    local extra="${2:-}"
    local json
    json=$(jq -n --arg cmd "$cmd" '{
        tool_name: "Bash",
        tool_input: {command: $cmd},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    if [[ -n "$extra" ]]; then
        json=$(printf '%s' "$json" | jq --argjson extra "$extra" '. * $extra')
    fi
    printf '%s' "$json"
}

# Build a pre-tool-use input for any tool
make_tool_input() {
    local tool_name="$1"
    shift
    local input_json
    if [[ $# -gt 0 ]]; then input_json="$1"; else input_json='{}'; fi
    jq -n --arg tn "$tool_name" --argjson ti "$input_json" '{
        tool_name: $tn,
        tool_input: $ti,
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }'
}

# Build a post-tool-use input with response
make_post_input() {
    local tool_name="$1"
    local response_text="$2"
    local command="${3:-}"
    jq -n --arg tn "$tool_name" --arg rt "$response_text" --arg cmd "$command" '{
        tool_name: $tn,
        tool_input: (if $cmd != "" then {command: $cmd} else {} end),
        tool_response: {content: [{text: $rt}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }'
}

# Build a subagent transcript path
make_subagent_path() {
    local agent_id="${1:-agent-test123}"
    printf '/home/user/.claude/projects/test/subagents/%s.jsonl' "$agent_id"
}

# Create a mock command in MOCK_DIR
mock_command() {
    local name="$1"
    local behavior="${2:-exit 0}"
    cat > "$MOCK_DIR/$name" << MOCK
#!/bin/bash
$behavior
MOCK
    chmod +x "$MOCK_DIR/$name"
}

# Generate string of N bytes
generate_bytes() {
    local n="$1"
    head -c "$n" /dev/urandom | tr '\0-\377' 'A-Za-z0-9\n' 2>/dev/null || python3 -c "print('x'*$n)"
}

# Generate string of N lines
generate_lines() {
    local n="$1"
    local i=0
    while (( i < n )); do
        printf 'line %d: some content here for testing\n' "$i"
        ((i++))
    done
}
