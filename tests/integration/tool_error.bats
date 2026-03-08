#!/usr/bin/env bats
# Integration tests for hooks/tool-error

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK="${SG_TOOL_ERROR_HOOK:-$PROJ_ROOT/hooks/tool-error}"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# ERROR LOGGING
# ==============================================================================

@test "logs error to errors.log" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "command not found: foobar"}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    assert_exist "$HOME/.claude/errors.log"
    run grep "foobar" "$HOME/.claude/errors.log"
    assert_success
}

@test "logs tool name in error" {
    local input
    input=$(jq -n '{tool_name: "Edit", session_id: "sess-1", tool_error: "file read-only"}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    run grep "Tool: Edit" "$HOME/.claude/errors.log"
    assert_success
}

@test "emits tool_error event" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "exit code 1"}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    run grep "tool_error" "$SG_EVENTS_FILE"
    assert_success
}

# ==============================================================================
# HINTS
# ==============================================================================

@test "provides permission denied hint for Bash" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "Permission denied: /etc/shadow"}')
    run_hook "$HOOK" "$input"
    assert_output --partial "sudo"
}

@test "provides command not found hint for Bash" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "command not found: mycmd"}')
    run_hook "$HOOK" "$input"
    assert_output --partial "installed"
}

@test "provides read-only hint for Edit" {
    local input
    input=$(jq -n '{tool_name: "Edit", session_id: "sess-1", tool_error: "File is read-only"}')
    run_hook "$HOOK" "$input"
    assert_output --partial "read-only"
}

@test "provides read-only hint for Write" {
    local input
    input=$(jq -n '{tool_name: "Write", session_id: "sess-1", tool_error: "Read-only file system"}')
    run_hook "$HOOK" "$input"
    assert_output --partial "read-only"
}

@test "no hint for generic error" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "some random error"}')
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "Hint"
}

# ==============================================================================
# LOG ROTATION
# ==============================================================================

@test "rotates error log when >1500 lines" {
    # Create a large error log
    mkdir -p "$HOME/.claude"
    python3 -c "
for i in range(2000):
    print(f'line {i}: some error message')
" > "$HOME/.claude/errors.log"
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", tool_error: "trigger rotation"}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    # Should be ~1000 lines now
    local lines
    lines=$(wc -l < "$HOME/.claude/errors.log")
    (( lines < 1100 ))
}

# ==============================================================================
# ERROR MESSAGE SANITIZATION
# ==============================================================================

@test "truncates long error messages in events" {
    local long_error
    long_error=$(python3 -c "print('x' * 500)")
    local input
    input=$(jq -n --arg err "$long_error" '{tool_name: "Bash", session_id: "sess-1", tool_error: $err}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    # Event should have truncated to 200 chars
    local event_err_len
    event_err_len=$(jq -r '.error_message | length' "$SG_EVENTS_FILE")
    (( event_err_len <= 210 ))
}

# ==============================================================================
# FALLBACK ERROR FIELD
# ==============================================================================

@test "reads .error field when .tool_error missing" {
    local input
    input=$(jq -n '{tool_name: "Bash", session_id: "sess-1", error: "fallback error msg"}')
    printf '%s' "$input" | "$HOOK"  2>/dev/null
    run grep "fallback error msg" "$HOME/.claude/errors.log"
    assert_success
}

# ==============================================================================
# EMPTY INPUT
# ==============================================================================

@test "empty stdin exits cleanly" {
    run_hook "$HOOK" ""
    assert_success
}
