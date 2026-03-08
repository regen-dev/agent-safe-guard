#!/usr/bin/env bats
# Integration tests for session-start, session-end, stop, pre-compact

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK_SESSION_START="${SG_SESSION_START_HOOK:-$PROJ_ROOT/hooks/session-start}"
    HOOK_SESSION_END="${SG_SESSION_END_HOOK:-$PROJ_ROOT/hooks/session-end}"
    HOOK_STOP="${SG_STOP_HOOK:-$PROJ_ROOT/hooks/stop}"
    HOOK_PRE_COMPACT="${SG_PRE_COMPACT_HOOK:-$PROJ_ROOT/hooks/pre-compact}"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# SESSION START
# ==============================================================================

@test "session-start creates session time files" {
    local input
    input=$(jq -n '{session_id: "sess-abc123", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_SESSION_START" "$input"
    assert_success
    assert_exist "$HOME/.claude/.session-times/sess-abc123.start"
    assert_exist "$HOME/.claude/.session-times/sess-abc123.start_ns"
}

@test "session-start creates session start marker" {
    local input
    input=$(jq -n '{session_id: "sess-abc123", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_SESSION_START" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/.session_start"
}

@test "session-start exports budget snapshot" {
    local input
    input=$(jq -n '{session_id: "sess-abc123", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_SESSION_START" "$input"
    assert_success
    assert_exist "$SG_SESSION_BUDGET_DIR/sess-abc123.start.json"
}

@test "session-start emits session_start event" {
    local input
    input=$(jq -n '{session_id: "sess-abc123", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_SESSION_START" "$input"
    assert_success
    assert_exist "$SG_EVENTS_FILE"
    run grep "session_start" "$SG_EVENTS_FILE"
    assert_success
}

@test "session-start handles empty session_id" {
    local input
    input=$(jq -n '{transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_SESSION_START" "$input"
    assert_success
}

@test "session-start empty stdin exits cleanly" {
    run_hook "$HOOK_SESSION_START" ""
    assert_success
}

# ==============================================================================
# SESSION END
# ==============================================================================

@test "session-end logs to session-log.txt" {
    # First create session start
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end1.start"
    local input
    input=$(jq -n '{session_id: "sess-end1", reason: "user_exit"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    assert_exist "$HOME/.claude/session-log.txt"
    run grep "sess-end1" "$HOME/.claude/session-log.txt"
    assert_success
}

@test "session-end emits session_end event" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end2.start"
    local input
    input=$(jq -n '{session_id: "sess-end2", reason: "done"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    run grep "session_end" "$SG_EVENTS_FILE"
    assert_success
}

@test "session-end cleans up budget start file" {
    mkdir -p "$HOME/.claude/.session-times" "$SG_SESSION_BUDGET_DIR"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end3.start"
    echo '{}' > "$SG_SESSION_BUDGET_DIR/sess-end3.start.json"
    local input
    input=$(jq -n '{session_id: "sess-end3", reason: "done"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    assert_not_exist "$SG_SESSION_BUDGET_DIR/sess-end3.start.json"
}

@test "session-end reaps ghost subagent state" {
    mkdir -p "$HOME/.claude/.session-times" "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end4.start"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=sess-end4\n' > "$SG_SUBAGENT_STATE_DIR/ghost-agent"
    echo "12345" > "$SG_SUBAGENT_STATE_DIR/ghost-agent.start"
    local input
    input=$(jq -n '{session_id: "sess-end4", reason: "done"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    assert_not_exist "$SG_SUBAGENT_STATE_DIR/ghost-agent"
    assert_not_exist "$SG_SUBAGENT_STATE_DIR/ghost-agent.start"
}

@test "session-end writes reset-reason file" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end5.start"
    local input
    input=$(jq -n '{session_id: "sess-end5", reason: "context_limit"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/reset-reason"
    run grep "context_limit" "$SG_STATE_DIR/reset-reason"
    assert_success
}

@test "session-end handles unknown session (no start file)" {
    local input
    input=$(jq -n '{session_id: "no-such-session", reason: "done"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
}

@test "session-end empty stdin exits cleanly" {
    run_hook "$HOOK_SESSION_END" ""
    assert_success
}

# ==============================================================================
# STOP
# ==============================================================================

@test "stop logs to session-log.txt" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-stop1.start"
    local input
    input=$(jq -n '{reason: "user_interrupt", tool_name: "Bash", session_id: "sess-stop1"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    assert_exist "$HOME/.claude/session-log.txt"
    run grep "user_interrupt" "$HOME/.claude/session-log.txt"
    assert_success
}

@test "stop emits session_stop event" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-stop2.start"
    local input
    input=$(jq -n '{reason: "done", session_id: "sess-stop2"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    run grep "session_stop" "$SG_EVENTS_FILE"
    assert_success
}

@test "stop returns block count summary" {
    local input
    input=$(jq -n '{reason: "done", session_id: "sess-stop3"}')
    run_hook "$HOOK_STOP" "$input"
    assert_output --partial "stop_hook_summary"
}

@test "stop skips when stop_hook_active=true" {
    local input
    input=$(jq -n '{stop_hook_active: true, reason: "done", session_id: "test"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    refute_output --partial "stop_hook_summary"
}

@test "stop empty stdin exits cleanly" {
    run_hook "$HOOK_STOP" ""
    assert_success
}

# ==============================================================================
# PRE-COMPACT
# ==============================================================================

@test "pre-compact returns session state summary" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-compact1.start"
    echo "25|5000|Bash:ls|$(date +%s)" > "$SG_STATE_DIR/session-sess-compact1"
    local input
    input=$(jq -n '{session_id: "sess-compact1", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "SafeGuard Session State"
    assert_output --partial "Tool calls: 25"
}

@test "pre-compact includes budget status" {
    mkdir -p "$HOME/.claude/.session-times" "$HOME/.claude/.safeguard"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-compact2.start"
    echo "140000" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(jq -n '{session_id: "sess-compact2", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_output --partial "Budget"
    assert_output --partial "50%"
}

@test "pre-compact emits compaction event" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-compact3.start"
    local input
    input=$(jq -n '{session_id: "sess-compact3", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_success
    run grep "compaction" "$SG_EVENTS_FILE"
    assert_success
}

@test "pre-compact exits when no session_id" {
    local input
    input=$(jq -n '{transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_success
    refute_output --partial "additionalContext"
}

@test "pre-compact empty stdin exits cleanly" {
    run_hook "$HOOK_PRE_COMPACT" ""
    assert_success
}

# ==============================================================================
# STOP - ADDITIONAL COVERAGE
# ==============================================================================

@test "stop with tool_name logs tool info" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-stop4.start"
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    local input
    input=$(jq -n '{reason: "timeout", tool_name: "Bash", session_id: "sess-stop4"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    run grep "tool: Bash" "$HOME/.claude/session-log.txt"
    assert_success
}

@test "stop counts blocked events in summary" {
    # Write some blocked events to the events file
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-stop5.start"
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    printf '{"event_type":"blocked","tool":"Bash"}\n' >> "$SG_EVENTS_FILE"
    printf '{"event_type":"blocked","tool":"Bash"}\n' >> "$SG_EVENTS_FILE"
    printf '{"event_type":"blocked","tool":"Bash"}\n' >> "$SG_EVENTS_FILE"
    local input
    input=$(jq -n '{reason: "done", session_id: "sess-stop5"}')
    run_hook "$HOOK_STOP" "$input"
    assert_output --partial "blocks: 3"
}

@test "stop calculates duration from session time file" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(( $(date +%s) - 300 ))" > "$HOME/.claude/.session-times/sess-stop6.start"
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    local input
    input=$(jq -n '{reason: "done", tool_name: "Read", session_id: "sess-stop6"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    run grep "300s" "$HOME/.claude/session-log.txt"
    assert_success
}

# ==============================================================================
# SESSION END - ADDITIONAL COVERAGE
# ==============================================================================

@test "session-end purges stale subagent state files" {
    mkdir -p "$HOME/.claude/.session-times" "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-end6.start"
    # Stale subagent from a different session
    printf 'AGENT_TYPE=Explore\nSESSION_ID=old-session\n' > "$SG_SUBAGENT_STATE_DIR/stale-agent"
    echo "12345" > "$SG_SUBAGENT_STATE_DIR/stale-agent.start"
    echo "5000|Bash|12345" > "$SG_SUBAGENT_STATE_DIR/stale-agent.bytes"
    echo "5|0|12345" > "$SG_SUBAGENT_STATE_DIR/stale-agent.calls"
    local input
    input=$(jq -n '{session_id: "sess-end6", reason: "done"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
}

@test "session-end calculates session duration" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(( $(date +%s) - 120 ))" > "$HOME/.claude/.session-times/sess-end7.start"
    local input
    input=$(jq -n '{session_id: "sess-end7", reason: "user_exit"}')
    run_hook "$HOOK_SESSION_END" "$input"
    assert_success
    assert_exist "$HOME/.claude/session-log.txt"
    run grep "sess-end7" "$HOME/.claude/session-log.txt"
    assert_success
}

# ==============================================================================
# PRE-COMPACT - ADDITIONAL COVERAGE
# ==============================================================================

@test "pre-compact includes subagent count" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-compact4.start"
    printf 'sess-compact4|2|%s\n' "$(date +%s)" > "$SG_STATE_DIR/subagent-count"
    local input
    input=$(jq -n '{session_id: "sess-compact4", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "subagent"
}

@test "stop with empty tool_name logs without tool info" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(date +%s)" > "$HOME/.claude/.session-times/sess-stop8.start"
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    local input
    input=$(jq -n '{reason: "done", session_id: "sess-stop8"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    # tool_name is empty → log line should NOT contain "tool:"
    run grep "Stop: done" "$HOME/.claude/session-log.txt"
    assert_success
    refute_output --partial "tool:"
}

@test "stop without session start file uses unknown duration" {
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    local input
    input=$(jq -n '{reason: "done", session_id: "sess-stop7"}')
    run_hook "$HOOK_STOP" "$input"
    assert_success
    assert_output --partial "stop_hook_summary"
    run grep "unknown" "$HOME/.claude/session-log.txt"
    assert_success
}

@test "pre-compact includes duration when session time exists" {
    mkdir -p "$HOME/.claude/.session-times"
    echo "$(( $(date +%s) - 180 ))" > "$HOME/.claude/.session-times/sess-compact5.start"
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.session_start"
    local input
    input=$(jq -n '{session_id: "sess-compact5", transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK_PRE_COMPACT" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "Duration: 3m"
}
