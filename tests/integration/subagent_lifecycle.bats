#!/usr/bin/env bats
# Integration tests for subagent-start and subagent-stop

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK_SUBAGENT_START="${SG_SUBAGENT_START_HOOK:-$PROJ_ROOT/hooks/subagent-start}"
    HOOK_SUBAGENT_STOP="${SG_SUBAGENT_STOP_HOOK:-$PROJ_ROOT/hooks/subagent-stop}"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# SUBAGENT START
# ==============================================================================

@test "subagent-start creates state files" {
    local input
    input=$(jq -n '{agent_id: "agent-abc", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    assert_exist "$SG_SUBAGENT_STATE_DIR/agent-abc"
    assert_exist "$SG_SUBAGENT_STATE_DIR/agent-abc.start"
    run grep "AGENT_TYPE=Explore" "$SG_SUBAGENT_STATE_DIR/agent-abc"
    assert_success
}

@test "subagent-start increments subagent count" {
    local input
    input=$(jq -n '{agent_id: "agent-s1", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/subagent-count"
    run cat "$SG_STATE_DIR/subagent-count"
    assert_output --partial "sess-1|1|"
}

@test "subagent-start increments count from existing" {
    printf 'sess-1|2|%s\n' "$(date +%s)" > "$SG_STATE_DIR/subagent-count"
    local input
    input=$(jq -n '{agent_id: "agent-s2", agent_type: "Plan", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    run cat "$SG_STATE_DIR/subagent-count"
    assert_output --partial "sess-1|3|"
}

@test "subagent-start emits subagent_start event" {
    local input
    input=$(jq -n '{agent_id: "agent-ev1", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    run grep "subagent_start" "$SG_EVENTS_FILE"
    assert_success
}

@test "subagent-start blocks when budget exhausted" {
    echo "SG_BUDGET_TOTAL=100" > "$HOME/.claude/.safeguard/config.env"
    mkdir -p "$HOME/.claude/.safeguard"
    echo "101" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(jq -n '{agent_id: "agent-budget", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "Budget exhausted"
    assert_output --partial '"continue": false'
}

@test "subagent-start provides Explore guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-g1", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "Glob"
}

@test "subagent-start provides Plan guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-g2", agent_type: "Plan", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "Read-only"
}

@test "subagent-start provides general-purpose guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-g3", agent_type: "general-purpose", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
}

@test "subagent-start warns at 75% budget" {
    echo "SG_BUDGET_TOTAL=100" > "$HOME/.claude/.safeguard/config.env"
    mkdir -p "$HOME/.claude/.safeguard"
    echo "80" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(jq -n '{agent_id: "agent-w1", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/budget-alert"
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "WARNING"
}

@test "subagent-start alerts critical at 90% budget" {
    echo "SG_BUDGET_TOTAL=100" > "$HOME/.claude/.safeguard/config.env"
    mkdir -p "$HOME/.claude/.safeguard"
    echo "95" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(jq -n '{agent_id: "agent-c1", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/budget-alert"
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "CRITICAL"
}

@test "subagent-start provides code-reviewer guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-cr", agent_type: "code-reviewer", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "Read-only"
}

@test "subagent-start provides deep-debugger guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-dd", agent_type: "deep-debugger", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "reproduce"
}

@test "subagent-start provides refactor guidance" {
    local input
    input=$(jq -n '{agent_id: "agent-rf", agent_type: "refactor", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_output --partial "additionalContext"
    assert_output --partial "agent-specific"
}

@test "subagent-start no guidance for unknown type" {
    local input
    input=$(jq -n '{agent_id: "agent-uk", agent_type: "custom-type", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    refute_output --partial "additionalContext"
}

@test "subagent-start does not override WARNING with WARNING" {
    echo "SG_BUDGET_TOTAL=100" > "$HOME/.claude/.safeguard/config.env"
    echo "80" > "$HOME/.claude/.safeguard/budget.state"
    echo "WARNING|80|$(date +%s)" > "$SG_STATE_DIR/budget-alert"
    local input
    input=$(jq -n '{agent_id: "agent-ww", agent_type: "Explore", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    # Should keep the existing WARNING, not create a new one
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "WARNING|80|"
}

@test "subagent-start resets count for different session" {
    printf 'old-session|5|%s\n' "$(date +%s)" > "$SG_STATE_DIR/subagent-count"
    local input
    input=$(jq -n '{agent_id: "agent-ns", agent_type: "Explore", session_id: "new-session"}')
    run_hook "$HOOK_SUBAGENT_START" "$input"
    assert_success
    run cat "$SG_STATE_DIR/subagent-count"
    assert_output --partial "new-session|1|"
}

@test "subagent-start empty stdin exits cleanly" {
    run_hook "$HOOK_SUBAGENT_START" ""
    assert_success
}

# ==============================================================================
# SUBAGENT STOP
# ==============================================================================

@test "subagent-stop updates budget with consumed bytes" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR" "$HOME/.claude/.safeguard"
    echo "0" > "$HOME/.claude/.safeguard/budget.state"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=sess-1\n' > "$SG_SUBAGENT_STATE_DIR/agent-stop1"
    echo "$(( $(date +%s) - 60 ))" > "$SG_SUBAGENT_STATE_DIR/agent-stop1.start"
    echo "35000|Bash|$(date +%s)" > "$SG_SUBAGENT_STATE_DIR/agent-stop1.bytes"
    local input
    input=$(jq -n '{agent_id: "agent-stop1", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
    # Budget should have increased: 35000 * 10 / 35 = 10000
    run cat "$HOME/.claude/.safeguard/budget.state"
    assert_output "10000"
}

@test "subagent-stop decrements subagent count" {
    printf 'sess-1|3|%s\n' "$(date +%s)" > "$SG_STATE_DIR/subagent-count"
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$SG_SUBAGENT_STATE_DIR/agent-stop2.start"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=sess-1\n' > "$SG_SUBAGENT_STATE_DIR/agent-stop2"
    local input
    input=$(jq -n '{agent_id: "agent-stop2", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
    run cat "$SG_STATE_DIR/subagent-count"
    assert_output --partial "sess-1|2|"
}

@test "subagent-stop emits subagent_stop event" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$SG_SUBAGENT_STATE_DIR/agent-stop3.start"
    printf 'AGENT_TYPE=Plan\nSESSION_ID=sess-1\n' > "$SG_SUBAGENT_STATE_DIR/agent-stop3"
    local input
    input=$(jq -n '{agent_id: "agent-stop3", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
    run grep "subagent_stop" "$SG_EVENTS_FILE"
    assert_success
}

@test "subagent-stop tracks worktree flag" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$SG_SUBAGENT_STATE_DIR/agent-stop4.start"
    printf 'AGENT_TYPE=general-purpose\nSESSION_ID=sess-1\n' > "$SG_SUBAGENT_STATE_DIR/agent-stop4"
    local input
    input=$(jq -n '{agent_id: "agent-stop4", session_id: "sess-1", worktree_path: "/tmp/worktree-abc"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
    run grep "has_worktree" "$SG_EVENTS_FILE"
    assert_success
}

@test "subagent-stop handles missing byte file" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    echo "$(date +%s)" > "$SG_SUBAGENT_STATE_DIR/agent-stop5.start"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=sess-1\n' > "$SG_SUBAGENT_STATE_DIR/agent-stop5"
    local input
    input=$(jq -n '{agent_id: "agent-stop5", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
}

@test "subagent-stop handles missing start file" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    local input
    input=$(jq -n '{agent_id: "agent-stop6", session_id: "sess-1"}')
    run_hook "$HOOK_SUBAGENT_STOP" "$input"
    assert_success
}

@test "subagent-stop empty stdin exits cleanly" {
    run_hook "$HOOK_SUBAGENT_STOP" ""
    assert_success
}
