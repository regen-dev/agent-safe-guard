#!/usr/bin/env bats
# Unit tests for hooks/lib/common.sh

setup() {
    load '../test_helper/common'
    setup_isolated_env

    # Source common.sh in isolated env
    source "$PROJ_ROOT/hooks/lib/common.sh"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# _sg_date_ns / _sg_date_sns / _sg_date_iso
# ==============================================================================

@test "_sg_date_ns returns numeric nanoseconds" {
    result=$(_sg_date_ns)
    [[ "$result" =~ ^[0-9]+$ ]]
    # Should be at least epoch seconds * 1e9
    (( result > 1000000000000000000 ))
}

@test "_sg_date_sns returns seconds.nanoseconds" {
    result=$(_sg_date_sns)
    [[ "$result" =~ ^[0-9]+\.[0-9]+$ ]]
}

@test "_sg_date_iso returns ISO date string" {
    result=$(_sg_date_iso)
    [[ "$result" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]
}

# ==============================================================================
# CONFIG LOADING
# ==============================================================================

@test "config.env values are loaded" {
    assert_equal "$SG_TRUNCATE_BYTES" "20480"
    assert_equal "$SG_SUPPRESS_BYTES" "524288"
    assert_equal "$SG_READ_GUARD_MAX_MB" "2"
    assert_equal "$SG_BUDGET_TOTAL" "280000"
}

@test "default values used when config.env missing" {
    rm -f "$HOME/.claude/.safeguard/config.env"
    unset SG_TRUNCATE_BYTES SG_SUPPRESS_BYTES SG_READ_GUARD_MAX_MB SG_BUDGET_TOTAL
    source "$PROJ_ROOT/hooks/lib/common.sh"
    assert_equal "$SG_TRUNCATE_BYTES" "20480"
    assert_equal "$SG_BUDGET_TOTAL" "280000"
}

@test "invalid config.env syntax shows warning" {
    # Must be truly invalid bash syntax (parse error, not just unknown command)
    printf 'if ;; then\n' > "$HOME/.claude/.safeguard/config.env"
    unset SG_TRUNCATE_BYTES
    local tmpscript="$TEST_TEMP/test_config.sh"
    cat > "$tmpscript" << 'SCRIPT'
#!/usr/bin/env bash
export HOME="$1"
export SG_STATE_DIR="$HOME/.claude/.statusline"
export SG_SESSION_BUDGET_DIR="$HOME/.claude/.session-budgets"
export SG_SUBAGENT_STATE_DIR="$HOME/.claude/.subagent-state"
source "$2" 2>&1
SCRIPT
    chmod +x "$tmpscript"
    run bash "$tmpscript" "$HOME" "$PROJ_ROOT/hooks/lib/common.sh"
    assert_output --partial "warning: invalid config syntax"
}

@test "custom config values override defaults" {
    echo 'SG_TRUNCATE_BYTES=99999' > "$HOME/.claude/.safeguard/config.env"
    unset SG_TRUNCATE_BYTES
    source "$PROJ_ROOT/hooks/lib/common.sh"
    assert_equal "$SG_TRUNCATE_BYTES" "99999"
}

# ==============================================================================
# _sg_with_lock
# ==============================================================================

@test "_sg_with_lock executes callback" {
    local lockdir="$TEST_TEMP/test.lock.d"
    _callback() { echo "executed"; }
    run _sg_with_lock "$lockdir" _callback
    assert_success
    assert_output "executed"
    # Lock dir should be cleaned up
    assert_not_exist "$lockdir"
}

@test "_sg_with_lock removes stale lock after timeout" {
    local lockdir="$TEST_TEMP/stale.lock.d"
    mkdir -p "$lockdir"
    _callback() { echo "ran"; }
    # Mock sleep to be instant (avoids 5s wait for 51 iterations)
    sleep() { :; }
    run _sg_with_lock "$lockdir" _callback
    assert_success
    assert_output "ran"
}

# ==============================================================================
# BUDGET TRACKER
# ==============================================================================

@test "_sg_budget_read returns 0 when no state" {
    run _sg_budget_read
    assert_success
    assert_output "0"
}

@test "_sg_budget_write and _sg_budget_read round-trip" {
    _sg_budget_write 12345
    run _sg_budget_read
    assert_output "12345"
}

@test "_sg_budget_update adds tokens" {
    _sg_budget_write 100
    _sg_budget_update 50
    run _sg_budget_read
    assert_output "150"
}

@test "_sg_budget_update ignores zero" {
    _sg_budget_write 100
    _sg_budget_update 0
    run _sg_budget_read
    assert_output "100"
}

@test "_sg_budget_update ignores non-numeric" {
    _sg_budget_write 100
    _sg_budget_update "abc"
    run _sg_budget_read
    assert_output "100"
}

@test "_sg_budget_check passes under limit" {
    export SG_BUDGET_TOTAL=280000
    _sg_budget_write 100000
    run _sg_budget_check
    assert_success
}

@test "_sg_budget_check fails over limit" {
    export SG_BUDGET_TOTAL=280000
    _sg_budget_write 280001
    run _sg_budget_check
    assert_failure
}

@test "_sg_budget_export returns valid JSON" {
    export SG_BUDGET_TOTAL=280000
    _sg_budget_write 140000
    result=$(_sg_budget_export)
    consumed=$(echo "$result" | jq -r '.consumed')
    util=$(echo "$result" | jq -r '.utilization')
    assert_equal "$consumed" "140000"
    assert_equal "$util" "50"
}

@test "_sg_budget_export writes cache file" {
    export SG_BUDGET_TOTAL=280000
    _sg_budget_write 0
    _sg_budget_export > /dev/null
    assert_exist "$SG_STATE_DIR/budget-export"
}

@test "_sg_budget_reset zeros the counter" {
    _sg_budget_write 99999
    _sg_budget_reset
    run _sg_budget_read
    assert_output "0"
}

# ==============================================================================
# SUBAGENT LIMIT LOOKUPS
# ==============================================================================

@test "_sg_call_limit returns default when no type-specific" {
    export SG_DEFAULT_CALL_LIMIT=30
    run _sg_call_limit "Explore"
    assert_output "30"
}

@test "_sg_call_limit returns type-specific override" {
    export SG_DEFAULT_CALL_LIMIT=30
    export SG_CALL_LIMIT_Explore=50
    run _sg_call_limit "Explore"
    assert_output "50"
}

@test "_sg_byte_limit returns default" {
    export SG_DEFAULT_BYTE_LIMIT=102400
    run _sg_byte_limit "Plan"
    assert_output "102400"
}

@test "_sg_byte_limit returns type-specific override" {
    export SG_DEFAULT_BYTE_LIMIT=102400
    export SG_BYTE_LIMIT_Plan=204800
    run _sg_byte_limit "Plan"
    assert_output "204800"
}

@test "_sg_call_limit normalizes hyphen to underscore" {
    export SG_DEFAULT_CALL_LIMIT=30
    export SG_CALL_LIMIT_deep_debugger=40
    run _sg_call_limit "deep-debugger"
    assert_output "40"
}

# ==============================================================================
# INPUT PARSING
# ==============================================================================

@test "_sg_read_input reads stdin" {
    echo '{"tool_name":"Bash"}' | {
        _sg_read_input
        assert_equal "$SG_INPUT" '{"tool_name":"Bash"}'
    }
}

@test "_sg_read_input returns 1 on empty stdin" {
    run bash -c "source '$PROJ_ROOT/hooks/lib/common.sh'; echo '' | _sg_read_input; echo \$?"
    assert_output --partial "1"
}

@test "_sg_parse_toplevel extracts field" {
    SG_INPUT='{"tool_name":"Bash","session_id":"abc123"}'
    run _sg_parse_toplevel "tool_name"
    assert_output "Bash"
}

@test "_sg_parse_toplevel returns empty for missing field" {
    SG_INPUT='{"tool_name":"Bash"}'
    run _sg_parse_toplevel "missing_field"
    assert_output ""
}

@test "_sg_parse_tool_name extracts tool name" {
    SG_INPUT='{"tool_name":"Read","session_id":"x"}'
    run _sg_parse_tool_name
    assert_output "Read"
}

@test "_sg_parse_session_id extracts session id" {
    SG_INPUT='{"tool_name":"Bash","session_id":"sess-abc"}'
    run _sg_parse_session_id
    assert_output "sess-abc"
}

@test "_sg_parse_transcript_path extracts path" {
    SG_INPUT='{"tool_name":"Bash","transcript_path":"/home/user/.claude/test.jsonl"}'
    run _sg_parse_transcript_path
    assert_output "/home/user/.claude/test.jsonl"
}

@test "_sg_parse_tool_input extracts fields via jq" {
    SG_INPUT='{"tool_input":{"command":"ls -la","file_path":"/tmp/foo"}}'
    run _sg_parse_tool_input command file_path
    assert_output "ls -la	/tmp/foo"
}

# ==============================================================================
# ID SANITIZATION
# ==============================================================================

@test "_sg_sanitize_id allows valid IDs" {
    run _sg_sanitize_id "abc-123_XYZ"
    assert_output "abc-123_XYZ"
}

@test "_sg_sanitize_id rejects invalid characters" {
    run _sg_sanitize_id 'abc;rm -rf /'
    assert_output ""
}

@test "_sg_sanitize_id rejects empty string" {
    run _sg_sanitize_id ""
    assert_output ""
}

@test "_sg_sanitize_id rejects path traversal" {
    run _sg_sanitize_id "../../../etc/passwd"
    assert_output ""
}

# ==============================================================================
# SUBAGENT DETECTION
# ==============================================================================

@test "_sg_is_subagent detects subagent path" {
    run _sg_is_subagent "/home/user/.claude/projects/test/subagents/agent-abc.jsonl"
    assert_success
}

@test "_sg_is_subagent detects tmp path" {
    run _sg_is_subagent "/tmp/agent-test.jsonl"
    assert_success
}

@test "_sg_is_subagent rejects main agent path" {
    run _sg_is_subagent "/home/user/.claude/projects/test/main.jsonl"
    assert_failure
}

@test "_sg_get_agent_id extracts from subagent path" {
    run _sg_get_agent_id "/home/user/.claude/projects/test/subagents/agent-abc123.jsonl"
    assert_output "abc123"
}

@test "_sg_get_agent_id returns empty for non-subagent" {
    run _sg_get_agent_id "/home/user/.claude/projects/test/main.jsonl"
    assert_output ""
}

@test "_sg_get_agent_type reads from state file" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=s1\n' > "$SG_SUBAGENT_STATE_DIR/abc123"
    run _sg_get_agent_type "abc123"
    assert_output "Explore"
}

@test "_sg_get_agent_type returns empty when no state" {
    run _sg_get_agent_type "nonexistent"
    assert_output ""
}

# ==============================================================================
# SECRET SCRUBBING
# ==============================================================================

@test "_sg_scrub_secrets redacts Bearer tokens" {
    result=$(echo 'Authorization: Bearer sk-abc123secret' | _sg_scrub_secrets)
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_scrub_secrets redacts API keys" {
    result=$(echo 'api_key=supersecret123456789012' | _sg_scrub_secrets)
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_scrub_secrets redacts github tokens" {
    result=$(echo 'token ghp_abc123secrettoken' | _sg_scrub_secrets)
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_scrub_secrets redacts sk- tokens" {
    result=$(echo 'key sk-proj-abc123secret' | _sg_scrub_secrets)
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_maybe_scrub leaves clean text unchanged" {
    local myvar="just a normal command ls -la"
    _sg_maybe_scrub myvar
    assert_equal "$myvar" "just a normal command ls -la"
}

@test "_sg_maybe_scrub scrubs variable containing secrets" {
    local myvar="curl -H Authorization: Bearer sk-abc123"
    _sg_maybe_scrub myvar
    [[ "$myvar" == *"[REDACTED]"* ]]
}

# ==============================================================================
# EVENT EMISSION
# ==============================================================================

@test "_sg_emit_block writes to events file" {
    export SG_TOOL_NAME="Bash"
    export SG_COMMAND="rm -rf /"
    export SG_SESSION_ID="test-sess"
    _sg_emit_block "destructive_cmd" 0
    assert_exist "$SG_EVENTS_FILE"
    run jq -r '.event_type' "$SG_EVENTS_FILE"
    assert_output "blocked"
}

@test "_sg_emit_event writes with correct fields" {
    export SG_TOOL_NAME="Bash"
    export SG_COMMAND="ls"
    export SG_SESSION_ID="test-sess"
    _sg_emit_event "truncated" 50000 10000 "output_truncated"
    assert_exist "$SG_EVENTS_FILE"
    run jq -r '.rule' "$SG_EVENTS_FILE"
    assert_output "output_truncated"
}

@test "_sg_emit_output_size writes tool_output_size event" {
    export SG_SESSION_ID="test-sess"
    _sg_emit_output_size "Bash" 4096 50 "ls -la"
    assert_exist "$SG_EVENTS_FILE"
    run jq -r '.event_type' "$SG_EVENTS_FILE"
    assert_output "tool_output_size"
    run jq -r '.output_bytes' "$SG_EVENTS_FILE"
    assert_output "4096"
}

@test "_sg_emit_block scrubs secrets from command" {
    export SG_TOOL_NAME="Bash"
    export SG_COMMAND="curl -H 'Authorization: Bearer sk-secret123' https://api.example.com"
    export SG_SESSION_ID="test-sess"
    _sg_emit_block "test_rule" 0
    run grep -o 'sk-secret123' "$SG_EVENTS_FILE"
    refute_output --partial "sk-secret123"
}

# ==============================================================================
# SYSTEM REMINDER STRIPPING
# ==============================================================================

@test "_sg_strip_reminders removes system-reminder blocks" {
    local text="line1
<system-reminder>
secret stuff here
</system-reminder>
line2"
    result=$(_sg_strip_reminders text)
    [[ "$result" == *"line1"* ]]
    [[ "$result" == *"line2"* ]]
    [[ "$result" != *"secret stuff"* ]]
}

@test "_sg_strip_reminders preserves content without reminders" {
    local text="just normal content
line two"
    result=$(_sg_strip_reminders text)
    [[ "$result" == *"just normal content"* ]]
    [[ "$result" == *"line two"* ]]
}

# ==============================================================================
# FILE UTILITIES
# ==============================================================================

@test "_sg_stat_mtime returns numeric timestamp" {
    local tmpf="$TEST_TEMP/testfile"
    touch "$tmpf"
    run _sg_stat_mtime "$tmpf"
    assert_success
    [[ "$output" =~ ^[0-9]+$ ]]
}

@test "_sg_stat_mtime returns 0 for nonexistent file" {
    run _sg_stat_mtime "/nonexistent/file"
    assert_output "0"
}

# ==============================================================================
# NOTIFICATIONS
# ==============================================================================

@test "_sg_notify runs without error when no notifier available" {
    # Remove notify-send and osascript from PATH
    export PATH="$MOCK_DIR"
    run _sg_notify "normal" "Test Title" "Test Body"
    # Should not fail even if no notifier
    assert_success
}

# ==============================================================================
# HOOK OUTPUT HELPERS
# ==============================================================================

@test "_sg_suppress_ok outputs suppressOutput JSON" {
    run bash -c "source '$PROJ_ROOT/hooks/lib/common.sh'; _sg_suppress_ok"
    assert_output '{"suppressOutput":true}'
}

@test "_sg_deny outputs deny JSON with reason" {
    run bash -c "source '$PROJ_ROOT/hooks/lib/common.sh'; _sg_deny 'test reason'"
    assert_output --partial '"permissionDecision":"deny"'
    assert_output --partial '"permissionDecisionReason":"test reason"'
}

# ==============================================================================
# INLINE VALIDATIONS
# ==============================================================================

@test "_sg_check_secrets detects AWS key pattern" {
    run _sg_check_secrets "found AKIAIOSFODNN7EXAMPLE in output"
    assert_success
}

@test "_sg_check_secrets detects JWT pattern" {
    run _sg_check_secrets "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    assert_success
}

@test "_sg_check_secrets detects private key" {
    run _sg_check_secrets "-----BEGIN RSA PRIVATE KEY-----"
    assert_success
}

@test "_sg_check_secrets returns 1 for clean text" {
    run _sg_check_secrets "just normal output with no secrets"
    assert_failure
}

@test "_sg_validate_readonly allows read commands" {
    run _sg_validate_readonly "cat /etc/hostname"
    assert_success
}

@test "_sg_validate_readonly blocks rm" {
    run _sg_validate_readonly "rm file.txt"
    assert_failure
}

@test "_sg_validate_readonly blocks mv" {
    run _sg_validate_readonly "mv a.txt b.txt"
    assert_failure
}

@test "_sg_validate_readonly blocks redirect" {
    run _sg_validate_readonly "echo foo > /tmp/bar"
    assert_failure
}

@test "_sg_validate_readonly blocks sed -i" {
    run _sg_validate_readonly "sed -i 's/old/new/' file.txt"
    assert_failure
}

@test "_sg_validate_git allows git log" {
    run _sg_validate_git "git log --oneline -10"
    assert_success
}

@test "_sg_validate_git allows git config --get" {
    run _sg_validate_git "git config --get user.name"
    assert_success
}

@test "_sg_validate_git blocks force push to main" {
    run _sg_validate_git "git push --force origin main"
    assert_failure
}

@test "_sg_validate_git blocks git reset --hard main" {
    run _sg_validate_git "git reset --hard origin/main"
    assert_failure
}

@test "_sg_validate_git blocks git config user.email write" {
    run _sg_validate_git "git config user.email 'attacker@evil.com'"
    assert_failure
}

# ==============================================================================
# TOOL LATENCY TRACKING
# ==============================================================================

@test "_sg_record_tool_start creates marker file" {
    _sg_record_tool_start "Bash"
    local found=false
    for f in "$SG_STATE_DIR"/.tool-start-Bash-*; do
        [[ -f "$f" ]] && found=true
    done
    assert_equal "$found" "true"
}

@test "_sg_record_tool_start does nothing for empty name" {
    _sg_record_tool_start ""
    run ls "$SG_STATE_DIR"/.tool-start-*
    assert_failure
}

@test "_sg_compute_tool_latency calculates delta" {
    _sg_record_tool_start "TestTool"
    sleep 0.1
    _sg_compute_tool_latency "TestTool"
    [[ "$SG_TOOL_LATENCY_MS" =~ ^[0-9]+$ ]]
    (( SG_TOOL_LATENCY_MS >= 50 ))
}

@test "_sg_compute_tool_latency returns 1 when no start marker" {
    run _sg_compute_tool_latency "NoSuchTool"
    assert_failure
}

@test "_sg_emit_latency writes event" {
    export SG_SESSION_ID="test-sess"
    _sg_emit_latency "Bash" 250 "ls -la"
    assert_exist "$SG_EVENTS_FILE"
    run jq -r '.event_type' "$SG_EVENTS_FILE"
    assert_output "tool_latency"
    run jq -r '.duration_ms' "$SG_EVENTS_FILE"
    assert_output "250"
}

# ==============================================================================
# SESSION START WITH DECIMAL TIMESTAMP
# ==============================================================================

@test "session start with decimal format is parsed" {
    # _SG_SESSION_START_NS containing a dot triggers cut -d. -f1
    echo "1709330000.123456789" > "$SG_STATE_DIR/.session_start"
    source "$PROJ_ROOT/hooks/lib/common.sh"
    assert_equal "$_SG_SESSION_START_S" "1709330000"
}

# ==============================================================================
# LATENCY OUT-OF-RANGE
# ==============================================================================

@test "_sg_compute_tool_latency rejects negative delta" {
    mkdir -p "$SG_STATE_DIR"
    # Create a tool start file with a future timestamp
    echo "99999999999999999999" > "$SG_STATE_DIR/.tool-start-FutureTool-$$"
    run _sg_compute_tool_latency "FutureTool"
    assert_failure
}

# ==============================================================================
# NOTIFICATION MOCK
# ==============================================================================

@test "_sg_notify calls notify-send when available" {
    # Create a mock notify-send that just succeeds
    MOCK_DIR="$TEST_TEMP/mocks"
    mkdir -p "$MOCK_DIR"
    cat > "$MOCK_DIR/notify-send" << 'MOCK'
#!/bin/bash
echo "NOTIFY: $@" >> "$HOME/.claude/notify.log"
MOCK
    chmod +x "$MOCK_DIR/notify-send"
    export PATH="$MOCK_DIR:$PATH"
    source "$PROJ_ROOT/hooks/lib/common.sh"
    _sg_notify "normal" "Test Title" "Test Body"
    assert_exist "$HOME/.claude/notify.log"
    run grep "NOTIFY:" "$HOME/.claude/notify.log"
    assert_success
}

# ==============================================================================
# SCRUB SECRETS
# ==============================================================================

@test "_sg_scrub_secrets redacts bearer tokens" {
    result=$(echo "Authorization: Bearer sk-12345abcdef" | _sg_scrub_secrets)
    [[ "$result" != *"sk-12345abcdef"* ]]
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_scrub_secrets redacts GitHub PATs" {
    result=$(echo "token ghp_abcdef1234567890" | _sg_scrub_secrets)
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "_sg_maybe_scrub handles secret in variable" {
    local cmd="curl -H 'Authorization: Bearer sk-12345' http://example.com"
    _sg_maybe_scrub cmd
    [[ "$cmd" == *"[REDACTED]"* ]]
}

@test "_sg_maybe_scrub leaves safe commands alone" {
    local cmd="ls -la /tmp"
    _sg_maybe_scrub cmd
    assert_equal "$cmd" "ls -la /tmp"
}
