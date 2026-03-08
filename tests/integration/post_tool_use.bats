#!/usr/bin/env bats
# Integration tests for hooks/post-tool-use

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK="${SG_POST_TOOL_HOOK:-$PROJ_ROOT/hooks/post-tool-use}"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# SMALL OUTPUT PASSTHROUGH
# ==============================================================================

@test "small Bash output passes with suppress" {
    run_hook "$HOOK" "$(make_post_input 'Bash' 'hello world' 'echo hello')"
    assert_output --partial "suppressOutput"
}

@test "non-Bash/Grep/Glob/Task tool passes with suppress" {
    run_hook "$HOOK" "$(make_post_input 'WebSearch' 'some results')"
    assert_output --partial "suppressOutput"
}

@test "Read tool (main agent) passes with suppress" {
    run_hook "$HOOK" "$(make_post_input 'Read' 'file content here' '/tmp/test.txt')"
    assert_output --partial "suppressOutput"
}

# ==============================================================================
# OUTPUT TRUNCATION
# ==============================================================================

@test "large Bash output gets truncated" {
    local big_output
    big_output=$(python3 -c "print('x' * 30000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Bash",
        tool_input: {command: "some-cmd"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "truncated"
}

@test "output exceeding suppress threshold gets suppressed entirely" {
    # Lower suppress threshold to avoid env ARG_MAX limits with export SG_INPUT
    cat > "$HOME/.claude/.safeguard/config.env" << 'EOF'
SG_TRUNCATE_BYTES=20480
SG_SUPPRESS_BYTES=30000
EOF
    local big_text
    big_text=$(python3 -c "print('x'*35000)")
    local input
    input=$(jq -n --arg text "$big_text" '{
        tool_name: "Bash",
        tool_input: {command: "some-cmd"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "too large"
}

# ==============================================================================
# SYSTEM REMINDER STRIPPING
# ==============================================================================

@test "strips system-reminder from non-Bash tool via modifyOutput" {
    local text
    text=$(printf 'result\n<system-reminder>\nsecret internal stuff\n</system-reminder>\nend')
    local input
    input=$(jq -n --arg text "$text" '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/test.txt"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}

# ==============================================================================
# SESSION STATE TRACKING
# ==============================================================================

@test "increments tool count in session state" {
    local input
    input=$(make_post_input "Bash" "hello" "echo hello")
    printf '%s' "$input" | "$HOOK" > /dev/null 2>&1 || true
    assert_exist "$SG_STATE_DIR/session-test-session-001"
    run cat "$SG_STATE_DIR/session-test-session-001"
    assert_output --partial "1|"
}

@test "tracks largest output in session" {
    local input1
    input1=$(make_post_input "Bash" "small" "echo small")
    printf '%s' "$input1" | "$HOOK" > /dev/null 2>&1 || true
    local big
    big=$(python3 -c "print('x' * 5000)")
    local input2
    input2=$(jq -n --arg text "$big" '{
        tool_name: "Bash",
        tool_input: {command: "big-cmd"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    printf '%s' "$input2" | "$HOOK" > /dev/null 2>&1 || true
    run cat "$SG_STATE_DIR/session-test-session-001"
    assert_output --partial "Bash:big-cmd"
}

# ==============================================================================
# SUBAGENT BYTE TRACKING
# ==============================================================================

@test "tracks cumulative bytes for subagent" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=test\n' > "$SG_SUBAGENT_STATE_DIR/sub1"
    local input
    input=$(jq -n '{
        tool_name: "Bash",
        tool_input: {command: "echo test"},
        tool_response: {content: [{text: "output text here"}]},
        session_id: "test-session-001",
        transcript_path: "/home/user/.claude/projects/test/subagents/agent-sub1.jsonl"
    }')
    printf '%s' "$input" | "$HOOK" > /dev/null 2>&1 || true
    assert_exist "$SG_SUBAGENT_STATE_DIR/sub1.bytes"
}

# ==============================================================================
# SPECIAL COMMAND HEAD-ONLY TRUNCATION
# ==============================================================================

@test "nm output gets head-only truncation" {
    local big_output
    big_output=$(python3 -c "print('symbol_line\\n' * 5000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Bash",
        tool_input: {command: "nm /usr/bin/test"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}

@test "strings output gets head-only truncation" {
    local big_output
    big_output=$(python3 -c "print('string_line\\n' * 5000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Bash",
        tool_input: {command: "strings /usr/bin/test"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}

# ==============================================================================
# SUBAGENT CUMULATIVE BYTES (with existing byte file)
# ==============================================================================

@test "subagent byte tracking accumulates from existing" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=test\n' > "$SG_SUBAGENT_STATE_DIR/sub2"
    echo "1000|Bash|12345" > "$SG_SUBAGENT_STATE_DIR/sub2.bytes"
    local input
    input=$(jq -n '{
        tool_name: "Bash",
        tool_input: {command: "echo test"},
        tool_response: {content: [{text: "some output text"}]},
        session_id: "test-session-001",
        transcript_path: "/home/user/.claude/projects/test/subagents/agent-sub2.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_success
    run cat "$SG_SUBAGENT_STATE_DIR/sub2.bytes"
    # 1000 + length("some output text")=16 = 1016
    assert_output --partial "1016|"
}

@test "subagent Read uses lower truncation threshold" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=test\n' > "$SG_SUBAGENT_STATE_DIR/sub3"
    # Create content larger than SG_SUBAGENT_READ_BYTES (10240) but under SG_TRUNCATE_BYTES (20480)
    local big_output
    big_output=$(python3 -c "print('x' * 15000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/big.txt"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-session-001",
        transcript_path: "/home/user/.claude/projects/test/subagents/agent-sub3.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "truncated"
}

# ==============================================================================
# GIT HINT STRIPPING
# ==============================================================================

@test "strips git hints from Bash output" {
    local text
    text=$(printf 'On branch main\nhint: use git push\nhint: to push changes\nChanges staged')
    local input
    input=$(jq -n --arg text "$text" '{
        tool_name: "Bash",
        tool_input: {command: "git status"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    refute_output --partial "hint:"
}

# ==============================================================================
# SYSTEM REMINDER STRIPPING FOR BASH TOOL
# ==============================================================================

@test "strips system-reminder from Bash tool and continues processing" {
    local text
    text=$(printf 'result data\n<system-reminder>\ninternal stuff\n</system-reminder>\nmore data')
    local input
    input=$(jq -n --arg text "$text" '{
        tool_name: "Bash",
        tool_input: {command: "some-cmd"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    # For Bash, reminder stripped + small output → modifyOutput with cleaned text
    assert_output --partial "modifyOutput"
    refute_output --partial "system-reminder"
}

@test "strips system-reminder from Grep tool" {
    local text
    text=$(printf 'grep results\n<system-reminder>\nstuff\n</system-reminder>\nmore')
    local input
    input=$(jq -n --arg text "$text" '{
        tool_name: "Grep",
        tool_input: {pattern: "test"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}

# ==============================================================================
# TASK STRUCTURED OUTPUT COMPRESSION
# ==============================================================================

@test "Task tool large output gets structured compression" {
    # Create output >6144 bytes with structured content
    local text=""
    local i=0
    while (( i < 200 )); do
        text="${text}# Section ${i}\n- item ${i} detail\n1) numbered item\nsome filler text that is not structured\n"
        i=$((i + 1))
    done
    text=$(printf '%b' "$text")
    local input
    input=$(jq -n --arg text "$text" '{
        tool_name: "Task",
        tool_input: {prompt: "do stuff"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "compressed"
}

# ==============================================================================
# BUDGET ALERT THRESHOLD (every 50 calls)
# ==============================================================================

@test "budget alert written at critical threshold on 50th call" {
    # Set state file to 49 previous calls
    mkdir -p "$SG_STATE_DIR"
    echo "49|100|Bash:ls|$(date +%s)" > "$SG_STATE_DIR/session-test-session-001"
    # Set budget high enough to trigger alert
    echo "252000" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(make_post_input "Bash" "hello" "echo hello")
    run_hook "$HOOK" "$input"
    assert_success
    # Check alert file was created (90% = 252000/280000)
    assert_exist "$SG_STATE_DIR/budget-alert"
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "CRITICAL"
}

@test "budget alert written at warning threshold on 50th call" {
    mkdir -p "$SG_STATE_DIR"
    echo "49|100|Bash:ls|$(date +%s)" > "$SG_STATE_DIR/session-test-session-001"
    echo "210000" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(make_post_input "Bash" "hello" "echo hello")
    run_hook "$HOOK" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/budget-alert"
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "WARNING"
}

# ==============================================================================
# NON-BASH TOOL LABEL TRACKING
# ==============================================================================

@test "tracks non-Bash tool name as label" {
    local input
    input=$(jq -n '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/test.txt"},
        tool_response: {content: [{text: "lots of content here for tracking purposes in the session"}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_success
    run cat "$SG_STATE_DIR/session-test-session-001"
    assert_output --partial "Read"
}

# ==============================================================================
# EMPTY INPUT
# ==============================================================================

@test "empty stdin exits cleanly" {
    run_hook "$HOOK" ""
    assert_success
}

# ==============================================================================
# BINARY OUTPUT DETECTION
# ==============================================================================

@test "binary output (NUL bytes) gets suppressed" {
    # Create binary content with NUL bytes
    local bintext
    bintext=$(printf 'ELF\x00\x01\x02binary\x00data')
    local input
    input=$(jq -n --arg text "$bintext" '{
        tool_name: "Bash",
        tool_input: {command: "cat /usr/bin/test"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_success
}

# ==============================================================================
# READ TOOL FROM MAIN AGENT
# ==============================================================================

@test "Read tool from main agent small output passes" {
    local input
    input=$(jq -n '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/test.txt"},
        tool_response: {content: [{text: "small file content"}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "suppressOutput"
}

# ==============================================================================
# GLOB AND TASK PASSTHROUGH
# ==============================================================================

@test "Glob output passes with suppress" {
    run_hook "$HOOK" "$(make_post_input 'Glob' 'file1.ts\nfile2.ts')"
    assert_output --partial "suppressOutput"
}

@test "Bash no-op case passes quickly" {
    run_hook "$HOOK" "$(make_post_input 'Bash' 'ok' 'echo ok')"
    assert_output --partial "suppressOutput"
}

# ==============================================================================
# NM/STRINGS HEAD-ONLY (additional)
# ==============================================================================

@test "subagent Bash uses normal truncation threshold" {
    mkdir -p "$SG_SUBAGENT_STATE_DIR"
    printf 'AGENT_TYPE=Explore\nSESSION_ID=test\n' > "$SG_SUBAGENT_STATE_DIR/sub4"
    local big_output
    big_output=$(python3 -c "print('x' * 25000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Bash",
        tool_input: {command: "some-cmd"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-session-001",
        transcript_path: "/home/user/.claude/projects/test/subagents/agent-sub4.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "truncated"
}

@test "Read for non-subagent passes with allowed event" {
    local input
    input=$(jq -n '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/regular.txt"},
        tool_response: {content: [{text: "regular file content that is from main agent"}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "suppressOutput"
}

@test "WebSearch output passes through with suppress" {
    run_hook "$HOOK" "$(make_post_input 'WebSearch' 'search results content')"
    assert_output --partial "suppressOutput"
}

@test "session state handles corrupt state file gracefully" {
    mkdir -p "$SG_STATE_DIR"
    echo "not|valid|state" > "$SG_STATE_DIR/session-test-session-001"
    local input
    input=$(make_post_input "Bash" "hello" "echo hello")
    run_hook "$HOOK" "$input"
    assert_success
    assert_output --partial "suppressOutput"
}

@test "budget alert written at warning level on 50th call" {
    mkdir -p "$SG_STATE_DIR"
    echo "49|100|Bash:ls|$(date +%s)" > "$SG_STATE_DIR/session-test-session-001"
    echo "210000" > "$HOME/.claude/.safeguard/budget.state"
    local input
    input=$(make_post_input "Bash" "hello" "echo hello")
    run_hook "$HOOK" "$input"
    assert_success
    assert_exist "$SG_STATE_DIR/budget-alert"
    run cat "$SG_STATE_DIR/budget-alert"
    assert_output --partial "WARNING"
}

@test "binary output detected and replaced with message" {
    # Use jq string expression to embed \u0000 — survives bash $() as JSON escape,
    # then jq -r in the hook outputs real NUL bytes for od to detect
    local input
    input=$(jq -n '{
        tool_name: "Bash",
        tool_input: {command: "cat /usr/bin/test"},
        tool_response: {content: [{text: ("ELF\u0000\u0001\u0002binary\u0000data" + ("A" * 25000))}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Binary output"
}

@test "tool latency emitted when tool start file exists" {
    mkdir -p "$SG_STATE_DIR"
    # Write a tool-start marker just before calling post-tool-use
    echo "$(date +%s%N)" > "$SG_STATE_DIR/.tool-start-Bash-$$"
    local input
    input=$(make_post_input "Bash" "hello world" "echo hello")
    run_hook "$HOOK" "$input"
    assert_success
    # The latency event should be emitted
    run grep "tool_latency" "$SG_EVENTS_FILE"
    assert_success
}

@test "Task output gets compressed when >6KB" {
    local big_output
    big_output=$(python3 -c "
for i in range(200):
    print(f'- Task item {i}: description here')
    print(f'  Status: pending')
")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Task",
        tool_input: {command: "list"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "compressed"
}

@test "otool output gets head-only truncation" {
    local big_output
    big_output=$(python3 -c "print('symbol_line\n' * 5000)")
    local input
    input=$(jq -n --arg text "$big_output" '{
        tool_name: "Bash",
        tool_input: {command: "otool -L /usr/bin/test"},
        tool_response: {content: [{text: $text}]},
        session_id: "test-sess",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}
