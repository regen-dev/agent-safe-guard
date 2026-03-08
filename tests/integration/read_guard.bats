#!/usr/bin/env bats
# Integration tests for hooks/read-guard

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK="${SG_READ_GUARD_HOOK:-$PROJ_ROOT/hooks/read-guard}"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# BUNDLED FILE BLOCKING
# ==============================================================================

@test "blocks node_modules read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/node_modules/express/index.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks dist directory read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/dist/bundle.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks build directory read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/build/app.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks .min.js read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/jquery.min.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks .bundle.js read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/app.bundle.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks .chunk.js read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/vendor.chunk.js"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks package-lock.json read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/package-lock.json"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks yarn.lock read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/yarn.lock"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks pnpm-lock.yaml read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/pnpm-lock.yaml"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks Cargo.lock read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/Cargo.lock"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "bundled"
}

@test "blocks poetry.lock read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/poetry.lock"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

@test "blocks composer.lock read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/composer.lock"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

@test "blocks Gemfile.lock read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/Gemfile.lock"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

@test "blocks go.sum read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/go.sum"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

@test "blocks vendor directory read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/vendor/autoload.php"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

@test "blocks __generated__ directory read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/__generated__/types.ts"}')
    run_hook "$HOOK" "$input"
    assert_failure
}

# ==============================================================================
# OVERSIZE FILE BLOCKING
# ==============================================================================

@test "blocks file >2MB" {
    local bigfile="$TEST_TEMP/big.txt"
    dd if=/dev/zero of="$bigfile" bs=1M count=3 2>/dev/null
    local input
    input=$(jq -n --arg fp "$bigfile" '{tool_name:"Read",tool_input:{file_path:$fp},session_id:"test",transcript_path:"/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK" "$input"
    assert_failure
    assert_output --partial "MB"
}

@test "allows file under 2MB" {
    local smallfile="$TEST_TEMP/small.txt"
    echo "small content" > "$smallfile"
    local input
    input=$(jq -n --arg fp "$smallfile" '{tool_name:"Read",tool_input:{file_path:$fp},session_id:"test",transcript_path:"/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK" "$input"
    assert_success
}

@test "allows nonexistent file (let Claude handle the error)" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/nonexistent/file.txt"}')
    run_hook "$HOOK" "$input"
    assert_success
}

# ==============================================================================
# NORMAL FILES PASS THROUGH
# ==============================================================================

@test "allows normal source file read" {
    local input
    input=$(make_tool_input "Read" '{"file_path":"/home/user/project/src/main.ts"}')
    run_hook "$HOOK" "$input"
    assert_success
}

# ==============================================================================
# EMPTY INPUT
# ==============================================================================

@test "empty file_path exits cleanly" {
    local input
    input=$(make_tool_input "Read" '{"file_path":""}')
    run_hook "$HOOK" "$input"
    assert_success
}

@test "empty stdin exits cleanly" {
    run_hook "$HOOK" ""
    assert_success
}

# ==============================================================================
# CUSTOM THRESHOLD
# ==============================================================================

@test "respects custom SG_READ_GUARD_MAX_MB" {
    echo 'SG_READ_GUARD_MAX_MB=1' > "$HOME/.claude/.safeguard/config.env"
    local bigfile="$TEST_TEMP/medium.txt"
    dd if=/dev/zero of="$bigfile" bs=1M count=2 2>/dev/null
    local input
    input=$(jq -n --arg fp "$bigfile" '{tool_name:"Read",tool_input:{file_path:$fp},session_id:"test",transcript_path:"/home/testuser/.claude/projects/test/main.jsonl"}')
    run_hook "$HOOK" "$input"
    assert_failure
}
