#!/usr/bin/env bats
# Integration tests for Phase 5: session-start injects repomap additionalContext
# via a second daemon exchange (Hook::kRepomapRender).
#
# Requires a running daemon via SG_DAEMON_SOCKET, and the native session-start
# client via SG_SESSION_START_HOOK. Make target `test-native-repomap-session-smoke`
# handles both.

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK="${SG_SESSION_START_HOOK:-}"
    if [ -z "$HOOK" ]; then
        skip "SG_SESSION_START_HOOK not set (run: make test-native-repomap-session-smoke)"
    fi
    if [ -z "${SG_DAEMON_SOCKET:-}" ]; then
        skip "SG_DAEMON_SOCKET not set (run: make test-native-repomap-session-smoke)"
    fi

    REPO="$TEST_TEMP/repo"
    mkdir -p "$REPO"
    cp -r "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref/." "$REPO/"
    # The daemon-side EnsureFresh refuses non-git directories by default
    # (incident 2026-05-01 — accidental $HOME walks). Mark the fixture as
    # a git working tree so the test path matches a real project.
    mkdir -p "$REPO/.git"
}

teardown() {
    teardown_isolated_env
}

make_input() {
    jq -n --arg sid "sess-$RANDOM" '{
        session_id: $sid,
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }'
}

# ==============================================================================
# PHASE 5 — session-start injects repomap additionalContext
# ==============================================================================

@test "session-start emits additionalContext when SG_FEATURE_REPOMAP=1" {
    local input
    input=$(make_input)
    SG_FEATURE_REPOMAP=1 SG_REPOMAP_MAX_TOKENS=1024 PWD="$REPO" \
        run bash -c "cd '$REPO' && printf '%s' '$input' | '$HOOK'"
    assert_success
    assert_output --partial "hookSpecificOutput"
    assert_output --partial "SessionStart"
    assert_output --partial "additionalContext"
    assert_output --partial "auth.ts:"
    assert_output --partial "AuthService"
}

@test "session-start skips repomap when SG_FEATURE_REPOMAP=0" {
    local input
    input=$(make_input)
    SG_FEATURE_REPOMAP=0 PWD="$REPO" \
        run bash -c "cd '$REPO' && printf '%s' '$input' | '$HOOK'"
    assert_success
    refute_output --partial "additionalContext"
    refute_output --partial "auth.ts:"
}

@test "session-start fails soft when repomap target has no source files" {
    local empty_dir="$TEST_TEMP/empty"
    mkdir -p "$empty_dir"
    local input
    input=$(make_input)
    SG_FEATURE_REPOMAP=1 PWD="$empty_dir" \
        run bash -c "cd '$empty_dir' && printf '%s' '$input' | '$HOOK'"
    # Client should still succeed (exit 0) — repomap failure is non-fatal.
    assert_success
    refute_output --partial "additionalContext"
}

@test "session-start respects SG_REPOMAP_MAX_TOKENS budget" {
    local input
    input=$(make_input)
    # Tiny budget → truncation → additionalContext likely empty (0 files fit)
    # → session-start falls back to no repomap injection.
    SG_FEATURE_REPOMAP=1 SG_REPOMAP_MAX_TOKENS=5 PWD="$REPO" \
        run bash -c "cd '$REPO' && printf '%s' '$input' | '$HOOK'"
    assert_success
    # Empty text means the session-start client falls back to not emitting
    # additionalContext at all (render returned "", fail-soft).
    refute_output --partial "auth.ts"
}

@test "session-start persists repomap cache after first injection" {
    local input
    input=$(make_input)
    SG_FEATURE_REPOMAP=1 PWD="$REPO" \
        run bash -c "cd '$REPO' && printf '%s' '$input' | '$HOOK'"
    assert_success
    assert_file_exist "$REPO/.asg-repomap/tags.v1.bin"
}
