#!/usr/bin/env bats
# Integration tests for asg-repomap (Phase 0: parse smoke test)

setup() {
    load '../test_helper/common'
    setup_isolated_env
    REPOMAP_BIN="${SG_REPOMAP_BIN:-$PROJ_ROOT/build/native/native/asg-repomap}"
    TS_FIXTURE="$PROJ_ROOT/tests/fixtures/repomap/ts-minimal/auth.ts"
    JS_FIXTURE="$PROJ_ROOT/tests/fixtures/repomap/js-minimal/util.js"
}

teardown() {
    teardown_isolated_env
}

# ==============================================================================
# PHASE 0 — parse smoke
# ==============================================================================

@test "asg-repomap build --file <ts> reports node_count > 0" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$TS_FIXTURE"
    assert_success
    assert_output --partial "ok lang=typescript"
    assert_output --regexp 'node_count=[0-9]+'
    # parser output for this fixture has well over 10 nodes
    assert_output --regexp 'node_count=([1-9][0-9]+|[0-9]{3,})'
}

@test "asg-repomap build --file <js> reports node_count > 0" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$JS_FIXTURE"
    assert_success
    assert_output --partial "ok lang=javascript"
    assert_output --regexp 'node_count=[0-9]+'
}

@test "asg-repomap build --file on unknown extension fails with clear error" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    local txt="$TEST_TEMP/notes.txt"
    echo "hello" > "$txt"
    run "$REPOMAP_BIN" build --file "$txt"
    assert_failure
    assert_output --partial "unsupported language"
}

@test "asg-repomap build --file on missing file fails" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$TEST_TEMP/does-not-exist.ts"
    assert_failure
    assert_output --partial "cannot read"
}

@test "asg-repomap without subcommand prints usage" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN"
    assert_failure
    assert_output --partial "usage:"
}
