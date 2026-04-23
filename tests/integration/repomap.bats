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

# ==============================================================================
# PHASE 1 — tag extraction
# ==============================================================================

@test "asg-repomap build --tags prints def/ref lines for ts fixture" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$TS_FIXTURE" --tags
    assert_success
    assert_output --partial "def class AuthService"
    assert_output --partial "def method login"
    assert_output --partial "def method logout"
    assert_output --partial "def function createAuth"
    assert_output --partial "ref class AuthService"
    refute_output --partial "def method constructor"
}

@test "asg-repomap build --tags prints def lines for js fixture" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$JS_FIXTURE" --tags
    assert_success
    assert_output --partial "def function greet"
}

@test "asg-repomap build --tags on crossref fixture finds cross-file ref" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref/api.ts" --tags
    assert_success
    assert_output --partial "def function handleLogin"
    assert_output --partial "ref class AuthService"
    assert_output --partial "ref call login"
}

@test "asg-repomap build without --tags omits tag lines" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" build --file "$TS_FIXTURE"
    assert_success
    refute_output --partial "def class"
    refute_output --partial "ref call"
    assert_output --partial "tag_count=0"
}

# ==============================================================================
# PHASE 2 — index + PageRank
# ==============================================================================

@test "asg-repomap rank --root prints ranked file list" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" rank --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref"
    assert_success
    assert_output --partial "ok files=3"
    assert_line --index 1 --regexp '^0\.[0-9]+ auth\.ts$'
}

@test "asg-repomap rank: most-referenced file ranks highest" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    # auth.ts defines AuthService used by both api.ts and gateway.ts →
    # should outrank api.ts (used only by gateway.ts) and gateway.ts (leaf).
    run "$REPOMAP_BIN" rank --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref"
    assert_success
    local auth_line api_line gw_line
    auth_line=$(echo "$output" | grep -n 'auth.ts$' | head -1 | cut -d: -f1)
    api_line=$(echo "$output"  | grep -n 'api.ts$'  | head -1 | cut -d: -f1)
    gw_line=$(echo "$output"   | grep -n 'gateway.ts$' | head -1 | cut -d: -f1)
    [ -n "$auth_line" ] && [ -n "$api_line" ] && [ -n "$gw_line" ]
    [ "$auth_line" -lt "$api_line" ]
    [ "$api_line"  -lt "$gw_line"  ]
}

@test "asg-repomap rank: scores sum to approximately 1" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" rank --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref"
    assert_success
    local sum
    sum=$(echo "$output" | awk '/^[0-9]+\.[0-9]+ / {s += $1} END {printf "%.4f", s}')
    # Sum must be in [0.99, 1.01] — PageRank stochastic invariant.
    run awk -v s="$sum" 'BEGIN { exit !(s >= 0.99 && s <= 1.01) }'
    assert_success
}

@test "asg-repomap rank --root on missing dir fails" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" rank --root "$TEST_TEMP/does-not-exist"
    assert_failure
    assert_output --partial "no source files"
}

# ==============================================================================
# PHASE 3 — formatter + token budget
# ==============================================================================

@test "asg-repomap render emits path:line kind subkind name" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref"
    assert_success
    assert_output --regexp 'auth\.ts:[0-9]+ def class AuthService'
    assert_output --regexp 'api\.ts:[0-9]+ def function handleLogin'
    # Refs are NOT included by default.
    refute_output --regexp ' ref call '
}

@test "asg-repomap render --refs includes ref tags" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref" --refs
    assert_success
    assert_output --regexp 'api\.ts:[0-9]+ ref call login'
    assert_output --regexp 'gateway\.ts:[0-9]+ ref class AuthService'
}

@test "asg-repomap render output is sorted by file then line" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref"
    assert_success
    # Strip the stderr banner (which goes to stderr already) and sort stdout
    # identically; diff must be empty.
    local stdout_only
    stdout_only=$(printf '%s\n' "$output" | grep -v '^ok files=')
    local sorted
    sorted=$(printf '%s\n' "$stdout_only" | LC_ALL=C sort)
    [ "$stdout_only" = "$sorted" ]
}

@test "asg-repomap render respects --budget (truncates)" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    # Tiny budget — no file fits → 0 files, truncated.
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref" --budget 10
    assert_success
    assert_output --partial "truncated"
    assert_output --partial "files=0/3"
}

@test "asg-repomap render produces stable token count" {
    [ -x "$REPOMAP_BIN" ] || skip "asg-repomap not built (run: make native-build)"
    # Run twice; stderr tokens line must match (deterministic rendering).
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref" --budget 1024
    assert_success
    local first
    first=$(echo "$output" | grep -oE 'tokens=[0-9]+')
    run "$REPOMAP_BIN" render --root "$PROJ_ROOT/tests/fixtures/repomap/ts-crossref" --budget 1024
    assert_success
    local second
    second=$(echo "$output" | grep -oE 'tokens=[0-9]+')
    [ "$first" = "$second" ]
}
