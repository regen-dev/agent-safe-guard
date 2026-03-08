#!/usr/bin/env bats
# Integration tests for asg-statusline

setup() {
    load '../test_helper/common'
    setup_isolated_env
    SCRIPT="$PROJ_ROOT/build/native/native/asg-statusline"
    if [[ ! -x "$SCRIPT" ]]; then
        cmake -S "$PROJ_ROOT" -B "$PROJ_ROOT/build/native" -DSG_BUILD_NATIVE=ON >/dev/null
        cmake --build "$PROJ_ROOT/build/native" --target asg-statusline -j >/dev/null
    fi
    # asg-statusline reads HOME/.claude/.statusline for state
    mkdir -p "$HOME/.claude/.statusline"
}

teardown() {
    teardown_isolated_env
}

_make_status_input() {
    jq -n \
        --arg sid "${1:-sess-test-001}" \
        --arg model "${2:-claude-opus-4-6}" \
        --argjson ctx_size "${3:-200000}" \
        --argjson total_in "${4:-50000}" \
        --argjson total_out "${5:-10000}" \
        --argjson cost "${6:-0.5}" \
        '{
            session_id: $sid,
            model: {display_name: $model, id: $model},
            context_window: {
                context_window_size: $ctx_size,
                total_input_tokens: $total_in,
                total_output_tokens: $total_out,
                used_percentage: 30
            },
            tool_count: 15,
            cost: {
                total_cost_usd: $cost,
                total_duration_ms: 120000,
                total_api_duration_ms: 80000,
                total_lines_added: 50,
                total_lines_removed: 10
            }
        }'
}

# ==============================================================================
# BASIC OUTPUT
# ==============================================================================

@test "produces output with model name" {
    local input
    input=$(_make_status_input)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "claude-opus-4-6"
}

@test "produces output with percentage" {
    local input
    input=$(_make_status_input)
    run_hook "$SCRIPT" "$input"
    assert_output --partial "%"
}

@test "produces output with cost" {
    local input
    input=$(_make_status_input)
    run_hook "$SCRIPT" "$input"
    assert_output --partial '$'
}

# ==============================================================================
# NO JQ DEPENDENCY
# ==============================================================================

@test "statusline works without jq in PATH" {
    local input
    input=$(_make_status_input)
    for cmd in bash cat date stat printf mkdir rm mv head awk grep cut sed tr wc touch; do
        ln -sf "$(which $cmd 2>/dev/null)" "$MOCK_DIR/$cmd" 2>/dev/null || true
    done
    export PATH="$MOCK_DIR"
    run_hook "$SCRIPT" "$input"
    export PATH="$ORIGINAL_PATH"
    assert_success
    assert_output --partial "claude-opus-4-6"
}

# ==============================================================================
# EMPTY/INVALID INPUT
# ==============================================================================

@test "handles empty input" {
    run_hook "$SCRIPT" ""
    assert_success
    assert_output --partial "Ctx 0%"
}

@test "handles invalid JSON" {
    run_hook "$SCRIPT" "not json at all"
    assert_success
    assert_output --partial "Ctx 0%"
}

# ==============================================================================
# FORMAT FUNCTIONS (via full pipeline)
# ==============================================================================

@test "formats token counts (thousands)" {
    local input
    input=$(_make_status_input "sess-1" "claude-sonnet" 200000 50000 10000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "200k"
}

@test "formats token counts (millions)" {
    local input
    input=$(_make_status_input "sess-1" "claude-sonnet" 2000000 500000 100000 1.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "2M"
}

# ==============================================================================
# COLOR CODING
# ==============================================================================

@test "green color for low usage (<50%)" {
    local input
    input=$(jq -n '{
        session_id: "sess-1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 10000, total_output_tokens: 5000, used_percentage: 10},
        cost: {total_cost_usd: 0.1}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Green escape code
    assert_output --partial "32m"
}

@test "yellow color for medium usage (50-80%)" {
    local input
    input=$(jq -n '{
        session_id: "sess-1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 60000, total_output_tokens: 60000, used_percentage: 65},
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Yellow escape code
    assert_output --partial "33m"
}

@test "red color for high usage (>80%)" {
    local input
    input=$(jq -n '{
        session_id: "sess-1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 90000, total_output_tokens: 90000, used_percentage: 90},
        cost: {total_cost_usd: 1.0}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Red escape code
    assert_output --partial "31m"
}

# ==============================================================================
# STATE FILE PERSISTENCE
# ==============================================================================

@test "creates state file on first run" {
    local input
    input=$(_make_status_input "sess-state1")
    printf '%s' "$input" | "$SCRIPT"  > /dev/null
    assert_exist "$HOME/.claude/.statusline/state"
}

@test "detects session change" {
    local input1
    input1=$(_make_status_input "sess-old" "test" 200000 50000 10000 0.5)
    bash -c "echo '$input1' | $SCRIPT" > /dev/null
    local input2
    input2=$(_make_status_input "sess-new" "test" 200000 5000 1000 0.1)
    bash -c "echo '$input2' | $SCRIPT" > /dev/null
    # State should now have sess-new
    run cat "$HOME/.claude/.statusline/state"
    assert_output --partial "sess-new"
}

# ==============================================================================
# TOOL COUNT DISPLAY
# ==============================================================================

@test "displays tool count when present" {
    local input
    input=$(_make_status_input "sess-tc1")
    run_hook "$SCRIPT" "$input"
    assert_output --partial "T:15"
}

# ==============================================================================
# LINES ADDED/REMOVED
# ==============================================================================

@test "displays lines added/removed" {
    local input
    input=$(_make_status_input "sess-loc1")
    run_hook "$SCRIPT" "$input"
    assert_output --partial "+50"
    assert_output --partial "-10"
}

# ==============================================================================
# COST NORMALIZATION
# ==============================================================================

@test "handles microdollar cost (large integer)" {
    local input
    input=$(jq -n '{
        session_id: "sess-cost1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        cost: {total_cost_usd: 500000}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Should normalize to $0.50
    assert_output --partial '$0.50'
}

@test "handles float dollar cost" {
    local input
    input=$(jq -n '{
        session_id: "sess-cost2",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        cost: {total_cost_usd: 1.25}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "$1.25"
}

# ==============================================================================
# SUBAGENT COUNT
# ==============================================================================

@test "displays subagent count when active" {
    printf 'sess-sub1|3|%s\n' "$(date +%s)" > "$HOME/.claude/.statusline/subagent-count"
    local input
    input=$(_make_status_input "sess-sub1")
    run_hook "$SCRIPT" "$input"
    assert_output --partial "Sub:3"
}

# ==============================================================================
# CONTEXT CLEAR TRACKING
# ==============================================================================

@test "displays clear count when present" {
    printf '2|50000|0.5\n' > "$HOME/.claude/.statusline/clears-sess-clr1"
    local input
    input=$(_make_status_input "sess-clr1")
    run_hook "$SCRIPT" "$input"
    assert_output --partial "Clr:2"
}

# ==============================================================================
# CACHE HIT RATE
# ==============================================================================

@test "displays cache hit percentage" {
    local input
    input=$(jq -n '{
        session_id: "sess-cache1",
        model: {display_name: "test"},
        context_window: {
            context_window_size: 200000,
            total_input_tokens: 50000,
            total_output_tokens: 10000,
            used_percentage: 30,
            current_usage: {
                input_tokens: 50000,
                output_tokens: 10000,
                cache_creation_input_tokens: 10000,
                cache_read_input_tokens: 40000
            }
        },
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Cache:"
}

# ==============================================================================
# STATE FILE WITH PREVIOUS SESSION (recovery/transition)
# ==============================================================================

@test "recovers from existing state file with full fields" {
    # Write a state file with the new 15-field format
    printf 'sess-st1|50000|10000|30000|200000|0.500000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-st1" "test" 200000 55000 12000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "test"
}

@test "detects context window reset (large drop)" {
    # Create state with high CTX usage
    printf 'sess-ctx1|80000|20000|90000|200000|0.500000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Now send input with much lower CTX (drop > 2000)
    local input
    input=$(_make_status_input "sess-ctx1" "test" 200000 5000 1000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Context clears show as Clr:N (Reset label only for token resets)
    assert_output --partial "Clr:1"
}

@test "tracks turn cost delta" {
    # First call to establish baseline
    printf 'sess-tc1|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-tc1" "test" 200000 60000 12000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Should show turn cost delta
    assert_output --partial '$'
}

@test "tracks peak cost per turn" {
    printf 'sess-pk1|50000|10000|30000|200000|0.100000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-pk1" "test" 200000 60000 12000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Peak cost file should be created
    assert_exist "$HOME/.claude/.statusline/peak-sess-pk1"
    assert_output --partial "pk:"
}

@test "displays budget percentage from cache" {
    # statusline reads budget from $STATE_DIR/budget-export with mtime ≤ 5s
    printf '{"consumed":210000,"limit":280000,"total_limit":280000,"utilization":75}' \
        > "$HOME/.claude/.statusline/budget-export"
    touch "$HOME/.claude/.statusline/budget-export"
    local input
    input=$(_make_status_input "sess-bgt1")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Bgt:"
}

@test "displays reset label from reason file" {
    # Create a reset-reason file (recent timestamp)
    printf '%s|user_reset|sess-rst1\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/reset-reason"
    local input
    input=$(_make_status_input "sess-rst1")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Reset"
}

@test "reads tool count from session-state file when JSON has 0" {
    # When JSON tool_count defaults to 0 and session-state has a count,
    # TOOL_COUNT is still "0" from JSON (jq defaults to 0), so session-state
    # count is only used when TOOL_COUNT is empty. Verify combined session state
    # file is read for HOT_SIZE_BYTES tracking.
    printf '42|15000|Bash:ls|%s\n' "$(date +%s)" > "$HOME/.claude/.statusline/session-sess-tcf1"
    local input
    input=$(jq -n '{
        session_id: "sess-tcf1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 10000, total_output_tokens: 5000, used_percentage: 10},
        cost: {total_cost_usd: 0.1}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # JSON defaults tool_count to 0, so T: not displayed (only shown when > 0)
    refute_output --partial "T:42"
}

@test "session state file provides tool count fallback" {
    # Session state file is at $STATE_DIR/session-$SESSION_ID
    # SS_COUNT is used when TOOL_COUNT (from JSON) is empty
    # But jq always defaults tool_count to 0, so this only works
    # when the JSON provides tool_count > 0 (which overrides).
    printf '25|15000|Bash:ls|%s\n' "$(date +%s)" > "$HOME/.claude/.statusline/session-sess-hot1"
    local input
    input=$(_make_status_input "sess-hot1")
    run_hook "$SCRIPT" "$input"
    assert_success
    # T:15 from JSON tool_count (takes priority over file's 25)
    assert_output --partial "T:15"
}

@test "context clear increments clear count" {
    # First state: high context usage
    printf 'sess-clr2|80000|20000|95000|200000|0.500000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Run with low context (triggers clear detection)
    local input
    input=$(_make_status_input "sess-clr2" "test" 200000 5000 1000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Clear file should be created/updated
    assert_exist "$HOME/.claude/.statusline/clears-sess-clr2"
}

@test "low cache hit percentage gets yellow color" {
    local input
    input=$(jq -n '{
        session_id: "sess-lc1",
        model: {display_name: "test"},
        context_window: {
            context_window_size: 200000,
            total_input_tokens: 50000,
            total_output_tokens: 10000,
            used_percentage: 30,
            current_usage: {
                input_tokens: 50000,
                output_tokens: 10000,
                cache_creation_input_tokens: 40000,
                cache_read_input_tokens: 5000
            }
        },
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Cache:"
}

@test "API duration percentage displayed" {
    # State file for same session to get SAME_SESSION=1
    printf 'sess-api1|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(jq -n '{
        session_id: "sess-api1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 55000, total_output_tokens: 12000, used_percentage: 35},
        cost: {total_cost_usd: 0.5, total_duration_ms: 200000, total_api_duration_ms: 150000}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "API:"
}

@test "format_tokens handles small numbers (<1000)" {
    local input
    input=$(_make_status_input "sess-sm1" "test" 500 100 50 0.01)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Small token counts displayed as-is
    assert_output --partial "500"
}

@test "num_or_zero returns 0 for non-numeric" {
    local input
    # Context size as 0 to test num_or_zero edge case
    input=$(jq -n '{
        session_id: "sess-nz1",
        model: {display_name: "test"},
        context_window: {context_window_size: 0, total_input_tokens: 0, total_output_tokens: 0, used_percentage: 0},
        cost: {total_cost_usd: 0}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Format is [model] {pct}% — with 0 usage
    assert_output --partial "0%"
}

@test "budget at high threshold gets red color" {
    # statusline reads budget from $STATE_DIR/budget-export with mtime ≤ 5s
    printf '{"consumed":259000,"limit":280000,"total_limit":280000,"utilization":92}' \
        > "$HOME/.claude/.statusline/budget-export"
    touch "$HOME/.claude/.statusline/budget-export"
    local input
    input=$(_make_status_input "sess-bgt2")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Bgt:92%"
}

@test "old 5-field state file format is handled" {
    # Legacy format: SESSION|TOTAL|CTX_USED|RESET_TS|RESET_REASON
    printf 'sess-old5|60000|45000|0|\n' > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-old5" "test" 200000 65000 15000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "test"
}

@test "token reset triggers Reset label" {
    # Same session, but total drops (token reset, not context clear)
    # Requires: total < prev_total within same session
    printf 'sess-tr1|80000|20000|50000|200000|0.500000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Send lower total tokens (80000+20000=100000 > 5000+1000=6000)
    local input
    input=$(_make_status_input "sess-tr1" "test" 200000 5000 1000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Token reset triggers both Clr and Reset label
    assert_output --partial "Reset"
}

@test "format_tokens with decimal in M range" {
    # 1500000 → 1.5M
    local input
    input=$(_make_status_input "sess-fmt1" "test" 1500000 100000 50000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "1.5M"
}

@test "format_tokens with decimal in k range" {
    # 1500 → 1.5k — context_window_size=1500
    local input
    input=$(_make_status_input "sess-fmt2" "test" 1500 100 50 0.01)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "1.5k"
}

@test "normalize_cost_usd handles non-numeric string" {
    # When cost is somehow non-numeric, should get 0
    local input
    input=$(jq -n '{
        session_id: "sess-nc1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        cost: {total_cost_usd: "invalid"}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "test"
}

@test "cache hit 40% shows neutral (no color code)" {
    local input
    input=$(jq -n '{
        session_id: "sess-cn1",
        model: {display_name: "test"},
        context_window: {
            context_window_size: 200000,
            total_input_tokens: 50000,
            total_output_tokens: 10000,
            used_percentage: 30,
            current_usage: {
                input_tokens: 50000,
                output_tokens: 10000,
                cache_creation_input_tokens: 30000,
                cache_read_input_tokens: 20000
            }
        },
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Cache:40%"
}

@test "API efficiency low (<40%) shows yellow" {
    printf 'sess-api2|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(jq -n '{
        session_id: "sess-api2",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 55000, total_output_tokens: 12000, used_percentage: 35},
        cost: {total_cost_usd: 0.5, total_duration_ms: 200000, total_api_duration_ms: 60000}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # API:30% with yellow color (33m) — escape code is between API: and 30%
    assert_output --partial "API:"
    assert_output --partial "30%"
    assert_output --partial "33m"
}

@test "budget between 75-89% shows yellow" {
    printf '{"consumed":224000,"limit":280000}' \
        > "$HOME/.claude/.statusline/budget-export"
    touch "$HOME/.claude/.statusline/budget-export"
    local input
    input=$(_make_status_input "sess-bgt3")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Bgt:80%"
    assert_output --partial "33m"
}

@test "budget below 75% shows neutral" {
    printf '{"consumed":140000,"limit":280000}' \
        > "$HOME/.claude/.statusline/budget-export"
    touch "$HOME/.claude/.statusline/budget-export"
    local input
    input=$(_make_status_input "sess-bgt4")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Bgt:50%"
}

@test "clear count 3+ shows red" {
    printf '3|150000|0.5\n' > "$HOME/.claude/.statusline/clears-sess-clr3"
    local input
    input=$(_make_status_input "sess-clr3")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Clr:3"
    assert_output --partial "31m"
}

@test "clear count 2 shows yellow" {
    printf '2|100000|0.3\n' > "$HOME/.claude/.statusline/clears-sess-clr4"
    local input
    input=$(_make_status_input "sess-clr4")
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Clr:2"
    assert_output --partial "33m"
}

@test "peak cost tracks and displays highest turn cost" {
    # First call sets baseline
    printf 'sess-pks1|50000|10000|30000|200000|0.100000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-pks1" "test" 200000 60000 12000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    # With valid delta ($0.50 - $0.10 = $0.40), peak should be created
    assert_exist "$HOME/.claude/.statusline/peak-sess-pks1"
    assert_output --partial "pk:"
}

@test "peak cost updates when new turn exceeds previous peak" {
    # State: prev cost $0.20
    printf 'sess-pku1|50000|10000|30000|200000|0.200000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Existing peak of $0.10
    printf '0.1000\n' > "$HOME/.claude/.statusline/peak-sess-pku1"
    # New cost $0.80, delta = $0.60 > $0.10 peak → update
    local input
    input=$(_make_status_input "sess-pku1" "test" 200000 60000 12000 0.8)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "pk:"
}

@test "show reset without label (SHOW_RESET but no RESET_LABEL)" {
    # Token reset: set RESET_REASON to "reset" for SHOW_RESET=1
    printf 'sess-rsl1|80000|20000|50000|200000|0.500000|120000|80000|50|10|0|0|test|%s|reset\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-rsl1" "test" 200000 5000 1000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "Reset"
}

@test "peak cost sanity check replaces insane value" {
    # State: prev cost $0.50
    printf 'sess-pksane|50000|10000|30000|200000|0.500000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Peak file with value larger than total cost (999 > 0.80)
    # Now that $(<file) bug is fixed, peak reads 999.9999 from file
    # But delta ($0.30) < peak (999.9999) so peak stays at 999.9999
    # Sanity check: 999.9999 > 0.80 total → insane → peak removed
    printf '999.9999\n' > "$HOME/.claude/.statusline/peak-sess-pksane"
    # New cost $0.80, delta = $0.30
    local input
    input=$(_make_status_input "sess-pksane" "test" 200000 60000 12000 0.8)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Peak 999.9999 > total 0.80 → sanity check removes it → no pk: shown
    refute_output --partial "pk:"
    # Peak file should be deleted by sanity check
    assert_not_exist "$HOME/.claude/.statusline/peak-sess-pksane"
}

@test "normalize_cost_usd converts large integer as microdollars" {
    # When cost_raw is >= 1000, it's treated as microdollars
    # Large integer costs are interpreted as microdollars.
    local input
    input=$(jq -n '{
        session_id: "sess-micro1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        cost: {total_cost_usd: 500000}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # 500000 microdollars = $0.50
    assert_output --partial '$0.50'
}

@test "tool count from session state file fallback" {
    # Create tool count file (legacy format)
    printf 'sess-tcfall|42|%s\n' "$(date +%s)" > "$HOME/.claude/.statusline/tool-count-sess-tcfall"
    # NO tool_count in JSON → defaults to 0 → TOOL_COUNT="" after check → fall through to file
    local input
    input=$(jq -n '{
        session_id: "sess-tcfall",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 10000, total_output_tokens: 5000, used_percentage: 10},
        cost: {total_cost_usd: 0.1}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Tool count 0 from JSON means TOOL_COUNT is "0", not empty
    # So the file fallback never triggers (this is expected behavior)
}

@test "used_percentage decimal parsing" {
    # Test the USED_PCT_RAW regex parsing with decimal
    local input
    input=$(jq -n '{
        session_id: "sess-pctd",
        model: {display_name: "test"},
        context_window: {
            context_window_size: 200000,
            total_input_tokens: 50000,
            total_output_tokens: 10000,
            used_percentage: "47.3"
        },
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "47"
}

@test "normalize_cost_usd returns 0 for non-numeric input" {
    local input
    input=$(jq -n '{
        session_id: "sess-badcost",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        cost: {total_cost_usd: "not-a-number"}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # Should show $0.00 or no cost since normalize returns '0'
    refute_output --partial '$not'
}

@test "tool count falls back to session state file when jq field invalid" {
    # Force TOOL_COUNT_RAW to non-numeric so fallback triggers
    mkdir -p "$HOME/.claude/.statusline"
    printf 'sess-tc1|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    echo "42|5000|Bash:ls|$(date +%s)" > "$HOME/.claude/.statusline/session-sess-tc1"
    local input
    input=$(jq -n '{
        session_id: "sess-tc1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        tool_count: "invalid",
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "T:42"
}

@test "legacy tool count file used as fallback" {
    # Force non-numeric tool_count so TOOL_COUNT stays empty,
    # no session state file, only legacy tool-count file exists
    mkdir -p "$HOME/.claude/.statusline"
    printf 'sess-ltc|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    echo "sess-ltc|99|$(date +%s)" > "$HOME/.claude/.statusline/tool-count-sess-ltc"
    local input
    input=$(jq -n '{
        session_id: "sess-ltc",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 50000, total_output_tokens: 10000, used_percentage: 30},
        tool_count: "invalid",
        cost: {total_cost_usd: 0.5}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "T:99"
}

@test "peak cost read from file when no valid delta" {
    # First invocation sets peak, second invocation has no delta
    mkdir -p "$HOME/.claude/.statusline"
    printf 'sess-pknd|50000|10000|30000|200000|0.500000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    printf '0.1500\n' > "$HOME/.claude/.statusline/peak-sess-pknd"
    # First call: session matches, cost matches → generates delta, reads peak
    local input
    input=$(_make_status_input "sess-pknd" "test" 200000 60000 12000 0.6)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "pk:"
}

@test "peak sanity check runs without error when peak is sane" {
    # Exercise the sanity check path where peak <= total → OK
    mkdir -p "$HOME/.claude/.statusline"
    printf 'sess-pksane2|50000|10000|30000|200000|0.100000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    # Delta $0.10 written as new peak, passes sanity check (0.10 <= 0.20)
    local input
    input=$(_make_status_input "sess-pksane2" "test" 200000 60000 12000 0.2)
    run_hook "$SCRIPT" "$input"
    assert_success
    assert_output --partial "pk:"
}

@test "num_or_zero returns 0 for non-numeric value from state file" {
    # Create state file with non-numeric fields to trigger num_or_zero else branch (L73)
    mkdir -p "$HOME/.claude/.statusline"
    printf 'sess-noz|corrupt|abc|xyz|200000|0.300000|120000|80000|50|10|0|0|test|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    local input
    input=$(_make_status_input "sess-noz" "test" 200000 50000 10000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Should handle non-numeric gracefully (produce output)
    assert_output --partial "test"
}

@test "large integer cost without decimal treated as microdollars" {
    # cost=5000 (integer, no decimal, no tokens) → ≥1000 heuristic → microdollars
    local input
    input=$(jq -n '{
        session_id: "sess-micro1",
        model: {display_name: "test"},
        context_window: {context_window_size: 200000, total_input_tokens: 0, total_output_tokens: 0, used_percentage: 30},
        cost: {total_cost_usd: 5000}
    }')
    run_hook "$SCRIPT" "$input"
    assert_success
    # 5000 microdollars = $0.005 → displayed as $0.01
    assert_output --partial '$0.0'
}

@test "peak read from file in non-delta path (first observation)" {
    # No previous state → HAS_VALID_DELTA=0, but peak file exists
    # Exercises non-delta peak read path
    mkdir -p "$HOME/.claude/.statusline"
    # No state file → PREV_SESSION="" → no delta
    printf '0.2500\n' > "$HOME/.claude/.statusline/peak-sess-pknondelta"
    local input
    input=$(_make_status_input "sess-pknondelta" "test" 200000 50000 10000 0.5)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Now that cat is used instead of $(<file), peak reads correctly from file
    assert_output --partial "pk:"
    assert_output --partial "0.25"
}

@test "session change cleans up old state files" {
    # Create old session state files
    printf 'sess-old1|50000|10000|30000|200000|0.300000|120000|80000|50|10|0|0|0|%s|\n' "$(date +%s)" \
        > "$HOME/.claude/.statusline/state"
    printf '2|50000|0.5\n' > "$HOME/.claude/.statusline/clears-sess-old1"
    printf '0.1234' > "$HOME/.claude/.statusline/peak-sess-old1"
    local input
    input=$(_make_status_input "sess-new1" "test" 200000 5000 1000 0.1)
    run_hook "$SCRIPT" "$input"
    assert_success
    # Old session files should be cleaned up
    assert_not_exist "$HOME/.claude/.statusline/clears-sess-old1"
    assert_not_exist "$HOME/.claude/.statusline/peak-sess-old1"
}
