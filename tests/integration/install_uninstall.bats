#!/usr/bin/env bats
# Integration tests for asg-install and asg-uninstall

setup() {
    load '../test_helper/common'
    setup_isolated_env
    INSTALL_BIN="$PROJ_ROOT/build/native/native/asg-install"
    UNINSTALL_BIN="$PROJ_ROOT/build/native/native/asg-uninstall"
    if [[ ! -x "$INSTALL_BIN" || ! -x "$UNINSTALL_BIN" ]]; then
        cmake -S "$PROJ_ROOT" -B "$PROJ_ROOT/build/native" -DSG_BUILD_NATIVE=ON >/dev/null
        cmake --build "$PROJ_ROOT/build/native" --target asg-install asg-uninstall asg-statusline -j >/dev/null
    fi
}

teardown() {
    teardown_isolated_env
}

NATIVE_TEST_BINARIES=(
    "sgd"
    "sg-hook-pre-tool-use"
    "sg-hook-post-tool-use"
    "sg-hook-read-guard"
    "sg-hook-read-compress"
    "sg-hook-permission-request"
    "sg-hook-stop"
    "sg-hook-session-start"
    "sg-hook-session-end"
    "sg-hook-pre-compact"
    "sg-hook-subagent-start"
    "sg-hook-subagent-stop"
    "sg-hook-tool-error"
    "asg-cli"
    "asg-statusline"
    "asg-install"
    "asg-uninstall"
)

create_stub_binary() {
    local path="$1"
    cat > "$path" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$path"
}

create_full_native_bin_dir() {
    local dir="$1"
    local bin_name
    mkdir -p "$dir"
    for bin_name in "${NATIVE_TEST_BINARIES[@]}"; do
        create_stub_binary "$dir/$bin_name"
    done
}

install_with_full_native_bins() {
    local native_bin_dir="$1"
    shift
    create_full_native_bin_dir "$native_bin_dir"
    "$INSTALL_BIN" --native --native-bin-dir "$native_bin_dir" --no-enable-systemd-user "$@"
}

# ==============================================================================
# INSTALL
# ==============================================================================

@test "install --native creates native hook symlinks" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    run install_with_full_native_bins "$native_bin_dir"
    assert_success
    assert_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    assert_exist "$HOME/.claude/hooks/asg-post-tool-use"
    assert_exist "$HOME/.claude/hooks/asg-read-guard"
    assert_exist "$HOME/.claude/hooks/asg-read-compress"
    assert_exist "$HOME/.claude/hooks/asg-permission-request"
    assert_exist "$HOME/.claude/hooks/asg-session-start"
    assert_exist "$HOME/.claude/hooks/asg-session-end"
    assert_exist "$HOME/.claude/hooks/asg-subagent-start"
    assert_exist "$HOME/.claude/hooks/asg-subagent-stop"
    assert_exist "$HOME/.claude/hooks/asg-stop"
    assert_exist "$HOME/.claude/hooks/asg-pre-compact"
    assert_exist "$HOME/.claude/hooks/asg-tool-error"
    [[ -L "$HOME/.claude/hooks/asg-pre-tool-use" ]]
    run readlink "$HOME/.claude/hooks/asg-pre-tool-use"
    assert_output "$native_bin_dir/sg-hook-pre-tool-use"
}

@test "install default mode uses direct native symlinks" {
    local native_bin_dir="$TEST_TEMP/native-bin-default"
    mkdir -p "$native_bin_dir"
    local native_bins=(
        "sgd"
        "sg-hook-pre-tool-use"
        "sg-hook-post-tool-use"
        "sg-hook-read-guard"
        "sg-hook-read-compress"
        "sg-hook-permission-request"
        "sg-hook-stop"
        "sg-hook-session-start"
        "sg-hook-session-end"
        "sg-hook-pre-compact"
        "sg-hook-subagent-start"
        "sg-hook-subagent-stop"
        "sg-hook-tool-error"
        "asg-cli"
        "asg-statusline"
        "asg-install"
        "asg-uninstall"
    )
    local b
    for b in "${native_bins[@]}"; do
        cat > "$native_bin_dir/$b" << 'EOF'
#!/usr/bin/env bash
exit 0
EOF
        chmod +x "$native_bin_dir/$b"
    done

    run env PATH="$native_bin_dir:$PATH" "$INSTALL_BIN"
    assert_success

    assert_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    [[ -L "$HOME/.claude/hooks/asg-pre-tool-use" ]]
    run readlink "$HOME/.claude/hooks/asg-pre-tool-use"
    [[ "$output" == "$native_bin_dir/sg-hook-pre-tool-use" || "$output" == "$PROJ_ROOT/build/native/native/sg-hook-pre-tool-use" ]]
    assert_exist "$HOME/.local/bin/asg-cli"
    [[ -L "$HOME/.local/bin/asg-cli" ]]
    run readlink "$HOME/.local/bin/asg-cli"
    [[ "$output" == "$native_bin_dir/asg-cli" || "$output" == "$PROJ_ROOT/build/native/native/asg-cli" ]]
}

@test "install uses built native client feature toggles when binaries are available" {
    if [[ ! -x "$PROJ_ROOT/build/native/native/sg-hook-pre-tool-use" ]]; then
        skip "native binaries not built"
    fi

    run "$INSTALL_BIN" --native --native-bin-dir "$PROJ_ROOT/build/native/native" --no-enable-systemd-user --no-feature-ui
    assert_success

    local input
    input=$(make_bash_input "rm -rf /")
    printf 'SG_FEATURE_PRE_TOOL_USE=0\n' > "$HOME/.claude/.safeguard/features.env"
    run_hook "$HOME/.claude/hooks/asg-pre-tool-use" "$input"
    assert_output --partial '"suppressOutput":true'
}

@test "install rejects removed --legacy-bash option" {
    run "$INSTALL_BIN" --legacy-bash
    assert_failure
    assert_output --partial "unknown option: --legacy-bash"
}

@test "install --native --enable-systemd-user installs asg units and removes legacy units" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    mkdir -p "$native_bin_dir"
    cat > "$native_bin_dir/sgd" << 'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$native_bin_dir/sgd"

    cat > "$MOCK_DIR/systemctl" << 'EOF'
#!/usr/bin/env bash
echo "$*" >> "$HOME/systemctl.calls"
exit 0
EOF
    chmod +x "$MOCK_DIR/systemctl"

    mkdir -p "$HOME/.config/systemd/user"
    printf 'legacy\n' > "$HOME/.config/systemd/user/agent-safe-guard-sgd.socket"
    printf 'legacy\n' > "$HOME/.config/systemd/user/agent-safe-guard-sgd.service"

    run env PATH="$MOCK_DIR:$PATH" "$INSTALL_BIN" \
        --native \
        --native-bin-dir "$native_bin_dir" \
        --enable-systemd-user
    assert_success

    assert_exist "$HOME/.config/systemd/user/asg.socket"
    assert_exist "$HOME/.config/systemd/user/asg.service"
    assert_not_exist "$HOME/.config/systemd/user/agent-safe-guard-sgd.socket"
    assert_not_exist "$HOME/.config/systemd/user/agent-safe-guard-sgd.service"
    run grep -F "ExecStart=$native_bin_dir/sgd" "$HOME/.config/systemd/user/asg.service"
    assert_success

    run grep -F -- "--user daemon-reload" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user disable --now agent-safe-guard-sgd.socket" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user disable --now agent-safe-guard-sgd.service" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user enable --now asg.socket" "$HOME/systemctl.calls"
    assert_success
}

@test "install creates config.env" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.claude/.safeguard/config.env"
}

@test "install creates features.env defaults" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.claude/.safeguard/features.env"
    run grep '^SG_FEATURE_STATUSLINE=0$' "$HOME/.claude/.safeguard/features.env"
    assert_success
}

@test "install scaffolds default policy catalog source" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.claude/.safeguard/policy/catalogs.json"
    run jq -r '.catalogs[0].source_url' "$HOME/.claude/.safeguard/policy/catalogs.json"
    assert_success
    assert_output "https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/rules-v0.3.0/rules/catalogs/github-core.json"
}

@test "install --feature-ui updates features.env selections" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    create_full_native_bin_dir "$native_bin_dir"
    run bash -c "{ printf 'n\n'; yes '' | head -n 11; printf 'y\n'; } | '$INSTALL_BIN' --native --native-bin-dir '$native_bin_dir' --no-enable-systemd-user --feature-ui"
    assert_success
    run grep '^SG_FEATURE_PRE_TOOL_USE=0$' "$HOME/.claude/.safeguard/features.env"
    assert_success
    run grep '^SG_FEATURE_STATUSLINE=1$' "$HOME/.claude/.safeguard/features.env"
    assert_success
}

@test "install preserves existing config.env" {
    echo "SG_TRUNCATE_BYTES=99999" > "$HOME/.claude/.safeguard/config.env"
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    run grep "99999" "$HOME/.claude/.safeguard/config.env"
    assert_success
}

@test "install creates settings.json" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.claude/settings.json"
    run jq -r '.hooks.PreToolUse | length' "$HOME/.claude/settings.json"
    assert_success
}

@test "install adds hook entries to settings.json" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    run jq -r '.hooks.PreToolUse[].hooks[].command // empty' "$HOME/.claude/settings.json"
    assert_output --partial "asg-pre-tool-use"
}

@test "install backs up existing settings.json" {
    echo '{"existing":"value"}' > "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    local backups
    backups=$(ls "$HOME/.claude/settings.json.bak."* 2>/dev/null | wc -l)
    (( backups >= 1 ))
}

@test "install is idempotent (run twice)" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    # Should not duplicate hook entries
    local pretool_count
    pretool_count=$(jq '.hooks.PreToolUse | length' "$HOME/.claude/settings.json")
    # Should have exactly 2 PreToolUse entries (wildcard + Read)
    assert_equal "$pretool_count" "2"
}

@test "install sets statusline" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    run jq -r '.statusLine.command' "$HOME/.claude/settings.json"
    assert_output "~/.local/bin/asg-statusline"
}

@test "install creates asg-statusline symlink" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.local/bin/asg-statusline"
    [[ -L "$HOME/.local/bin/asg-statusline" ]]
    run readlink "$HOME/.local/bin/asg-statusline"
    assert_output "$native_bin_dir/asg-statusline"
}

@test "install creates asg-install and asg-uninstall symlinks" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null

    assert_exist "$HOME/.local/bin/asg-install"
    [[ -L "$HOME/.local/bin/asg-install" ]]
    run readlink "$HOME/.local/bin/asg-install"
    assert_output "$native_bin_dir/asg-install"

    assert_exist "$HOME/.local/bin/asg-uninstall"
    [[ -L "$HOME/.local/bin/asg-uninstall" ]]
    run readlink "$HOME/.local/bin/asg-uninstall"
    assert_output "$native_bin_dir/asg-uninstall"
}

@test "install preserves existing user hooks" {
    # Create a pre-existing user hook
    echo '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-custom-hook","timeout":5}]}]}}' > "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    run jq -r '.hooks.PreToolUse[].hooks[].command' "$HOME/.claude/settings.json"
    assert_output --partial "my-custom-hook"
}

@test "install creates config.env from template when missing" {
    # Remove the config.env that setup_isolated_env creates
    rm -f "$HOME/.claude/.safeguard/config.env"
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    assert_exist "$HOME/.claude/.safeguard/config.env"
    # Verify it has default content from the template
    run grep "SG_TRUNCATE_BYTES" "$HOME/.claude/.safeguard/config.env"
    assert_success
}

# ==============================================================================
# UNINSTALL
# ==============================================================================

@test "uninstall removes installed hooks" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    "$UNINSTALL_BIN" > /dev/null
    assert_not_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    assert_not_exist "$HOME/.claude/hooks/asg-post-tool-use"
    assert_not_exist "$HOME/.claude/hooks/asg-session-start"
}

@test "uninstall --help shows usage without removing installed files" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null

    run "$UNINSTALL_BIN" --help
    assert_success
    assert_output --partial "Usage: asg-uninstall"
    assert_output --partial "Config and local state"

    assert_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    assert_exist "$HOME/.local/bin/asg-cli"
}

@test "uninstall rejects unknown options" {
    run "$UNINSTALL_BIN" --nope
    assert_failure
    assert_output --partial "unknown option: --nope"
}

@test "uninstall removes native launcher hooks" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    run install_with_full_native_bins "$native_bin_dir"
    assert_success
    assert_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    [[ -L "$HOME/.claude/hooks/asg-pre-tool-use" ]]
    assert_exist "$HOME/.local/bin/asg-cli"
    [[ -L "$HOME/.local/bin/asg-cli" ]]

    run "$UNINSTALL_BIN"
    assert_success
    assert_not_exist "$HOME/.claude/hooks/asg-pre-tool-use"
    assert_not_exist "$HOME/.local/bin/asg-cli"
    assert_not_exist "$HOME/.local/bin/asg-statusline"
    assert_not_exist "$HOME/.local/bin/asg-install"
    assert_not_exist "$HOME/.local/bin/asg-uninstall"
}

@test "uninstall removes systemd user units from native install" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    mkdir -p "$native_bin_dir"
    cat > "$native_bin_dir/sgd" << 'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$native_bin_dir/sgd"

    cat > "$MOCK_DIR/systemctl" << 'EOF'
#!/usr/bin/env bash
echo "$*" >> "$HOME/systemctl.calls"
exit 0
EOF
    chmod +x "$MOCK_DIR/systemctl"

    env PATH="$MOCK_DIR:$PATH" "$INSTALL_BIN" \
        --native \
        --native-bin-dir "$native_bin_dir" \
        --enable-systemd-user > /dev/null
    printf 'legacy\n' > "$HOME/.config/systemd/user/agent-safe-guard-sgd.socket"
    printf 'legacy\n' > "$HOME/.config/systemd/user/agent-safe-guard-sgd.service"

    run env PATH="$MOCK_DIR:$PATH" "$UNINSTALL_BIN"
    assert_success

    assert_not_exist "$HOME/.config/systemd/user/asg.socket"
    assert_not_exist "$HOME/.config/systemd/user/asg.service"
    assert_not_exist "$HOME/.config/systemd/user/agent-safe-guard-sgd.socket"
    assert_not_exist "$HOME/.config/systemd/user/agent-safe-guard-sgd.service"
    run grep -F -- "--user disable --now asg.socket" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user disable --now asg.service" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user disable --now agent-safe-guard-sgd.socket" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user disable --now agent-safe-guard-sgd.service" "$HOME/systemctl.calls"
    assert_success
    run grep -F -- "--user daemon-reload" "$HOME/systemctl.calls"
    assert_success
}

@test "uninstall cleans settings.json" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    "$UNINSTALL_BIN" > /dev/null
    # agent-safe-guard hook entries should be gone
    run jq -r '.hooks.PreToolUse // [] | .[].hooks // [] | .[].command // empty' "$HOME/.claude/settings.json"
    refute_output --partial "sg-"
}

@test "uninstall removes statusline" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    "$UNINSTALL_BIN" > /dev/null
    run jq -r '.statusLine // empty' "$HOME/.claude/settings.json"
    assert_output ""
}

@test "uninstall preserves config directory" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    "$UNINSTALL_BIN" > /dev/null
    assert_exist "$HOME/.claude/.safeguard"
}

@test "uninstall preserves user hooks" {
    echo '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-hook","timeout":5}]}]}}' > "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    "$UNINSTALL_BIN" > /dev/null
    run jq -r '.hooks.PreToolUse[].hooks[].command // empty' "$HOME/.claude/settings.json"
    assert_output --partial "my-hook"
}

@test "uninstall handles missing settings.json gracefully" {
    rm -f "$HOME/.claude/settings.json"
    run "$UNINSTALL_BIN"
    assert_success
}

@test "uninstall shows backup info" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    run "$UNINSTALL_BIN"
    assert_success
    assert_output --partial "agent-safe-guard uninstalled."
}

# ==============================================================================
# INSTALL ERROR PATHS
# ==============================================================================

@test "install fails on invalid settings.json" {
    echo 'not valid json{{{' > "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    run install_with_full_native_bins "$native_bin_dir"
    assert_failure
    assert_output --partial "failed to update settings.json"
}

@test "install without existing settings.json creates empty base" {
    rm -f "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    run install_with_full_native_bins "$native_bin_dir"
    assert_success
    assert_exist "$HOME/.claude/settings.json"
    run jq -r '.hooks | keys | length' "$HOME/.claude/settings.json"
    assert_success
}

# ==============================================================================
# UNINSTALL ADDITIONAL PATHS
# ==============================================================================

@test "install handles merge producing invalid JSON" {
    # Create a valid settings.json so install proceeds to merge
    echo '{}' > "$HOME/.claude/settings.json"
    local native_bin_dir="$TEST_TEMP/native-bin"
    create_full_native_bin_dir "$native_bin_dir"
    # Create a broken jq wrapper that outputs garbage for the merge step
    # but works for validation (jq empty) and other calls
    local mock_dir="$TEST_TEMP/jq-mock"
    mkdir -p "$mock_dir"
    local real_jq
    real_jq="$(command -v jq)"
    cat > "$mock_dir/jq" << MOCK
#!/bin/bash
# If this is the merge operation (--argjson + reduce), output garbage
if [[ "\$*" == *"argjson"* && "\$*" == *"reduce"* ]]; then
    echo "NOT_VALID_JSON{{{"
    exit 0
fi
exec "$real_jq" "\$@"
MOCK
    chmod +x "$mock_dir/jq"
    run env PATH="$mock_dir:$PATH" "$INSTALL_BIN" --native --native-bin-dir "$native_bin_dir" --no-enable-systemd-user
    assert_failure
    assert_output --partial "failed to update settings.json"
}

@test "uninstall handles jq cleanup failure" {
    # Install first
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    # Create a mock jq that outputs garbage for the cleanup filter
    local mock_dir="$TEST_TEMP/jq-mock-uninst"
    mkdir -p "$mock_dir"
    local real_jq
    real_jq="$(command -v jq)"
    cat > "$mock_dir/jq" << MOCK
#!/bin/bash
# If cleaning settings.json (the complex filter), produce garbage stdout
if [[ "\$*" == *"sg-"* && "\$*" == *"select"* ]]; then
    echo "BROKEN{{{"
    exit 0
fi
exec "$real_jq" "\$@"
MOCK
    chmod +x "$mock_dir/jq"
    run env PATH="$mock_dir:$PATH" "$UNINSTALL_BIN"
    assert_success
    assert_output --partial "Failed to clean"
}

@test "uninstall with no backup files shows no backup info" {
    local native_bin_dir="$TEST_TEMP/native-bin"
    install_with_full_native_bins "$native_bin_dir" > /dev/null
    rm -f "$HOME/.claude/settings.json.bak."*
    run "$UNINSTALL_BIN"
    assert_success
    refute_output --partial "Recent backups"
}
