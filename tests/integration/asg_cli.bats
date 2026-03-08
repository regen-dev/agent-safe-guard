#!/usr/bin/env bats
# Integration tests for asg-cli

setup() {
    load '../test_helper/common'
    setup_isolated_env
    CLI_BIN="$PROJ_ROOT/build/native/native/asg-cli"
    if [[ ! -x "$CLI_BIN" ]]; then
        cmake -S "$PROJ_ROOT" -B "$PROJ_ROOT/build/native" -DSG_BUILD_NATIVE=ON >/dev/null
        cmake --build "$PROJ_ROOT/build/native" --target asg-cli -j >/dev/null
    fi
    FEATURES_FILE="$HOME/.claude/.safeguard/features.env"
}

teardown() {
    teardown_isolated_env
}

make_catalog_fixture() {
    local fixture_dir="$1"
    local core_dir="$fixture_dir/core"
    local catalogs_dir="$fixture_dir/catalogs"
    local manifest="$core_dir/vendor-shell-pack.json"
    local catalog="$catalogs_dir/github-core.json"
    mkdir -p "$core_dir" "$catalogs_dir"

    cat > "$manifest" <<'EOF'
{"version":"0.1.0","package":"vendor-shell-pack","title":"Vendor Shell Pack","summary":"Local vendor rules","category":"vendor","rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}
EOF

    local manifest_sha
    manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')

    cat > "$catalog" <<EOF
{"catalog_version":1,"catalog_id":"github-core","display_name":"GitHub Core Catalog","packages":[{"package_id":"vendor-shell-pack","package_version":"0.1.0","display_name":"Vendor Shell Pack","description":"Local vendor rules","download_url":"../core/vendor-shell-pack.json","sha256":"$manifest_sha","tags":["vendor","shell"],"phases":["pre_tool_use"],"rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}]}
EOF

    echo "$catalog"
}

@test "asg-cli --print shows feature list" {
    run "$CLI_BIN" --print --features-file "$FEATURES_FILE"
    assert_success
    assert_output --partial "asg-cli features file:"
    assert_output --partial "Command Firewall"
    assert_output --partial "PreToolUse"
    assert_output --partial "StatusLine"
}

@test "asg-cli --set persists a feature toggle" {
    run "$CLI_BIN" --set SG_FEATURE_STATUSLINE=1 --features-file "$FEATURES_FILE"
    assert_success
    run grep '^SG_FEATURE_STATUSLINE=1$' "$FEATURES_FILE"
    assert_success
}

@test "asg-cli --print-rules shows package and rule catalog" {
    run "$CLI_BIN" --print-rules
    assert_success
    assert_output --partial "asg-cli policy dir:"
    assert_output --partial "Command Defense"
    assert_output --partial "Output Defense"
    assert_output --partial "100200 destructive_command"
    assert_output --partial "250100 post_tool_use_pipeline"
    assert_output --partial "Approval Defense"
    assert_output --partial "Telemetry"
    assert_output --partial "400120 stop_summary_emit"
    assert_output --partial "Memory Defense"
    assert_output --partial "350100 pre_compact_memory_context"
}

@test "asg-cli --catalog-list scaffolds the default first-party catalog" {
    run "$CLI_BIN" --catalog-list
    assert_success
    assert_output --partial "GitHub Core Catalog"
    assert_output --partial "raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/rules-v0.2.0/rules/catalogs/github-core.json"
}

@test "asg-cli default catalog scaffold can be overridden by env before first run" {
    local custom_catalog="$TEST_TEMP/custom-catalog.json"

    run env SG_DEFAULT_CATALOG_URL="$custom_catalog" "$CLI_BIN" --catalog-list
    assert_success
    assert_output --partial "$custom_catalog"

    run jq -r '.catalogs[0].source_url' "$HOME/.claude/.safeguard/policy/catalogs.json"
    assert_success
    assert_output "$custom_catalog"
}

@test "asg-cli --print-rules loads external package manifests" {
    local rules_dir="$TEST_TEMP/rules"
    mkdir -p "$rules_dir"
    cat > "$rules_dir/command-defense.json" <<'EOF'
{"version":"0.1.0","package":"command-defense","title":"Curated Command Pack","summary":"External catalog metadata","category":"core","rules":[{"rule_id":100200,"name":"destructive_command","phase":"pre_tool_use","severity":"critical"}]}
EOF

    run "$CLI_BIN" --print-rules --rules-dir "$rules_dir"
    assert_success
    assert_output --partial "Curated Command Pack (command-defense)"
    assert_output --partial "100200 destructive_command"
}

@test "asg-cli --set-package persists package mode in policy state" {
    run "$CLI_BIN" --set-package command-defense=detection_only
    assert_success
    assert_output --partial "[DET ] Command Defense"

    run jq -r '.packages[] | select(.package=="command-defense") | .mode' \
        "$HOME/.claude/.safeguard/policy/packages.json"
    assert_success
    assert_output "detection_only"
}

@test "asg-cli --set-rule persists rule override in policy state" {
    run "$CLI_BIN" --set-rule 100200=off
    assert_success
    assert_output --partial "[OFF ] 100200 destructive_command"

    run jq -r '.packages[] | select(.package=="command-defense") | .rules[] | select(.rule_id==100200) | .mode' \
        "$HOME/.claude/.safeguard/policy/packages.json"
    assert_success
    assert_output "off"
}

@test "asg-cli --install-package installs manifest and records provenance" {
    local manifest="$TEST_TEMP/vendor-shell-pack.json"
    cat > "$manifest" <<'EOF'
{"version":"0.1.0","package":"vendor-shell-pack","title":"Vendor Shell Pack","summary":"Local vendor rules","category":"vendor","rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}
EOF

    run "$CLI_BIN" --install-package "$manifest"
    assert_success
    assert_output --partial "Vendor Shell Pack (vendor-shell-pack)"

    assert_file_exist "$HOME/.claude/.safeguard/policy/installed/vendor-shell-pack.json"

    run jq -r '.installed[] | select(.package=="vendor-shell-pack") | .source_path' \
        "$HOME/.claude/.safeguard/policy/installed.json"
    assert_success
    assert_output "$manifest"
}

@test "asg-cli --remove-package removes installed manifest and record" {
    local manifest="$TEST_TEMP/vendor-shell-pack.json"
    cat > "$manifest" <<'EOF'
{"version":"0.1.0","package":"vendor-shell-pack","title":"Vendor Shell Pack","summary":"Local vendor rules","category":"vendor","rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}
EOF

    run "$CLI_BIN" --install-package "$manifest"
    assert_success

    run "$CLI_BIN" --remove-package vendor-shell-pack
    assert_success
    refute_output --partial "Vendor Shell Pack (vendor-shell-pack)"

    assert_file_not_exist "$HOME/.claude/.safeguard/policy/installed/vendor-shell-pack.json"
    run jq -e '.installed[] | select(.package=="vendor-shell-pack")' \
        "$HOME/.claude/.safeguard/policy/installed.json"
    assert_failure
}

@test "asg-cli catalog add and sync caches remote catalog metadata" {
    local catalog
    catalog=$(make_catalog_fixture "$TEST_TEMP/catalog-fixture")

    run "$CLI_BIN" --catalog-add "file://$catalog"
    assert_success
    assert_output --partial "asg-cli catalogs file:"

    run jq -r --arg url "file://$catalog" '.catalogs[] | select(.source_url==$url) | .source_url' \
        "$HOME/.claude/.safeguard/policy/catalogs.json"
    assert_success
    assert_output "file://$catalog"

    run "$CLI_BIN" --catalog-sync
    assert_success
    assert_output --partial "GitHub Core Catalog (github-core)"

    local cache_path
    cache_path=$(jq -r --arg url "file://$catalog" '.catalogs[] | select(.source_url==$url) | .cache_path' \
        "$HOME/.claude/.safeguard/policy/catalogs.json")
    assert_file_exist "$cache_path"
}

@test "asg-cli --catalog-search finds package and rule metadata from synced catalogs" {
    local catalog
    catalog=$(make_catalog_fixture "$TEST_TEMP/catalog-fixture")

    run "$CLI_BIN" --catalog-add "file://$catalog"
    assert_success
    run "$CLI_BIN" --catalog-sync
    assert_success

    run "$CLI_BIN" --catalog-search vendor_shell_guard
    assert_success
    assert_output --partial "[github-core] Vendor Shell Pack (vendor-shell-pack)"
    assert_output --partial "rule 910001 vendor_shell_guard"
}

@test "asg-cli --catalog-install installs verified package from synced catalog" {
    local catalog
    catalog=$(make_catalog_fixture "$TEST_TEMP/catalog-fixture")

    run "$CLI_BIN" --catalog-add "file://$catalog"
    assert_success
    run "$CLI_BIN" --catalog-sync
    assert_success

    run "$CLI_BIN" --catalog-install vendor-shell-pack
    assert_success
    assert_output --partial "Vendor Shell Pack (vendor-shell-pack)"

    assert_file_exist "$HOME/.claude/.safeguard/policy/installed/vendor-shell-pack.json"
    run jq -r '.installed[] | select(.package=="vendor-shell-pack") | .catalog_id' \
        "$HOME/.claude/.safeguard/policy/installed.json"
    assert_success
    assert_output "github-core"

    run jq -r '.installed[] | select(.package=="vendor-shell-pack") | .download_url' \
        "$HOME/.claude/.safeguard/policy/installed.json"
    assert_success
    assert_output "file://$TEST_TEMP/catalog-fixture/core/vendor-shell-pack.json"
}

@test "asg-cli local catalog path resolves relative package paths" {
    local catalog
    catalog=$(make_catalog_fixture "$TEST_TEMP/catalog-fixture")

    run "$CLI_BIN" --catalog-add "$catalog"
    assert_success
    run "$CLI_BIN" --catalog-sync
    assert_success
    run "$CLI_BIN" --catalog-install vendor-shell-pack
    assert_success

    run jq -r '.installed[] | select(.package=="vendor-shell-pack") | .download_url' \
        "$HOME/.claude/.safeguard/policy/installed.json"
    assert_success
    assert_output "$TEST_TEMP/catalog-fixture/core/vendor-shell-pack.json"
}

@test "asg-cli --catalog-install rejects package when downloaded manifest drifts from catalog sha256" {
    local fixture_dir="$TEST_TEMP/catalog-bad-sha"
    local manifest="$fixture_dir/vendor-shell-pack.json"
    local catalog="$fixture_dir/catalog.json"
    local manifest_sha=""
    mkdir -p "$fixture_dir"

    cat > "$manifest" <<'EOF'
{"version":"0.1.0","package":"vendor-shell-pack","title":"Vendor Shell Pack","summary":"Local vendor rules","category":"vendor","rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}
EOF
    manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')

    cat > "$catalog" <<EOF
{"catalog_version":1,"catalog_id":"github-core","display_name":"GitHub Core Catalog","source_url":"file://$catalog","packages":[{"package_id":"vendor-shell-pack","package_version":"0.1.0","display_name":"Vendor Shell Pack","description":"Local vendor rules","download_url":"file://$manifest","sha256":"$manifest_sha","tags":["vendor","shell"],"phases":["pre_tool_use"],"rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"low"}]}]}
EOF

    run "$CLI_BIN" --catalog-add "file://$catalog"
    assert_success
    run "$CLI_BIN" --catalog-sync
    assert_success

    cat > "$manifest" <<'EOF'
{"version":"0.1.1","package":"vendor-shell-pack","title":"Vendor Shell Pack","summary":"Mutated vendor rules","category":"vendor","rules":[{"rule_id":910001,"name":"vendor_shell_guard","phase":"pre_tool_use","severity":"medium"}]}
EOF

    run "$CLI_BIN" --catalog-install vendor-shell-pack
    assert_failure
    assert_output --partial "catalog install failed: sha256 mismatch"
    assert_file_not_exist "$HOME/.claude/.safeguard/policy/installed/vendor-shell-pack.json"
}

@test "asg-cli migrates legacy official catalog URL to the tagged bootstrap URL" {
    mkdir -p "$HOME/.claude/.safeguard/policy"
    cat > "$HOME/.claude/.safeguard/policy/catalogs.json" <<'EOF'
{"version":1,"catalogs":[{"catalog_id":"github-core","display_name":"GitHub Core Catalog","source_url":"https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/main/rules/catalogs/github-core.json","cache_path":"/tmp/legacy.json","added_at":1,"last_synced_at":0}]}
EOF

    run "$CLI_BIN" --catalog-list
    assert_success
    assert_output --partial "rules-v0.2.0/rules/catalogs/github-core.json"

    run jq -r '.catalogs[0].source_url' "$HOME/.claude/.safeguard/policy/catalogs.json"
    assert_success
    assert_output "https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/rules-v0.2.0/rules/catalogs/github-core.json"
}

@test "asg-cli rejects invalid local manifest schema" {
    local manifest="$TEST_TEMP/bad-manifest.json"
    cat > "$manifest" <<'EOF'
{"version":"0.1.0","package":"bad-package","rules":[{"rule_id":990001,"name":"bad_rule","phase":"not-a-phase","severity":"low"}]}
EOF

    run "$CLI_BIN" --install-package "$manifest"
    assert_failure
    assert_output --partial "install failed: rule 990001 has invalid phase"
}

@test "asg-cli rejects invalid catalog schema during sync" {
    local fixture_dir="$TEST_TEMP/catalog-invalid-schema"
    local catalog="$fixture_dir/catalog.json"
    mkdir -p "$fixture_dir"

    cat > "$catalog" <<'EOF'
{"catalog_version":1,"catalog_id":"github-core","display_name":"GitHub Core Catalog","packages":[{"package_id":"broken-pack","package_version":"0.1.0","display_name":"Broken Pack","download_url":"file:///tmp/broken.json","sha256":"abcd","phases":["pre_tool_use"],"rules":[{"rule_id":920001,"name":"broken_rule","phase":"pre_tool_use","severity":"low"}]}]}
EOF

    run "$CLI_BIN" --catalog-add "file://$catalog"
    assert_success

    run "$CLI_BIN" --catalog-sync
    assert_failure
    assert_output --partial "catalog sync failed:"
    assert_output --partial "invalid sha256"
}

@test "asg-cli interactive mode fails without tty" {
    run "$CLI_BIN" --features-file "$FEATURES_FILE"
    assert_failure
    assert_output --partial "interactive mode unavailable"
}

@test "asg-cli preserves unknown keys when saving features" {
    mkdir -p "$(dirname "$FEATURES_FILE")"
    cat > "$FEATURES_FILE" <<'EOF'
# custom settings
SG_PACKAGE_COMMAND_DEFENSE=detection_only
SG_FEATURE_STATUSLINE=0
EOF

    run "$CLI_BIN" --set SG_FEATURE_STATUSLINE=1 --features-file "$FEATURES_FILE"
    assert_success

    run grep '^SG_PACKAGE_COMMAND_DEFENSE=detection_only$' "$FEATURES_FILE"
    assert_success
    run grep '^SG_FEATURE_STATUSLINE=1$' "$FEATURES_FILE"
    assert_success
}
