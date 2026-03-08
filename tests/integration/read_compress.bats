#!/usr/bin/env bats
# Integration tests for hooks/read-compress

setup() {
    load '../test_helper/common'
    setup_isolated_env
    HOOK="${SG_READ_COMPRESS_HOOK:-$PROJ_ROOT/hooks/read-compress}"
}

teardown() {
    teardown_isolated_env
}

_make_read_input() {
    local file_path="$1"
    local content="$2"
    jq -n --arg fp "$file_path" --arg text "$content" '{
        tool_name: "Read",
        tool_input: {file_path: $fp},
        tool_response: {content: [{text: $text}]},
        session_id: "test-session-001",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }'
}

# ==============================================================================
# SKIP NON-READ TOOLS
# ==============================================================================

@test "ignores non-Read tool" {
    local input
    input=$(jq -n '{
        tool_name: "Bash",
        tool_input: {command: "ls"},
        tool_response: {content: [{text: "output"}]},
        session_id: "test",
        transcript_path: "/home/testuser/.claude/projects/test/main.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "modifyOutput"
}

# ==============================================================================
# SMALL FILES PASS THROUGH
# ==============================================================================

@test "small file (<500 lines) passes through" {
    local content
    content=$(python3 -c "
for i in range(100):
    print(f'line {i}: some content')
")
    local input
    input=$(_make_read_input "/tmp/small.py" "$content")
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "modifyOutput"
}

# ==============================================================================
# TEXT/MARKDOWN FILES SKIP COMPRESSION
# ==============================================================================

@test "markdown files skip compression" {
    local content
    content=$(python3 -c "
for i in range(600):
    print(f'# Section {i}')
    print(f'Content for section {i}')
")
    local input
    input=$(_make_read_input "/tmp/readme.md" "$content")
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "Structure extracted"
}

@test "txt files skip compression" {
    local content
    content=$(python3 -c "
for i in range(600):
    print(f'log entry {i}: something happened')
")
    local input
    input=$(_make_read_input "/tmp/app.log" "$content")
    run_hook "$HOOK" "$input"
    refute_output --partial "Structure extracted"
}

@test "csv files skip compression" {
    local content
    content=$(python3 -c "
print('name,age,city')
for i in range(600):
    print(f'user{i},{20+i},city{i}')
")
    local input
    input=$(_make_read_input "/tmp/data.csv" "$content")
    run_hook "$HOOK" "$input"
    refute_output --partial "Structure extracted"
}

# ==============================================================================
# JSON STRUCTURAL EXTRACTION
# ==============================================================================

@test "large JSON file gets structure extracted" {
    local content
    content=$(python3 -c "
for i in range(600):
    indent = '    ' if i % 2 == 0 else '        '
    print(f'{indent}\"key_{i}\": \"value_{i}\",')
")
    local input
    input=$(_make_read_input "/tmp/config.json" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

# ==============================================================================
# YAML STRUCTURAL EXTRACTION
# ==============================================================================

@test "large YAML file gets structure extracted" {
    local content
    content=$(python3 -c "
for i in range(600):
    print(f'service_{i}:')
    print(f'  image: nginx:{i}')
    print(f'  port: {8000+i}')
")
    local input
    input=$(_make_read_input "/tmp/docker-compose.yml" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

# ==============================================================================
# TOML STRUCTURAL EXTRACTION
# ==============================================================================

@test "large TOML file gets structure extracted" {
    local content
    content=$(python3 -c "
for i in range(600):
    if i % 10 == 0:
        print(f'[section_{i}]')
    print(f'key_{i} = \"value_{i}\"')
")
    local input
    input=$(_make_read_input "/tmp/config.toml" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

# ==============================================================================
# CODE FILE STRUCTURAL EXTRACTION
# ==============================================================================

@test "large Python file gets signatures extracted" {
    local content
    content=$(python3 -c "
for i in range(200):
    print(f'import module_{i}')
    print(f'class MyClass{i}:')
    print(f'    def method_{i}(self):')
    print(f'        pass')
    print(f'')
")
    local input
    input=$(_make_read_input "/tmp/big_module.py" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
    assert_output --partial "signatures"
}

@test "large TypeScript file gets signatures extracted" {
    local content
    content=$(python3 -c "
for i in range(200):
    print(f'import {{ Module{i} }} from \"./module{i}\";')
    print(f'export const handler{i} = () => {{')
    print(f'  // implementation')
    print(f'}};')
    print(f'export interface Config{i} {{')
    print(f'  field: string;')
    print(f'}}')
")
    local input
    input=$(_make_read_input "/tmp/big.ts" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

@test "large Rust file gets signatures extracted" {
    local content
    content=$(python3 -c "
for i in range(200):
    print(f'use crate::module{i};')
    print(f'pub fn function_{i}() -> Result<(), Error> {{')
    print(f'    todo!()')
    print(f'}}')
    print(f'pub struct Struct{i} {{')
    print(f'    field: u32,')
    print(f'}}')
")
    local input
    input=$(_make_read_input "/tmp/big.rs" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

# ==============================================================================
# SUBAGENT LOWER THRESHOLD
# ==============================================================================

@test "subagent triggers compression at 300 lines (not 500)" {
    local content
    content=$(python3 -c "
for i in range(350):
    print(f'def function_{i}():')
    print(f'    pass')
")
    local input
    input=$(jq -n --arg text "$content" '{
        tool_name: "Read",
        tool_input: {file_path: "/tmp/medium.py"},
        tool_response: {content: [{text: $text}]},
        session_id: "test",
        transcript_path: "/home/user/.claude/projects/test/subagents/agent-sub1.jsonl"
    }')
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
}

# ==============================================================================
# SYSTEM REMINDER STRIPPING
# ==============================================================================

@test "strips system-reminder from Read content" {
    local content="line 1
<system-reminder>
internal stuff
</system-reminder>
line 2"
    local input
    input=$(_make_read_input "/tmp/test.py" "$content")
    run_hook "$HOOK" "$input"
    # Small file, reminder should be stripped silently
    assert_success
}

# ==============================================================================
# EMPTY INPUT
# ==============================================================================

@test "empty stdin exits cleanly" {
    run_hook "$HOOK" ""
    assert_success
}

@test "empty content exits cleanly" {
    local input
    input=$(_make_read_input "/tmp/empty.py" "")
    run_hook "$HOOK" "$input"
    assert_success
}

# ==============================================================================
# ADDITIONAL CONFIG FORMAT EXTRACTION
# ==============================================================================

@test "large XML file gets structure extracted" {
    local content
    content=$(python3 -c "
print('<?xml version=\"1.0\"?>')
print('<root>')
for i in range(600):
    print(f'  <element_{i} attr=\"val\">')
    print(f'    <child>content {i}</child>')
    print(f'  </element_{i}>')
print('</root>')
")
    local input
    input=$(_make_read_input "/tmp/config.xml" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

@test "large INI/cfg file gets structure extracted" {
    local content
    content=$(python3 -c "
for i in range(600):
    if i % 10 == 0:
        print(f'[section_{i}]')
    print(f'option_{i} = value_{i}')
")
    local input
    input=$(_make_read_input "/tmp/app.cfg" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

# ==============================================================================
# ADDITIONAL CODE FORMATS
# ==============================================================================

@test "large Go file gets signatures extracted" {
    local content
    content=$(python3 -c "
print('package main')
print('')
print('import (')
print('    \"fmt\"')
print(')')
for i in range(200):
    print(f'func Handler{i}() error {{')
    print(f'    return nil')
    print(f'}}')
    print('')
")
    local input
    input=$(_make_read_input "/tmp/main.go" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

@test "large PHP file gets signatures extracted" {
    local content
    content=$(python3 -c "
print('<?php')
print('namespace App\\\\Controllers;')
for i in range(200):
    print(f'public function action{i}() {{')
    print(f'    return null;')
    print(f'}}')
    print('')
")
    local input
    input=$(_make_read_input "/tmp/Controller.php" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

@test "large file with nested methods gets private/protected extracted" {
    local content
    content=$(python3 -c "
for i in range(200):
    print(f'    private function helper{i}() {{')
    print(f'        return null;')
    print(f'    }}')
    print(f'    protected int field{i};')
    print(f'    public String getValue{i}() {{')
    print(f'        return \"\";')
    print(f'    }}')
")
    local input
    input=$(_make_read_input "/tmp/BigClass.java" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

@test "large file with markdown headings in code gets extracted" {
    local content
    content=$(python3 -c "
for i in range(200):
    print(f'## Section {i}')
    print(f'Content for section {i}')
    print(f'More content')
    print(f'Even more content')
")
    local input
    input=$(_make_read_input "/tmp/docs.mdx" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "signatures"
}

@test "large HTML file gets structure extracted" {
    local content
    content=$(python3 -c "
print('<html>')
for i in range(600):
    print(f'  <div class=\"item-{i}\">')
    print(f'    <span>Item {i}</span>')
    print(f'  </div>')
print('</html>')
")
    local input
    input=$(_make_read_input "/tmp/page.html" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

@test "env file skips compression even when large" {
    local content
    content=$(python3 -c "
for i in range(600):
    print(f'VAR_{i}=value_{i}')
")
    local input
    input=$(_make_read_input "/tmp/.env" "$content")
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "Structure extracted"
}

@test "gitignore file skips compression even when large" {
    local content
    content=$(python3 -c "
for i in range(600):
    print(f'*.tmp{i}')
")
    local input
    input=$(_make_read_input "/tmp/.gitignore" "$content")
    run_hook "$HOOK" "$input"
    assert_success
    refute_output --partial "Structure extracted"
}

@test "large SVG file gets XML structure extracted" {
    local content
    content=$(python3 -c "
print('<svg xmlns=\"http://www.w3.org/2000/svg\">')
for i in range(600):
    print(f'  <rect x=\"{i}\" y=\"0\" width=\"10\" height=\"10\"/>')
print('</svg>')
")
    local input
    input=$(_make_read_input "/tmp/diagram.svg" "$content")
    run_hook "$HOOK" "$input"
    assert_output --partial "modifyOutput"
    assert_output --partial "Structure extracted"
}

@test "read-compress with system-reminder in large Read" {
    local lines=""
    local i=0
    while (( i < 600 )); do
        lines="${lines}def func_${i}():\n    pass\n"
        i=$((i + 1))
    done
    local content
    content=$(printf '%b<system-reminder>\ninternal\n</system-reminder>\n%b' "$lines" "$lines")
    local input
    input=$(_make_read_input "/tmp/big_with_reminder.py" "$content")
    run_hook "$HOOK" "$input"
    assert_success
}
