#!/usr/bin/env bash
# claude-safe-guard shared library
# Source this at the top of hooks for common utilities

# ==============================================================================
# ENVIRONMENT SETUP
# ==============================================================================

export SG_STATE_DIR="${SG_STATE_DIR:-$HOME/.claude/.statusline}"
export SG_SESSION_BUDGET_DIR="${SG_SESSION_BUDGET_DIR:-$HOME/.claude/.session-budgets}"
export SG_SUBAGENT_STATE_DIR="${SG_SUBAGENT_STATE_DIR:-$HOME/.claude/.subagent-state}"
export SG_EVENTS_FILE="$SG_STATE_DIR/events.jsonl"

# ==============================================================================
# DATE HELPERS (Linux-only)
# ==============================================================================

_sg_date_ns()  { date +%s%N; }
_sg_date_sns() { date +%s.%N; }
_sg_date_iso() { date -Iseconds; }

# Session start timestamp (cached)
if [[ -f "$SG_STATE_DIR/.session_start" ]]; then
    _SG_SESSION_START_NS=$(cat "$SG_STATE_DIR/.session_start" 2>/dev/null)
    if [[ "$_SG_SESSION_START_NS" == *.* ]]; then
        _SG_SESSION_START_S=$(cut -d. -f1 <<< "$_SG_SESSION_START_NS")
    else
        _SG_SESSION_START_S="$_SG_SESSION_START_NS"
    fi
else
    _SG_SESSION_START_S=$(date +%s)
fi
export _SG_SESSION_START_S

export _SG_NOW_S=$(date +%s)
export _SG_NOW_NS=$(_sg_date_sns)

# ==============================================================================
# CONFIG
# ==============================================================================

_SG_CONFIG_ENV="${HOME}/.claude/.safeguard/config.env"
if [[ -f "$_SG_CONFIG_ENV" ]]; then
    if bash -n "$_SG_CONFIG_ENV" 2>/dev/null; then
        source "$_SG_CONFIG_ENV"
    else
        printf 'safeguard: warning: invalid config syntax in "%s"; using defaults\n' "$_SG_CONFIG_ENV" >&2
    fi
fi

export SG_TRUNCATE_BYTES=${SG_TRUNCATE_BYTES:-20480}
export SG_SUBAGENT_READ_BYTES=${SG_SUBAGENT_READ_BYTES:-10240}
export SG_SUPPRESS_BYTES=${SG_SUPPRESS_BYTES:-524288}
export SG_READ_GUARD_MAX_MB=${SG_READ_GUARD_MAX_MB:-2}
export SG_WRITE_MAX_BYTES=${SG_WRITE_MAX_BYTES:-102400}
export SG_EDIT_MAX_BYTES=${SG_EDIT_MAX_BYTES:-51200}
export SG_NOTEBOOK_MAX_BYTES=${SG_NOTEBOOK_MAX_BYTES:-51200}
export SG_DEFAULT_CALL_LIMIT=${SG_DEFAULT_CALL_LIMIT:-30}
export SG_DEFAULT_BYTE_LIMIT=${SG_DEFAULT_BYTE_LIMIT:-102400}
export SG_BUDGET_TOTAL=${SG_BUDGET_TOTAL:-280000}

# ==============================================================================
# ATOMIC LOCKING (mkdir-based, fixes _warden_with_lock undefined bug)
# ==============================================================================

_sg_with_lock() {
    local lockdir="$1"
    local callback="$2"
    local i=0
    while ! mkdir "$lockdir" 2>/dev/null; do
        ((i++))
        if ((i > 50)); then
            # Stale lock after 5s - force remove and retry
            rm -rf "$lockdir" 2>/dev/null
            mkdir "$lockdir" 2>/dev/null || return 1
            break
        fi
        sleep 0.1
    done
    "$callback"
    rm -rf "$lockdir" 2>/dev/null
}

# ==============================================================================
# BUDGET TRACKER
# ==============================================================================

SG_BUDGET_STATE="${HOME}/.claude/.safeguard/budget.state"
SG_BUDGET_CACHE="$SG_STATE_DIR/budget-export"

_sg_budget_read() {
    [[ -f "$SG_BUDGET_STATE" ]] || { echo 0; return; }
    local val
    val=$(<"$SG_BUDGET_STATE")
    [[ "$val" =~ ^[0-9]+$ ]] && echo "$val" || echo 0
}

_sg_budget_write() {
    mkdir -p "$(dirname "$SG_BUDGET_STATE")"
    printf '%d' "$1" > "$SG_BUDGET_STATE"
}

_sg_budget_update() {
    local tokens="${1:-0}"
    [[ "$tokens" =~ ^[0-9]+$ ]] || return 0
    (( tokens == 0 )) && return 0
    local consumed
    consumed=$(_sg_budget_read)
    consumed=$((consumed + tokens))
    _sg_budget_write "$consumed"
}

_sg_budget_check() {
    local consumed
    consumed=$(_sg_budget_read)
    (( consumed < SG_BUDGET_TOTAL ))
}

_sg_budget_export() {
    local consumed total util
    consumed=$(_sg_budget_read)
    total="$SG_BUDGET_TOTAL"
    util=0
    (( total > 0 )) && util=$((consumed * 100 / total))
    local json
    json=$(printf '{"consumed":%d,"limit":%d,"total_limit":%d,"utilization":%d}' \
        "$consumed" "$total" "$total" "$util")
    echo "$json"
    mkdir -p "$(dirname "$SG_BUDGET_CACHE")"
    printf '%s' "$json" > "$SG_BUDGET_CACHE" 2>/dev/null || true
}

_sg_budget_reset() {
    _sg_budget_write 0
}

# ==============================================================================
# SUBAGENT LIMIT LOOKUPS
# ==============================================================================

_sg_call_limit() {
    local type="${1//-/_}"
    local var="SG_CALL_LIMIT_${type}"
    echo "${!var:-$SG_DEFAULT_CALL_LIMIT}"
}

_sg_byte_limit() {
    local type="${1//-/_}"
    local var="SG_BYTE_LIMIT_${type}"
    echo "${!var:-$SG_DEFAULT_BYTE_LIMIT}"
}

# ==============================================================================
# INPUT PARSING
# ==============================================================================

_sg_read_input() {
    read -r -t 5 -d '' SG_INPUT || true
    export SG_INPUT
    [[ -z "$SG_INPUT" ]] && return 1
    return 0
}

_sg_parse_toplevel() {
    local field="$1"
    local value=""
    if [[ "$SG_INPUT" =~ \"$field\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    printf '%s' "$value"
}

_sg_parse_tool_name() {
    _sg_parse_toplevel "tool_name"
}

_sg_parse_session_id() {
    _sg_parse_toplevel "session_id"
}

_sg_parse_transcript_path() {
    _sg_parse_toplevel "transcript_path"
}

_sg_parse_tool_input() {
    local -a fields=("$@")
    local jq_expr='['
    for field in "${fields[@]}"; do
        jq_expr+=".tool_input.$field // \"\", "
    done
    jq_expr="${jq_expr%, }] | @tsv"
    printf '%s' "$SG_INPUT" | jq -r "$jq_expr" 2>/dev/null
}

# ==============================================================================
# ID SANITIZATION
# ==============================================================================

_sg_sanitize_id() {
    local id="$1"
    if [[ "$id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        printf '%s' "$id"
    fi
}

# ==============================================================================
# SUBAGENT DETECTION
# ==============================================================================

_sg_is_subagent() {
    local transcript_path="$1"
    [[ "$transcript_path" == *"/subagents/"* || "$transcript_path" == *"/tmp/"* ]]
}

_sg_get_agent_id() {
    local transcript_path="$1"
    local agent_id=""
    if [[ "$transcript_path" == *"/subagents/"* ]]; then
        agent_id=$(basename "$transcript_path" .jsonl | sed 's/^agent-//')
        agent_id=$(_sg_sanitize_id "$agent_id")
    fi
    printf '%s' "$agent_id"
}

_sg_get_agent_type() {
    local agent_id="$1"
    local agent_type=""
    if [[ -n "$agent_id" && -f "$SG_SUBAGENT_STATE_DIR/$agent_id" ]]; then
        agent_type=$(grep '^AGENT_TYPE=' "$SG_SUBAGENT_STATE_DIR/$agent_id" 2>/dev/null | head -1 | cut -d= -f2)
    fi
    printf '%s' "$agent_type"
}

# ==============================================================================
# EVENT EMISSION
# ==============================================================================

_sg_scrub_secrets() {
    sed -E \
        's/(-H|--header) +[^ ]+/\1 [REDACTED]/g;
         s/(Bearer |Authorization: ?)[^ ]+/\1[REDACTED]/gi;
         s/([a-zA-Z_]*(key|secret|token|password|credential|api_key|database_url|client_id|client_secret|access_token|refresh_token)[a-zA-Z_]*)=[^ ]+/\1=[REDACTED]/gi;
         s/(ghp_|github_pat_|sk-|gho_|glpat-|xox[bpsa]-)[^ ]+/[REDACTED]/g'
}

_sg_maybe_scrub() {
    local _varname=$1
    local _val="${!_varname}"
    local _prev_nocasematch
    _prev_nocasematch=$(shopt -p nocasematch 2>/dev/null || true)
    shopt -s nocasematch
    if [[ "$_val" =~ (-H|--header|bearer|authorization|token|key=|secret=|password=|credential=|database_url=|client_id=|client_secret=|access_token=|ghp_|github_pat_|sk-|gho_|glpat-|xox[bpsa]-) ]]; then
        printf -v "$_varname" '%s' "$(printf '%s' "$_val" | _sg_scrub_secrets)"
    fi
    eval "$_prev_nocasematch" 2>/dev/null || true
}

_sg_emit_block() {
    local rule="$1" tokens="$2" cmd_override="${3:-}"
    local ts=$((_SG_NOW_S - _SG_SESSION_START_S))
    local cmd_safe="${cmd_override:-${SG_COMMAND:0:200}}"
    cmd_safe="${cmd_safe//$'\n'/ }"
    cmd_safe="${cmd_safe//\\/\\\\}"
    cmd_safe="${cmd_safe//\"/\\\"}"
    _sg_maybe_scrub cmd_safe
    printf '{"timestamp":%d,"event_type":"blocked","tool":"%s","session_id":"%s","original_cmd":"%s","rule":"%s","tokens_saved":%d}\n' \
        "$ts" "${SG_TOOL_NAME:-unknown}" "${SG_SESSION_ID:-}" "$cmd_safe" "$rule" "$tokens" \
        >> "$SG_EVENTS_FILE" 2>/dev/null
}

_sg_emit_event() {
    local etype="$1" orig_bytes="$2" final_bytes="$3" rule="${4:-}"
    local saved=$(( (orig_bytes - final_bytes) * 10 / 35 ))
    (( saved < 0 )) && saved=0
    local ts=$((_SG_NOW_S - _SG_SESSION_START_S))
    local rule_field=""
    [[ -n "$rule" ]] && rule_field="$(printf ',"rule":"%s"' "$rule")"
    local cmd_safe="${SG_COMMAND:0:200}"
    cmd_safe="${cmd_safe//$'\n'/ }"
    cmd_safe="${cmd_safe//\\/\\\\}"
    cmd_safe="${cmd_safe//\"/\\\"}"
    _sg_maybe_scrub cmd_safe
    printf '{"timestamp":%d,"event_type":"%s","tool":"%s","session_id":"%s","original_cmd":"%s","tokens_saved":%d,"original_output_bytes":%d,"final_output_bytes":%d%s}\n' \
        "$ts" "$etype" "${SG_TOOL_NAME:-unknown}" "${SG_SESSION_ID:-}" "$cmd_safe" "$saved" "$orig_bytes" "$final_bytes" "$rule_field" \
        >> "$SG_EVENTS_FILE" 2>/dev/null
}

_sg_emit_output_size() {
    local tool_name="$1" output_bytes="$2" output_lines="${3:-0}" cmd="${4:-}"
    local ts=$((_SG_NOW_S - _SG_SESSION_START_S))
    local estimated_tokens=$(( output_bytes * 10 / 35 ))
    local cmd_safe="${cmd:0:200}"
    cmd_safe="${cmd_safe//$'\n'/ }"
    cmd_safe="${cmd_safe//\\/\\\\}"
    cmd_safe="${cmd_safe//\"/\\\"}"
    _sg_maybe_scrub cmd_safe
    printf '{"timestamp":%d,"event_type":"tool_output_size","tool":"%s","session_id":"%s","output_bytes":%d,"output_lines":%d,"estimated_tokens":%d,"original_cmd":"%s"}\n' \
        "$ts" "$tool_name" "${SG_SESSION_ID:-}" "$output_bytes" "$output_lines" "$estimated_tokens" "$cmd_safe" \
        >> "$SG_EVENTS_FILE" 2>/dev/null
}

# ==============================================================================
# SYSTEM REMINDER STRIPPING
# ==============================================================================

_sg_strip_reminders() {
    local text_ref="${!1}"
    local cleaned
    cleaned=$(printf '%s' "${text_ref}" | sed '/^<system-reminder>/,/^<\/system-reminder>/d')
    cleaned=$(printf '%s' "$cleaned" | awk 'NF{found=NR} {a[NR]=$0} END{for(i=1;i<=found;i++)print a[i]}')
    printf '%s' "$cleaned"
}

# ==============================================================================
# FILE UTILITIES
# ==============================================================================

_sg_stat_mtime() {
    stat -c%Y "$1" 2>/dev/null || echo 0
}

# ==============================================================================
# NOTIFICATIONS
# ==============================================================================

_sg_notify() {
    local urgency="$1" title="$2" body="$3"
    if command -v notify-send &>/dev/null; then
        notify-send -u "$urgency" "$title" "$body"
    fi
}

# ==============================================================================
# HOOK OUTPUT HELPERS
# ==============================================================================

_sg_suppress_ok() {
    echo '{"suppressOutput":true}'
    exit 0
}

_sg_deny() {
    local reason="$1"
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
    exit 0
}

# ==============================================================================
# INLINE VALIDATIONS
# ==============================================================================

_sg_check_secrets() {
    local response="$1"
    local secret_patterns='(AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.eyJ|-----BEGIN .* PRIVATE KEY-----|api[_-]?key.*=.*[a-zA-Z0-9]{20,})'
    if printf '%s' "$response" | grep -qiE "$secret_patterns"; then
        return 0
    fi
    return 1
}

_sg_validate_readonly() {
    local command="$1"
    local write_patterns='(\brm\b|\brmdir\b|\bmv\b|\bcp\b|(^|[^-])>|>>|\btee\b|sed -i|\bchmod\b|\bchown\b|\btruncate\b|\bdd\b|\binstall\b|rsync.*--delete|\bpatch\b|git checkout -- |git restore|\bunlink\b|\bshred\b|\btouch\b|\bln\b|\bmkdir\b)'
    if printf '%s' "$command" | grep -qiE "$write_patterns"; then
        return 1
    fi
    return 0
}

_sg_validate_git() {
    local command="$1"
    if printf '%s' "$command" | grep -qiE '(git push.*--force|git push.*-f|git reset --hard|git clean -fd|git clean -f)'; then
        if printf '%s' "$command" | grep -qiE '(main|master|origin)'; then
            echo "Blocked: Force push/reset to main/master requires explicit user approval" >&2
            return 1
        fi
    fi
    if printf '%s' "$command" | grep -qiE 'git config'; then
        if printf '%s' "$command" | grep -qiE '(--get|--get-all|--list|-l|--show-origin)'; then
            return 0
        elif printf '%s' "$command" | grep -qiE '(user\.|email|name|credential)'; then
            echo "Blocked: Git config writes not allowed" >&2
            return 1
        fi
    fi
    return 0
}

# ==============================================================================
# TOOL LATENCY TRACKING
# ==============================================================================

_sg_record_tool_start() {
    local tool_name="$1"
    [[ -z "$tool_name" ]] && return
    mkdir -p "$SG_STATE_DIR"
    _sg_date_ns > "$SG_STATE_DIR/.tool-start-${tool_name}-$$" 2>/dev/null
}

_sg_compute_tool_latency() {
    local tool_name="$1"
    SG_TOOL_LATENCY_MS=""
    SG_TOOL_START_NS=""
    SG_TOOL_END_NS=""
    local start_file="" newest_file="" newest_mtime=0
    for f in "$SG_STATE_DIR"/.tool-start-"${tool_name}"-*; do
        [[ -f "$f" ]] || continue
        local mtime
        mtime=$(_sg_stat_mtime "$f")
        if (( mtime > newest_mtime )); then
            newest_mtime=$mtime
            newest_file="$f"
        fi
    done
    start_file="$newest_file"
    [[ -z "$start_file" || ! -f "$start_file" ]] && return 1
    SG_TOOL_START_NS=$(cat "$start_file" 2>/dev/null)
    rm -f "$start_file" 2>/dev/null
    [[ ! "$SG_TOOL_START_NS" =~ ^[0-9]+$ ]] && return 1
    SG_TOOL_END_NS=$(_sg_date_ns)
    local delta_ns=$(( SG_TOOL_END_NS - SG_TOOL_START_NS ))
    SG_TOOL_LATENCY_MS=$(( delta_ns / 1000000 ))
    if (( SG_TOOL_LATENCY_MS < 0 || SG_TOOL_LATENCY_MS > 600000 )); then
        SG_TOOL_LATENCY_MS=""
        return 1
    fi
    export SG_TOOL_LATENCY_MS SG_TOOL_START_NS SG_TOOL_END_NS
    return 0
}

_sg_emit_latency() {
    local tool_name="$1" latency_ms="$2" cmd="${3:-}"
    local ts=$((_SG_NOW_S - _SG_SESSION_START_S))
    local cmd_safe="${cmd:0:200}"
    cmd_safe="${cmd_safe//$'\n'/ }"
    cmd_safe="${cmd_safe//\\/\\\\}"
    cmd_safe="${cmd_safe//\"/\\\"}"
    _sg_maybe_scrub cmd_safe
    printf '{"timestamp":%d,"event_type":"tool_latency","tool":"%s","session_id":"%s","duration_ms":%d,"original_cmd":"%s"}\n' \
        "$ts" "$tool_name" "${SG_SESSION_ID:-}" "$latency_ms" "$cmd_safe" \
        >> "$SG_EVENTS_FILE" 2>/dev/null
}
