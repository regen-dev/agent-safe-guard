#!/usr/bin/env bash
# Parse PS4 trace output into coverage report
# Usage: parse-coverage.sh <trace-file> <source-dir>

set -euo pipefail

TRACE_FILE="${1:?Usage: parse-coverage.sh <trace-file> <source-dir>}"
SOURCE_DIR="${2:?Usage: parse-coverage.sh <trace-file> <source-dir>}"
SOURCE_DIR=$(cd "$SOURCE_DIR" && pwd)

# Build source file list
declare -a SRC_FILES=()
for src in "$SOURCE_DIR"/hooks/lib/common.sh "$SOURCE_DIR"/hooks/*; do
    [[ -f "$src" && ! -d "$src" ]] && SRC_FILES+=("$src")
done

# Step 1: Extract covered file:line pairs FAST using grep+sed
# Handles +, ++, +++ prefix from nested bash traces
# Pattern: strip leading +'s, capture "filename:lineno" before the trailing ": "
COVERED_TMP=$(mktemp)
trap 'rm -f "$COVERED_TMP"' EXIT

grep -oP '^\++\K[^:]+:[0-9]+(?=: )' "$TRACE_FILE" 2>/dev/null | sort -u > "$COVERED_TMP" || true

# Step 2: Load covered lines into associative array
declare -A COVERED_LINES
while IFS= read -r entry; do
    COVERED_LINES["$entry"]=1
done < "$COVERED_TMP"

COVERED_COUNT=${#COVERED_LINES[@]}
echo "Trace file: $(wc -l < "$TRACE_FILE") raw lines, $COVERED_COUNT unique source:line pairs"

# Step 3: Count coverage per source file
total_lines=0
covered_lines=0

printf "\n%-50s %8s %8s %8s\n" "File" "Total" "Covered" "Pct"
printf "%-50s %8s %8s %8s\n" "$(printf '%0.s-' {1..50})" "--------" "--------" "--------"

for src in "${SRC_FILES[@]}"; do
    bname=$(basename "$src")

    file_total=0
    file_covered=0
    lineno=0
    in_heredoc=0
    heredoc_marker=""
    prev_continued=0
    in_case=0
    in_sq_string=0
    in_array=0
    in_procsub=0       # inside < <(...) process substitution
    in_dq_assign=0     # inside multiline double-quoted assignment
    while IFS= read -r srcline; do
        lineno=$((lineno + 1))

        # Track process substitution continuation: < <( ... )
        # Lines between < <( and the closing ) are never individually traced
        if (( in_procsub )); then
            stripped="${srcline#"${srcline%%[![:space:]]*}"}"
            if [[ "$stripped" == ')'* ]]; then
                in_procsub=0
            fi
            continue
        fi

        # Track multiline double-quoted string assignments
        # Lines inside VAR="...\n...\n..." are never individually traced
        if (( in_dq_assign )); then
            # Count unescaped double quotes to detect string end
            local_stripped="${srcline//\\\"/}"  # remove escaped quotes
            ndq="${local_stripped//[^\"]/}"
            if (( ${#ndq} % 2 == 1 )); then
                in_dq_assign=0
            fi
            continue
        fi

        # Track heredoc content (not bash code, never traced)
        if (( in_heredoc )); then
            stripped="${srcline#"${srcline%%[![:space:]]*}"}"
            if [[ "$stripped" == "$heredoc_marker" || "$stripped" == "${heredoc_marker})" ]]; then
                in_heredoc=0
                heredoc_marker=""
            fi
            continue
        fi
        # Detect heredoc start: <<'MARKER' or <<-'MARKER' or <<MARKER
        if [[ "$srcline" =~ \<\<-?[[:space:]]*[\'\"]?([A-Za-z_][A-Za-z_0-9]*)[\'\"]? ]]; then
            heredoc_marker="${BASH_REMATCH[1]}"
            in_heredoc=1
            # If this is a command substitution assignment with heredoc,
            # bash traces at the end, not the start line
            if [[ "$stripped" == *'=$('*'<<'* ]]; then
                continue
            fi
        fi

        # Track multiline single-quoted strings (jq/awk args never traced)
        if (( in_sq_string )); then
            # Count single quotes to detect string end
            nq="${srcline//[^\']/}"
            if (( ${#nq} % 2 == 1 )); then
                in_sq_string=0
            fi
            continue
        fi

        # Skip blank, comments, pure braces/keywords
        stripped="${srcline#"${srcline%%[![:space:]]*}"}"
        [[ -z "$stripped" ]] && continue
        [[ "$stripped" =~ ^# ]] && continue
        [[ "$stripped" =~ ^(then|else|fi|do|done|esac|\{|\}|\)\;?|\;\;)$ ]] && continue
        # Block redirect closing: } >> file or } > file — never individually traced
        [[ "$stripped" =~ ^\}[[:space:]]*\>+ ]] && continue

        # Skip function definition header lines: funcname() {
        [[ "$stripped" =~ ^[a-zA-Z_][a-zA-Z_0-9]*\(\)[[:space:]]*\{?$ ]] && continue

        # Detect process substitution start: line ends with < <( or contains < <( without closing )
        if [[ "$stripped" == *'< <('* ]] && [[ "$stripped" != *')' ]]; then
            in_procsub=1
        fi

        # Detect multiline double-quoted string assignment start
        # Pattern: VAR="... or _FINAL="$SUMMARY without closing " on same line
        # Bash traces the entire multiline assignment as one command, so opening line
        # may not be individually traced. Skip ALL lines of the multiline string.
        if [[ "$stripped" =~ ^[A-Za-z_].*=\" ]] || [[ "$stripped" =~ ^[A-Za-z_].*=\"\$ ]]; then
            local_stripped="${stripped//\\\"/}"  # remove escaped quotes
            ndq="${local_stripped//[^\"]/}"
            if (( ${#ndq} % 2 == 1 )); then
                in_dq_assign=1
                continue  # skip opening line too
            fi
        fi

        # Detect multiline single-quoted string start (odd number of ' on one line)
        nq="${stripped//[^\']/}"
        if (( ${#nq} % 2 == 1 )); then
            in_sq_string=1
            # Multiline single-quoted commands (jq '...', awk '...', sed '...')
            # are traced at the closing line, not the opening. Skip opening line
            # when it contains a command invocation (awk/jq/sed/grep/perl) or
            # a command substitution assignment $(
            if [[ "$stripped" == *'=$('* || "$stripped" =~ (jq|awk|sed|grep|perl)[[:space:]] ]]; then
                continue
            fi
        fi

        # Skip array literal elements: lines between VAR=( and ) that are pure strings
        # Bash traces the entire array assignment at the closing ), not individual lines
        if [[ "$stripped" =~ ^[A-Za-z_]+[A-Za-z_0-9]*=\( ]]; then
            in_array=1
            # If the array doesn't close on this line, skip the opening line too
            [[ "$stripped" != *\) ]] && continue
        fi
        if (( in_array )); then
            if [[ "$stripped" == *\) ]] && [[ "$stripped" != *=\(* ]]; then
                in_array=0
                continue
            fi
            # Skip lines that are array elements (quoted strings)
            [[ "$stripped" =~ ^\" ]] && continue
        fi

        # Skip backslash continuation lines
        # Bash traces multiline commands at a specific line:
        # - Simple commands (printf, echo): traced at FIRST line
        # - $() assignments: traced at LAST continuation line
        # - if [[ ... ]]: traced at the [[ ]] line (last continuation)
        # - >> redirect: traced at FIRST line
        if (( prev_continued )); then
            prev_continued=0
            [[ "$stripped" == *\\ ]] && prev_continued=1
            continue
        fi
        if [[ "$stripped" == *\\ ]]; then
            prev_continued=1
            # Skip first-line of continuations traced at LAST line:
            # - Command substitution assignments: VAR=$(...
            # - Compound tests: if [[ ..., if ..., elif ...
            # - String-argument closings: ..." \ or ...' \ (never individually traced)
            if [[ "$stripped" == *'=$('* || "$stripped" == 'if [['* || \
                  "$stripped" == 'if '* || "$stripped" == 'elif '* || \
                  "$stripped" == *'" \' || "$stripped" == *"' \\" ]]; then
                continue
            fi
        fi

        # Skip case arm pattern lines (pattern) — bash traces at the body, not the pattern
        # Pattern: lines like *"something"*|*"other"*) or ending with |\
        if (( in_case )); then
            # Empty case arms: pattern) ;; — no body, never traced
            if [[ "$stripped" =~ \)[[:space:]]*\;\;$ ]] && [[ "$stripped" != *'$('* ]]; then
                continue
            fi
            # Case arm pattern that continues with | or |\ — skip it
            if [[ "$stripped" == *'|' || "$stripped" == *'|\' ]]; then
                continue
            fi
            if [[ "$stripped" == ';;' ]]; then
                : # terminator after body, count it
            elif [[ "$stripped" == *\) && "$stripped" != *\(\) && "$stripped" != *'$('* ]]; then
                # This is a case pattern closing with ) — skip it
                continue
            fi
        fi
        [[ "$stripped" == 'case '* ]] && in_case=1
        [[ "$stripped" == 'esac' ]] && in_case=0

        file_total=$((file_total + 1))
        if [[ -n "${COVERED_LINES["$bname:$lineno"]:-}" ]]; then
            file_covered=$((file_covered + 1))
        fi
    done < "$src"

    if (( file_total > 0 )); then
        pct=$((file_covered * 100 / file_total))
    else
        pct=0
    fi
    printf "%-50s %8d %8d %7d%%\n" "$bname" "$file_total" "$file_covered" "$pct"
    total_lines=$((total_lines + file_total))
    covered_lines=$((covered_lines + file_covered))
done

printf "%-50s %8s %8s %8s\n" "$(printf '%0.s-' {1..50})" "--------" "--------" "--------"
if (( total_lines > 0 )); then
    pct=$((covered_lines * 100 / total_lines))
else
    pct=0
fi
printf "%-50s %8d %8d %7d%%\n" "TOTAL" "$total_lines" "$covered_lines" "$pct"
echo ""
