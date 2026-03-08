#!/usr/bin/env bash
# Coverage instrumentation via PS4 trace
# Source this via BASH_ENV to trace all bash processes
# Writes line-level trace to $SG_COVERAGE_FILE

if [[ -n "${SG_COVERAGE_FILE:-}" && -z "${_SG_COVERAGE_ACTIVE:-}" ]]; then
    _SG_COVERAGE_ACTIVE=1  # local to this process (not exported)
    export PS4='+${BASH_SOURCE[0]##*/}:${LINENO}: '
    exec {_SG_TRACEFD}>>"$SG_COVERAGE_FILE"
    BASH_XTRACEFD=$_SG_TRACEFD  # local FD (not exported, each process opens its own)
    set -x
fi
