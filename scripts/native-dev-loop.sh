#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${SG_NATIVE_BUILD_DIR:-$ROOT_DIR/build/native}"
SOCKET_PATH="${SG_DAEMON_SOCKET:-/tmp/agent-safe-guard/sgd-dev.sock}"
BATS_BIN="$ROOT_DIR/tests/test_helper/bats-core/bin/bats"
BATS_FILE="$ROOT_DIR/tests/integration/pre_tool_use.bats"
BATS_FILTER="${SG_BATS_FILTER:-blocks rm -rf /|blocks curl \| bash|Write tool under limit passes with suppress|Write tool over limit gets denied|Glob \\*\\* in home dir gets denied|Glob \\*\\* with narrow path passes}"

run_once=false
if [[ "${1:-}" == "--once" ]]; then
  run_once=true
fi

configure_and_build() {
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DSG_BUILD_NATIVE=ON
  cmake --build "$BUILD_DIR" -j
}

run_smoke_suite() {
  local daemon="$BUILD_DIR/native/sgd"
  local client="$BUILD_DIR/native/sg-hook-pre-tool-use"

  if [[ ! -x "$daemon" || ! -x "$client" ]]; then
    echo "native binaries not found; build step likely failed" >&2
    return 1
  fi

  rm -f "$SOCKET_PATH"
  "$daemon" --socket "$SOCKET_PATH" >"$BUILD_DIR/sgd-dev.log" 2>&1 &
  local daemon_pid=$!
  trap "stop_daemon $daemon_pid" EXIT

  local ready=false
  for _ in $(seq 1 50); do
    if [[ -S "$SOCKET_PATH" ]]; then
      ready=true
      break
    fi
    sleep 0.1
  done

  if [[ "$ready" != true ]]; then
    echo "daemon socket did not become ready: $SOCKET_PATH" >&2
    return 1
  fi

  SG_PRE_TOOL_HOOK="$client" \
  SG_DAEMON_SOCKET="$SOCKET_PATH" \
  "$BATS_BIN" --jobs 1 --timing --print-output-on-failure \
    --filter "$BATS_FILTER" "$BATS_FILE"

  trap - EXIT
  stop_daemon "$daemon_pid"
}

stop_daemon() {
  local pid="$1"
  kill "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

configure_and_build
run_smoke_suite

if [[ "$run_once" == true ]]; then
  exit 0
fi

if command -v watchexec >/dev/null 2>&1; then
  echo "watching native/, tests/integration/, tests/test_helper/ with watchexec"
  exec watchexec \
    --watch "$ROOT_DIR/native" \
    --watch "$ROOT_DIR/tests/integration" \
    --watch "$ROOT_DIR/tests/test_helper" \
    --exts cpp,hpp,bats,bash,txt,md \
    -- "$0" --once
fi

if command -v entr >/dev/null 2>&1; then
  echo "watching native/, tests/integration/, tests/test_helper/ with entr"
  cd "$ROOT_DIR"
  rg --files native tests/integration tests/test_helper \
    | entr -c "$0" --once
  exit 0
fi

echo "No watcher found (install watchexec or entr). Running one-shot only." >&2
