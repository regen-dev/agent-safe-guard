BATS := ./tests/test_helper/bats-core/bin/bats
BATS_FLAGS := --jobs 32 --timing --print-output-on-failure
PROJ_ROOT := $(shell pwd)
COVERAGE_DIR := ./coverage
TRACE_FILE := /tmp/sg-coverage-trace.txt
NATIVE_BUILD_DIR ?= ./build/native
NATIVE_ASAN_BUILD_DIR ?= ./build/native-asan

# Memory-safety toolchain. ASan is the default mandate (no external dep,
# fast, leak-detecting). Valgrind is the heavier optional check kept for
# release pipelines and diffs that touch allocator-sensitive code.
# CLAUDE.md "Memory & resource safety" mandates that one of these MUST run
# in every CI build — the test-memory target is the contract.
ASAN_OPTIONS_DEFAULT ?= detect_leaks=1:halt_on_error=1:abort_on_error=0:print_stats=0
UBSAN_OPTIONS_DEFAULT ?= halt_on_error=1:abort_on_error=0:print_stacktrace=1
VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --error-exitcode=99 --leak-check=full \
	--show-leak-kinds=definite,indirect \
	--errors-for-leak-kinds=definite,indirect --track-origins=yes

.PHONY: test test-unit test-integration coverage clean \
	native-configure native-build native-build-asan \
	test-native-pre-smoke test-native-post-smoke \
	test-native-permission-smoke test-native-read-guard-smoke \
	test-native-rule-audit \
	test-native-read-compress-smoke test-native-stop-smoke \
	test-native-session-start-smoke test-native-session-end-smoke \
	test-native-pre-compact-smoke test-native-subagent-start-smoke \
	test-native-subagent-stop-smoke test-native-tool-error-smoke \
	test-native-repomap-smoke test-native-repomap-session-smoke \
	test-native-unit test-memory test-memory-valgrind \
	native-install-user native-uninstall-user native-watch

test: test-memory
	$(BATS) $(BATS_FLAGS) tests/unit/ tests/integration/

# `test-bats` is the same shell-only gate without the C++ memory check, for
# the rare case where you're iterating on a bats-only diff and the C++
# build artifacts haven't changed. CI must use `make test`, not this.
test-bats:
	$(BATS) $(BATS_FLAGS) tests/unit/ tests/integration/

test-unit:
	$(BATS) $(BATS_FLAGS) tests/unit/

test-integration:
	$(BATS) $(BATS_FLAGS) tests/integration/

coverage:
	@rm -f $(TRACE_FILE)
	@touch $(TRACE_FILE)
	SG_COVERAGE_FILE=$(TRACE_FILE) \
		$(BATS) --timing --print-output-on-failure tests/unit/ tests/integration/
	@echo ""
	@echo "Parsing coverage from trace..."
	@bash $(PROJ_ROOT)/tests/parse-coverage.sh $(TRACE_FILE) $(PROJ_ROOT)

clean:
	rm -rf $(COVERAGE_DIR) $(TRACE_FILE)

native-configure:
	cmake -S . -B $(NATIVE_BUILD_DIR) -DSG_BUILD_NATIVE=ON

native-build: native-configure
	cmake --build $(NATIVE_BUILD_DIR) -j

# AddressSanitizer + UBSan build, with C++ unit tests enabled. Every CI run
# of `make test-memory` rebuilds this from scratch; do NOT skip it. See
# CLAUDE.md "Memory & resource safety" for why this is non-negotiable.
native-build-asan:
	cmake -S . -B $(NATIVE_ASAN_BUILD_DIR) \
		-DSG_BUILD_NATIVE=ON \
		-DSG_BUILD_TESTS=ON \
		-DSG_SANITIZER=address,undefined \
		-DCMAKE_BUILD_TYPE=Debug
	cmake --build $(NATIVE_ASAN_BUILD_DIR) -j

# Run the C++ unit suite under ASan/UBSan. This is the primary gate that
# catches the kind of unbounded growth + leak that produced the 2026-05-01
# incident. New features that allocate in loops MUST add a stress case here.
test-native-unit: native-build-asan
	@echo "=== sg_repomap_unit_tests under ASan/UBSan ==="
	ASAN_OPTIONS=$(ASAN_OPTIONS_DEFAULT) \
	UBSAN_OPTIONS=$(UBSAN_OPTIONS_DEFAULT) \
	$(NATIVE_ASAN_BUILD_DIR)/native/sg_repomap_unit_tests

# Full memory check: ASan/UBSan unit tests. This is the target referenced
# from CLAUDE.md as the mandatory pre-merge gate.
test-memory: test-native-unit
	@echo ""
	@echo "=== Memory check passed (ASan + UBSan, unit suite) ==="

# Heavier valgrind run, optional, used for releases and any diff that
# touches the repomap / daemon allocator. Requires `valgrind` on PATH.
# On Ubuntu/Debian: `sudo apt install valgrind`.
test-memory-valgrind: native-build
	@command -v $(VALGRIND) >/dev/null 2>&1 || { \
		echo "valgrind not installed; install with 'sudo apt install valgrind' or set VALGRIND=/path"; \
		exit 1; }
	@echo "=== valgrind: asg-repomap CLI smoke ==="
	$(VALGRIND) $(VALGRIND_FLAGS) \
		$(NATIVE_BUILD_DIR)/native/asg-repomap build --file \
		$(PROJ_ROOT)/tests/fixtures/repomap/ts-minimal/auth.ts

native-install-user: native-build
	./$(NATIVE_BUILD_DIR)/native/asg-install

native-uninstall-user: native-build
	./$(NATIVE_BUILD_DIR)/native/asg-uninstall

test-native-pre-smoke: native-build
	./scripts/native-dev-loop.sh --once

test-native-post-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-post-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-post-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_POST_TOOL_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-post-tool-use" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/post_tool_use.bats

test-native-permission-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-permission-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-permission-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_PERMISSION_REQUEST_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-permission-request" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/permission_request.bats

test-native-read-guard-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-read-guard-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-read-guard-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_READ_GUARD_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-read-guard" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/read_guard.bats

test-native-rule-audit: native-build
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/native_rule_audit.bats

test-native-read-compress-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-read-compress-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-read-compress-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_READ_COMPRESS_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-read-compress" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/read_compress.bats

test-native-stop-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-stop-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-stop-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_STOP_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-stop" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^stop ' tests/integration/session_lifecycle.bats

test-native-session-start-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-session-start-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-session-start-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_SESSION_START_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-session-start" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^session-start ' tests/integration/session_lifecycle.bats

test-native-session-end-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-session-end-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-session-end-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_SESSION_END_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-session-end" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^session-end ' tests/integration/session_lifecycle.bats

test-native-pre-compact-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-pre-compact-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-pre-compact-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_PRE_COMPACT_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-pre-compact" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^pre-compact ' tests/integration/session_lifecycle.bats

test-native-subagent-start-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-subagent-start-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-subagent-start-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_SUBAGENT_START_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-subagent-start" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^subagent-start ' tests/integration/subagent_lifecycle.bats

test-native-subagent-stop-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-subagent-stop-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-subagent-stop-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_SUBAGENT_STOP_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-subagent-stop" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure \
	--filter '^subagent-stop ' tests/integration/subagent_lifecycle.bats

test-native-repomap-smoke: native-build
	SG_REPOMAP_BIN="$(PWD)/$(NATIVE_BUILD_DIR)/native/asg-repomap" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/repomap.bats

test-native-repomap-session-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-repomap-session-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-repomap-session-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_SESSION_START_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-session-start" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/repomap_session.bats

test-native-tool-error-smoke: native-build
	SOCK=/tmp/agent-safe-guard/sgd-tool-error-smoke.sock; \
	mkdir -p /tmp/agent-safe-guard; \
	rm -f "$$SOCK"; \
	./$(NATIVE_BUILD_DIR)/native/sgd --socket "$$SOCK" >/tmp/sgd-tool-error-smoke.log 2>&1 & \
	PID=$$!; \
	trap 'kill $$PID >/dev/null 2>&1 || true; kill -9 $$PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 50); do [ -S "$$SOCK" ] && break; sleep 0.1; done; \
	SG_TOOL_ERROR_HOOK="$(PWD)/$(NATIVE_BUILD_DIR)/native/sg-hook-tool-error" \
	SG_DAEMON_SOCKET="$$SOCK" \
	./tests/test_helper/bats-core/bin/bats --jobs 1 --timing --print-output-on-failure tests/integration/tool_error.bats

native-watch: native-build
	./scripts/native-dev-loop.sh
