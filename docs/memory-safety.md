# Memory & resource safety — contributor contract

> **NON-NEGOTIABLE.** Every PR that touches code which allocates,
> iterates, or accepts external input must satisfy the checklist below.
> The mandate exists because the daemon ate 33 GB of RAM in production
> on 2026-05-01 by shipping a feature with N×M growth and no bounds.

## What happened

The repomap module's PageRank ranker (`RankFiles` in
`native/src/native/repomap_index.cpp`) iterated `refs.size() *
defs.size()` per identifier. The legacy `0.1` weight multiplier on
popular identifiers (`i`, `data`, `_`, ...) downweighted their
*contribution* but not their *iteration*. Combined with a walker that
had no hard cap on file count and a daemon that accepted any cwd
(including `$HOME`), one accidental session-start in `/home/wendel`
produced:

- single-thread `R` state burning 60% CPU for two hours
- 33.5 GB anonymous-private dirty memory (peak 41.7 GB)
- zero `.asg-repomap` cache files written — never converged

The fix is in commits `0146c17`, `4019fb2`, `7dfa938`, and `c9fa6f6`:
hard refusal of unsafe roots, file-count cap, popular-identifier skip,
deadline parameter, RSS watchdog, systemd `MemoryMax=`, and an
adversarial doctest suite running under AddressSanitizer + UBSan.

## The checklist

Every PR that allocates, iterates, or accepts external input must
answer all of these before review starts:

- [ ] **Worst-case input size** — what's the largest legal input? What
      input would a hostile or careless caller provide (e.g., `$HOME`,
      a 100k-file repo, a synthetic identifier referenced 10k times)?
- [ ] **Worst-case memory** — what's RSS at worst-case input? Show the
      math: `N items × bytes/item = M bytes`. If you can't show the
      math, you don't have a bound.
- [ ] **Worst-case CPU time** — what's the wall-clock at worst-case?
      Same rule — show the math.
- [ ] **Hard cap** — every container that grows must have an enforced
      `max_*` field on its options struct, configurable via env var,
      with a sane default. Skipping when the cap is reached is
      preferable to degraded computation.
- [ ] **Deadline** — any operation > 1s worst-case takes a `deadline`
      `std::chrono::steady_clock::time_point` parameter, checks it
      inside its inner loops, and returns a partial-but-valid result on
      timeout.
- [ ] **Adversarial test** — at least one doctest case in
      `native/tests/repomap_unit_tests.cpp` (or a sibling) that
      constructs the worst-case input and asserts the operation
      completes (or refuses cleanly) within the documented bounds.
- [ ] **Refuse, don't try** — prefer refusing dangerous inputs (e.g.,
      `IsUnsafeRoot`) over heuristic mitigation. The 0.1 weight
      multiplier that "downweighted" popular identifiers in PageRank
      still iterated every edge — that's exactly how we ate 33 GB.

## Pattern: nested loops over user data

If you write `for (a in As) for (b in Bs) f(a, b)`, you owe the reader
either:

1. A proof that `|As| × |Bs|` is bounded by a known small constant, OR
2. An explicit cap that skips the iteration when the product exceeds
   threshold (see `RankFiles` `popular_def_threshold` /
   `max_edges_per_ident` in `native/src/native/repomap_index.cpp`).

There is no third option.

## Mandatory memory-check toolchain

`make test` runs the C++ unit suite under AddressSanitizer + UBSan via
`make test-memory`. You can't get a green test run without passing the
memory check.

| Target | Tool | When |
|--------|------|------|
| `make test-memory` | ASan + UBSan, doctest unit suite | Every commit, every CI run, every local pre-push |
| `make test-memory-valgrind` | valgrind `--leak-check=full` | Heavier check before releases and on diffs that touch the daemon allocator |

Why both:

- **ASan** catches use-after-free, heap-buffer-overflow, double-free,
  leaks (with `detect_leaks=1`), and stack-use-after-scope. Fast. No
  external dependency. Required.
- **UBSan** catches integer overflow, signed shift overflow, null
  deref, misaligned access, invalid enum values. Required.
- **Valgrind** catches a slightly different leak class (uninitialized
  reads via Memcheck) and works against the production binary without
  recompile. Optional locally; required before tagging a release.
  Install with `sudo apt install valgrind`.

**Do not bypass.** `--no-verify`, `make test-bats` (the C++-skipping
escape hatch), and `SG_SANITIZER=off` are not acceptable shortcuts. If
the memory check is flaky, fix the flake — never skip the check.

## Daemon backstops

The `sgd` daemon self-polices so a bug like 2026-05-01 cannot run for
two hours again:

- **In-process RSS watchdog**: `StartRssWatchdogFromEnv()` in
  `native/src/native/rss_watchdog.cpp` polls `/proc/self/status` every
  1s, flips an abort flag when RSS exceeds `SG_DAEMON_MAX_RSS_BYTES`
  (1 GiB default), then exits with code 137 after a 5s grace period so
  systemd restarts us. Emits structured `daemon_rss_high` /
  `daemon_rss_abort` events into `events.jsonl`.
- **Cgroup limits**: `systemd/sgd.service` ships `MemoryHigh=1G`,
  `MemoryMax=2G`, `TasksMax=64`. The kernel OOM-killer is the absolute
  last line of defense.

When you add a new long-running operation, **check the abort flag**.
The watchdog is wired in but worthless if downstream code doesn't read
it.

## What "tested for memory" means

| Component | How it's covered |
|-----------|------------------|
| Repomap parser/index/ranker | `sg_repomap_unit_tests` doctest, ASan+UBSan, includes adversarial cases |
| Daemon allocator hot paths | `make test-memory-valgrind` against bats smoke tests pre-release |
| New module that allocates | New doctest file under `native/tests/`, linked from `native/CMakeLists.txt` if `SG_BUILD_TESTS=ON` |

If your diff allocates and you can't point at the test that exercises
the worst case, you're not ready to merge.

## Forensic playbook (for the next incident)

When the daemon is misbehaving:

```bash
# Daemon mem + CPU
systemctl --user status asg.service

# Process state (R = running, not blocked on I/O)
cat /proc/$PID/status | rg 'State|VmRSS|VmPeak|Threads'

# Heap / mmap breakdown — distinguishes malloc growth from file mmap
cat /proc/$PID/smaps_rollup

# Userspace stack from a running process (no symbols → addresses + addr2line)
gdb -batch -p $PID -ex 'thread apply all bt' -ex 'detach' -ex 'quit'

# Resolve a runtime addr → function (binary base from /proc/$PID/maps)
addr2line -e <binary> -f -C $((runtime_addr - load_base))

# Skip-list / cache discovery
fd -t d .asg-repomap "$PWD" --max-depth 5
```

`State: R` in `/proc/$PID/status` is the first signal. If a "stuck"
process is in `R`, it's burning CPU in a loop, not blocked on I/O.
That points at gdb, not strace.
