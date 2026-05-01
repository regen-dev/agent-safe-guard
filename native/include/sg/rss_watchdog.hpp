#pragma once

// Process self-RSS watchdog. Runs in a detached background thread, polling
// /proc/self/status every interval. If RSS exceeds the configured cap, it
// flips an atomic abort flag visible to the rest of the daemon and (after a
// grace period of continued breach) exits the process with a non-zero code
// so systemd restarts us with a clean slate.
//
// This is a hard backstop for the kind of unbounded growth that ate 33 GB
// on 2026-05-01 (see ~/.mem/asg-repomap-leak-2026-05-01.md). systemd's
// MemoryMax= is the absolute last line of defense; this watchdog catches
// the breach earlier and emits a structured event for postmortem.
//
// Configurable via env when StartFromEnv() is used:
//   SG_DAEMON_MAX_RSS_BYTES — RSS cap in bytes, default 1 GiB.
//   SG_DAEMON_WATCHDOG_INTERVAL_MS — poll interval, default 1000 ms.
//   SG_DAEMON_WATCHDOG_GRACE_MS — keep going if RSS stays above the cap for
//     this long before aborting, default 5000 ms.
//   SG_DAEMON_WATCHDOG_DISABLE — set to "1" to disable entirely (tests).

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace sg {

struct RssWatchdogOptions {
  std::uint64_t max_rss_bytes = 1ULL << 30;  // 1 GiB
  std::uint32_t interval_ms = 1000;
  std::uint32_t grace_ms = 5000;
};

// Reads VmRSS from /proc/self/status. Returns 0 on error. Public for tests.
std::uint64_t ReadSelfRssBytes();

// Starts the watchdog thread (detached). Idempotent — second call is a
// no-op. The returned pointer is observable by the rest of the daemon to
// short-circuit long-running operations when the watchdog has tripped; it
// stays valid for the process lifetime.
const std::atomic<bool>* StartRssWatchdog(const RssWatchdogOptions& opts);

// Convenience: read options from SG_DAEMON_* env vars, then start.
const std::atomic<bool>* StartRssWatchdogFromEnv();

}  // namespace sg
