#include "sg/rss_watchdog.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace sg {

namespace {

// Module-static abort flag + start-once guard. The flag pointer handed to
// callers stays valid for the process lifetime; once set, it stays set until
// the daemon exits.
std::atomic<bool> g_abort{false};
std::atomic<bool> g_started{false};

std::uint64_t ReadProcStatusVmRssBytes() {
  // /proc/self/status has a "VmRSS: <kB> kB" line. Cheap to parse and avoids
  // pulling in a /proc parser dependency.
  std::ifstream f("/proc/self/status");
  if (!f) return 0;
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      const char* p = line.c_str() + 6;
      while (*p == ' ' || *p == '\t') ++p;
      char* end = nullptr;
      const unsigned long long kb = std::strtoull(p, &end, 10);
      if (end == p) return 0;
      return static_cast<std::uint64_t>(kb) * 1024ULL;
    }
  }
  return 0;
}

void EmitEvent(const char* event_type, std::uint64_t rss_bytes,
               std::uint64_t cap_bytes) {
  // The events.jsonl path is owned by the host. We avoid pulling in a full
  // event-emit helper here to keep the watchdog dependency-free. stderr is
  // captured by systemd into the journal.
  std::fprintf(stderr,
               "sgd: watchdog %s rss_bytes=%llu cap_bytes=%llu\n", event_type,
               static_cast<unsigned long long>(rss_bytes),
               static_cast<unsigned long long>(cap_bytes));
  // Best-effort append to events.jsonl when SG_EVENTS_FILE points somewhere.
  if (const char* path = std::getenv("SG_EVENTS_FILE");
      path != nullptr && *path != '\0') {
    std::ofstream ev(path, std::ios::app);
    if (ev) {
      ev << "{\"event_type\":\"" << event_type
         << "\",\"rss_bytes\":" << rss_bytes
         << ",\"cap_bytes\":" << cap_bytes << "}\n";
    }
  }
}

}  // namespace

std::uint64_t ReadSelfRssBytes() {
  return ReadProcStatusVmRssBytes();
}

const std::atomic<bool>* StartRssWatchdog(const RssWatchdogOptions& opts) {
  bool expected = false;
  if (!g_started.compare_exchange_strong(expected, true)) {
    return &g_abort;
  }
  std::thread([opts]() {
    using clock = std::chrono::steady_clock;
    clock::time_point first_breach{};
    bool in_breach = false;
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(opts.interval_ms));
      const auto rss = ReadProcStatusVmRssBytes();
      if (rss == 0) continue;  // /proc unreadable — be conservative
      if (rss <= opts.max_rss_bytes) {
        if (in_breach) {
          EmitEvent("daemon_rss_recovered", rss, opts.max_rss_bytes);
          in_breach = false;
          g_abort.store(false);
        }
        continue;
      }
      // Above the cap.
      if (!in_breach) {
        first_breach = clock::now();
        in_breach = true;
        g_abort.store(true);
        EmitEvent("daemon_rss_high", rss, opts.max_rss_bytes);
        continue;
      }
      const auto over = clock::now() - first_breach;
      if (over >= std::chrono::milliseconds(opts.grace_ms)) {
        EmitEvent("daemon_rss_abort", rss, opts.max_rss_bytes);
        // Flush stderr so journald has the line before we exit.
        std::fflush(stderr);
        // Exit non-zero so systemd restarts us with Restart=on-failure.
        std::_Exit(137);
      }
    }
  }).detach();
  return &g_abort;
}

const std::atomic<bool>* StartRssWatchdogFromEnv() {
  if (const char* dis = std::getenv("SG_DAEMON_WATCHDOG_DISABLE");
      dis != nullptr && *dis == '1') {
    return &g_abort;
  }
  RssWatchdogOptions opts;
  if (const char* raw = std::getenv("SG_DAEMON_MAX_RSS_BYTES");
      raw != nullptr && *raw != '\0') {
    try {
      opts.max_rss_bytes =
          static_cast<std::uint64_t>(std::stoull(raw));
    } catch (...) {
    }
  }
  if (const char* raw = std::getenv("SG_DAEMON_WATCHDOG_INTERVAL_MS");
      raw != nullptr && *raw != '\0') {
    try {
      opts.interval_ms = static_cast<std::uint32_t>(std::stoul(raw));
    } catch (...) {
    }
  }
  if (const char* raw = std::getenv("SG_DAEMON_WATCHDOG_GRACE_MS");
      raw != nullptr && *raw != '\0') {
    try {
      opts.grace_ms = static_cast<std::uint32_t>(std::stoul(raw));
    } catch (...) {
    }
  }
  return StartRssWatchdog(opts);
}

}  // namespace sg
