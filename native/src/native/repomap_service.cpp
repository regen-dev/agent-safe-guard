#include "sg/repomap_service.hpp"

#include "sg/repomap_index.hpp"
#include "sg/repomap_store.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace sg::repomap {

namespace fs = std::filesystem;

namespace {

// Hardcoded list of paths that EnsureFresh refuses by default. These are
// places where the daemon was historically dropped by accident (e.g. user
// runs `claude` from $HOME) and the walker exploded. The list intentionally
// catches both raw `/` and the common system-managed roots; per-user $HOME
// is checked separately because we can't bake an absolute path here.
constexpr std::array<std::string_view, 9> kUnsafeAbsoluteRoots = {
    "/",         "/tmp",   "/var", "/etc",   "/usr",
    "/opt",      "/mnt",   "/media", "/home",
};

bool IsUnsafeAbsoluteRoot(const fs::path& p) {
  // Compare against canonical lexically-normal form so trailing slashes
  // and `.` don't sneak past the check.
  const auto norm = p.lexically_normal().generic_string();
  for (auto unsafe : kUnsafeAbsoluteRoots) {
    if (norm == unsafe) return true;
  }
  // $HOME — read late so tests can set it to a temp dir and not trip.
  if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    if (norm == fs::path(home).lexically_normal().generic_string()) return true;
  }
  return false;
}

bool LooksLikeGitWorkingTree(const fs::path& p) {
  std::error_code ec;
  // Either `.git/` directory (regular working tree) or `.git` file
  // (worktrees / submodules with gitdir pointer) qualifies.
  const fs::path dot_git = p / ".git";
  if (fs::exists(dot_git, ec)) return true;
  return false;
}

}  // namespace

bool IsUnsafeRoot(std::string_view path) {
  return IsUnsafeAbsoluteRoot(fs::path(path));
}

namespace {

std::uint64_t MtimeNsFor(const fs::path& path) {
  std::error_code ec;
  const auto ftime = fs::last_write_time(path, ec);
  if (ec) return 0;
  const auto sctp =
      std::chrono::time_point_cast<std::chrono::system_clock::duration>(
          ftime - fs::file_time_type::clock::now() +
          std::chrono::system_clock::now());
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          sctp.time_since_epoch())
          .count());
}

std::uint64_t SizeFor(const fs::path& path) {
  std::error_code ec;
  const auto size = fs::file_size(path, ec);
  if (ec) return 0;
  return static_cast<std::uint64_t>(size);
}

// Threshold in nanoseconds below which we consider mtimes equal. Some
// filesystems (ext4 without large inodes, network mounts) only record
// second-granularity mtimes; avoid thrashing the cache on those.
constexpr std::uint64_t kMtimeSlopNs = 2'000'000'000ULL;

bool MtimeMatches(std::uint64_t cached, std::uint64_t current) {
  if (cached == current) return true;
  const auto diff = cached > current ? cached - current : current - cached;
  return diff <= kMtimeSlopNs;
}

}  // namespace

Index EnsureFresh(std::string_view repo_root, const EnsureOptions& opts,
                  EnsureStats* stats_out, std::string* error) {
  EnsureStats stats;
  Index idx;
  std::string local_err;

  fs::path root(repo_root);
  std::error_code ec;
  if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
    stats.skip_reason = EnsureSkipReason::kRootMissing;
    if (error != nullptr) *error = "repo_root does not exist or not a dir";
    if (stats_out != nullptr) *stats_out = stats;
    return idx;
  }

  // Refuse to walk roots that historically caused unbounded growth — $HOME,
  // /, /tmp, etc. The escape hatch is `allow_unsafe_root`, used by tests and
  // by the `asg-repomap` CLI which trusts the user to point at a real repo.
  if (!opts.allow_unsafe_root && IsUnsafeAbsoluteRoot(root)) {
    stats.skip_reason = EnsureSkipReason::kUnsafeRoot;
    if (error != nullptr) {
      *error = "refusing to repomap unsafe root: " +
               root.lexically_normal().generic_string();
    }
    if (stats_out != nullptr) *stats_out = stats;
    return idx;
  }

  // Require a git working tree by default. Catches the case where `claude`
  // is started in a directory that *isn't* unsafe-listed but also isn't a
  // project (random scratch dirs, downloads, etc.).
  if (opts.require_git_root && !opts.allow_unsafe_root &&
      !LooksLikeGitWorkingTree(root)) {
    stats.skip_reason = EnsureSkipReason::kNotGitRepo;
    if (error != nullptr) {
      *error = "refusing to repomap non-git directory: " +
               root.lexically_normal().generic_string();
    }
    if (stats_out != nullptr) *stats_out = stats;
    return idx;
  }

  // Step 1: try cache.
  bool have_cache = false;
  if (!opts.force_rebuild && CacheExists(repo_root)) {
    if (ReadCache(repo_root, &idx, &local_err)) {
      have_cache = true;
      stats.used_cache = true;
    } else {
      // Corrupt cache → fall back to full build. Do not propagate the error:
      // callers typically want the map anyway; we'll overwrite the cache at
      // the end.
      idx = Index{};
    }
  }
  idx.repo_root = std::string(repo_root);

  // Step 2: walk the filesystem for the authoritative set of source files.
  std::vector<std::string> live_paths;
  const auto walk_status =
      CollectSourceFiles(repo_root, &live_paths, opts.build);
  if (walk_status == WalkStatus::kFileCapHit) {
    stats.skip_reason = EnsureSkipReason::kFileCapHit;
    // Continue with the partial set so the caller still gets *something*,
    // but the skip_reason field tells the audit log why the result is
    // incomplete. The cap exists because $HOME-sized walks otherwise OOM.
  }

  std::unordered_map<std::string, std::uint32_t> cached_by_rel;
  cached_by_rel.reserve(idx.files.size());
  for (std::uint32_t i = 0; i < idx.files.size(); ++i) {
    cached_by_rel.emplace(idx.files[i].rel_path, i);
  }

  std::vector<FileEntry> next;
  next.reserve(live_paths.size());
  for (const auto& abs_path : live_paths) {
    fs::path abs(abs_path);
    std::error_code rel_ec;
    std::string rel =
        fs::relative(abs, root, rel_ec).generic_string();
    if (rel_ec || rel.empty()) rel = abs.generic_string();

    const std::uint64_t cur_mtime = MtimeNsFor(abs);
    const std::uint64_t cur_size = SizeFor(abs);

    auto hit = cached_by_rel.find(rel);
    if (have_cache && hit != cached_by_rel.end()) {
      const auto& cached = idx.files[hit->second];
      if (cached.size_bytes == cur_size &&
          MtimeMatches(cached.mtime_ns, cur_mtime)) {
        // Unchanged — keep cached entry.
        next.push_back(cached);
        continue;
      }
    }
    FileEntry entry;
    if (!ParseIntoFileEntry(repo_root, abs_path, opts.build, &entry)) {
      // Skip files we can't parse. If a prior cached entry existed it's
      // dropped too (we trust the current filesystem state).
      continue;
    }
    if (hit != cached_by_rel.end()) {
      ++stats.files_reparsed;
    } else {
      ++stats.files_added;
    }
    next.push_back(std::move(entry));
  }

  // Files that were in the cache but vanished from the walk.
  if (have_cache) {
    std::unordered_map<std::string, bool> live_rels;
    for (const auto& e : next) live_rels[e.rel_path] = true;
    for (const auto& cached : idx.files) {
      if (!live_rels.contains(cached.rel_path)) {
        ++stats.files_dropped;
      }
    }
  }

  idx.files = std::move(next);
  stats.files_total = idx.files.size();
  RebuildDerivedMaps(&idx);

  // Step 3: persist.
  if (opts.persist_cache) {
    if (opts.write_git_exclude) {
      (void)EnsureGitExclude(repo_root, &local_err);
    }
    if (WriteCache(idx, &local_err)) {
      stats.wrote_cache = true;
    } else if (error != nullptr) {
      *error = local_err;
    }
  }

  if (stats_out != nullptr) *stats_out = stats;
  return idx;
}

}  // namespace sg::repomap
