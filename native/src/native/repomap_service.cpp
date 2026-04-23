#include "sg/repomap_service.hpp"

#include "sg/repomap_index.hpp"
#include "sg/repomap_store.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace sg::repomap {

namespace fs = std::filesystem;

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
    if (error != nullptr) *error = "repo_root does not exist or not a dir";
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
  CollectSourceFiles(repo_root, &live_paths);

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
