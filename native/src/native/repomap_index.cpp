#include "sg/repomap_index.hpp"

#include "sg/repomap_parser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace sg::repomap {

namespace {

namespace fs = std::filesystem;

constexpr std::array<std::string_view, 11> kSkipDirs = {
    ".git", "node_modules", "vendor",  "build",       "dist",     ".next",
    "coverage", "__pycache__", ".venv", "target",  ".asg-repomap",
};

bool ShouldSkipDir(std::string_view name) {
  for (auto skip : kSkipDirs) {
    if (name == skip) return true;
  }
  return false;
}

std::uint64_t MtimeNs(const fs::path& path) {
  std::error_code ec;
  const auto ftime = fs::last_write_time(path, ec);
  if (ec) return 0;
  // Convert to system_clock epoch so the number is comparable across runs.
  // file_time_type's epoch is implementation-defined; we approximate by
  // round-tripping through system_clock::now delta.
  const auto sctp =
      std::chrono::time_point_cast<std::chrono::system_clock::duration>(
          ftime - fs::file_time_type::clock::now() +
          std::chrono::system_clock::now());
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          sctp.time_since_epoch())
          .count());
}

}  // namespace

void CollectSourceFiles(std::string_view repo_root,
                        std::vector<std::string>* out) {
  fs::path root(repo_root);
  std::error_code ec;
  if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) return;
  std::vector<fs::path> paths;
  for (auto it = fs::recursive_directory_iterator(
           root, fs::directory_options::skip_permission_denied, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    const auto& entry = *it;
    const auto& p = entry.path();
    const auto fname = p.filename().string();
    if (entry.is_directory(ec)) {
      if (ShouldSkipDir(fname)) {
        it.disable_recursion_pending();
      }
      continue;
    }
    if (entry.is_symlink(ec)) continue;
    if (!entry.is_regular_file(ec)) continue;
    if (DetectLanguage(p.string()) == Language::kUnknown) continue;
    paths.push_back(p);
  }
  std::sort(paths.begin(), paths.end());
  out->reserve(paths.size());
  for (const auto& p : paths) out->push_back(p.string());
}

void RebuildDerivedMaps(Index* idx) {
  idx->defines.clear();
  idx->references.clear();
  for (std::uint32_t fid = 0; fid < idx->files.size(); ++fid) {
    for (const auto& tag : idx->files[fid].tags) {
      if (tag.kind == TagKind::kDef) {
        idx->defines[tag.name].push_back(fid);
      } else {
        idx->references[tag.name].push_back(fid);
      }
    }
  }
  for (auto& kv : idx->defines) {
    std::sort(kv.second.begin(), kv.second.end());
    kv.second.erase(std::unique(kv.second.begin(), kv.second.end()),
                    kv.second.end());
  }
}

bool ParseIntoFileEntry(std::string_view repo_root, std::string_view abs_path,
                        const BuildOptions& opts, FileEntry* entry) {
  fs::path abs(abs_path);
  std::error_code size_ec;
  const auto size = fs::file_size(abs, size_ec);
  if (!size_ec && size > opts.max_file_bytes) return false;

  auto parsed = ParseFile(abs.string(), /*extract_tags=*/true);
  if (!parsed.stats.ok) return false;

  std::error_code rel_ec;
  entry->rel_path = fs::relative(abs, fs::path(repo_root), rel_ec).generic_string();
  if (rel_ec || entry->rel_path.empty()) entry->rel_path = abs.generic_string();
  entry->size_bytes = parsed.stats.bytes;
  entry->mtime_ns = MtimeNs(abs);
  entry->tags = std::move(parsed.tags);
  return true;
}

double IdentifierShapeMultiplier(std::string_view ident) {
  if (ident.empty()) return 1.0;
  if (ident.front() == '_') return 0.1;
  if (ident.size() >= 8) {
    bool has_upper_after_first = false;
    bool has_underscore = false;
    bool has_hyphen = false;
    for (std::size_t i = 1; i < ident.size(); ++i) {
      const unsigned char ch = static_cast<unsigned char>(ident[i]);
      if (std::isupper(ch) != 0) has_upper_after_first = true;
      if (ch == '_') has_underscore = true;
      if (ch == '-') has_hyphen = true;
    }
    if (has_upper_after_first || has_underscore || has_hyphen) {
      return 10.0;
    }
  }
  return 1.0;
}

Index BuildIndex(std::string_view repo_root, const BuildOptions& opts) {
  Index idx;
  idx.repo_root = std::string(repo_root);
  if (idx.repo_root.empty()) return idx;

  fs::path root(idx.repo_root);
  std::error_code ec;
  if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
    return idx;
  }

  std::vector<std::string> sources;
  CollectSourceFiles(idx.repo_root, &sources);
  for (const auto& path : sources) {
    FileEntry entry;
    if (!ParseIntoFileEntry(idx.repo_root, path, opts, &entry)) continue;
    idx.files.push_back(std::move(entry));
  }
  RebuildDerivedMaps(&idx);
  return idx;
}

std::vector<RankedFile> RankFiles(const Index& idx, const RankOptions& opts) {
  const std::size_t n = idx.files.size();
  std::vector<RankedFile> ranked;
  if (n == 0) return ranked;

  // adjacency: adj[src] = list of (dst, weight)
  std::vector<std::vector<std::pair<std::uint32_t, double>>> adj(n);
  // Pass 1: accumulate (src, dst) -> weight into a per-src map, then flatten.
  std::vector<std::unordered_map<std::uint32_t, double>> per_src(n);
  for (const auto& [ident, def_files] : idx.defines) {
    auto ref_it = idx.references.find(ident);
    if (ref_it == idx.references.end()) continue;
    const double shape = IdentifierShapeMultiplier(ident);
    const double rare =
        def_files.size() > 5 ? 0.1 : 1.0;  // widely-defined = less informative
    const double mul = shape * rare;
    for (const std::uint32_t src : ref_it->second) {
      for (const std::uint32_t dst : def_files) {
        if (src == dst) continue;
        per_src[src][dst] += mul;
      }
    }
  }
  for (std::uint32_t src = 0; src < n; ++src) {
    double out_sum = 0.0;
    for (const auto& kv : per_src[src]) out_sum += kv.second;
    if (out_sum <= 0.0) continue;
    adj[src].reserve(per_src[src].size());
    for (const auto& kv : per_src[src]) {
      adj[src].emplace_back(kv.first, kv.second / out_sum);
    }
  }

  std::vector<double> r(n, 1.0 / static_cast<double>(n));
  std::vector<double> r_new(n);
  const double teleport = (1.0 - opts.damping) / static_cast<double>(n);
  for (std::size_t iter = 0; iter < opts.max_iters; ++iter) {
    std::fill(r_new.begin(), r_new.end(), teleport);
    // Dangling nodes (no outbound edges) redistribute uniformly.
    double dangling_mass = 0.0;
    for (std::uint32_t src = 0; src < n; ++src) {
      if (adj[src].empty()) {
        dangling_mass += r[src];
      } else {
        for (const auto& [dst, w] : adj[src]) {
          r_new[dst] += opts.damping * w * r[src];
        }
      }
    }
    const double dangling_share =
        opts.damping * dangling_mass / static_cast<double>(n);
    if (dangling_share > 0.0) {
      for (double& v : r_new) v += dangling_share;
    }
    double delta = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
      delta += std::abs(r_new[i] - r[i]);
    }
    r.swap(r_new);
    if (delta < opts.tol) break;
  }

  ranked.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    ranked.push_back({i, r[i]});
  }
  std::sort(ranked.begin(), ranked.end(),
            [&](const RankedFile& a, const RankedFile& b) {
              if (a.score != b.score) return a.score > b.score;
              return idx.files[a.file_id].rel_path <
                     idx.files[b.file_id].rel_path;
            });
  return ranked;
}

}  // namespace sg::repomap
