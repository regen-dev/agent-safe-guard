#pragma once

#include "sg/repomap_parser.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sg::repomap {

struct FileEntry {
  std::string rel_path;
  std::uint64_t mtime_ns = 0;
  std::uint64_t size_bytes = 0;
  std::vector<Tag> tags;
};

struct Index {
  std::string repo_root;
  std::vector<FileEntry> files;
  // identifier -> file ids that define / reference it
  std::unordered_map<std::string, std::vector<std::uint32_t>> defines;
  std::unordered_map<std::string, std::vector<std::uint32_t>> references;
};

struct BuildOptions {
  std::uint64_t max_file_bytes = 512 * 1024;  // skip files larger than this
  // Hard cap on the number of source files indexed in one pass. The walker
  // aborts when this is hit (caller can detect via CollectSourceFiles return).
  // Bound exists because $HOME-sized walks otherwise eat unbounded memory.
  // See `~/.mem/asg-repomap-leak-2026-05-01.md` for the incident.
  std::size_t max_files = 5000;
};

// Reasons CollectSourceFiles / BuildIndex stopped before walking everything.
enum class WalkStatus : std::uint8_t {
  kOk = 0,
  kRootMissing,        // repo_root does not exist or is not a directory
  kFileCapHit,         // hit BuildOptions::max_files
};

// Walk `repo_root` recursively collecting .ts/.js source files, parse them,
// and populate an Index. Hardcoded skip list: .git, node_modules, vendor,
// build, dist, .next, coverage, __pycache__, .venv, target, and the repomap
// cache dir itself.
Index BuildIndex(std::string_view repo_root, const BuildOptions& opts = {});

// Collect the list of .ts/.js source files under `repo_root`. Honors the
// skip list and `opts.max_files`. Results are sorted. Returns whether the
// walk completed normally or was aborted.
WalkStatus CollectSourceFiles(std::string_view repo_root,
                              std::vector<std::string>* out,
                              const BuildOptions& opts = {});

// Rebuild the derived defines/references maps after a caller mutates
// idx.files in place. Idempotent.
void RebuildDerivedMaps(Index* idx);

// Parse one file and fill a FileEntry (rel_path, mtime_ns, size_bytes, tags).
// `rel_path` is derived from `repo_root`. Returns false on parse error.
bool ParseIntoFileEntry(std::string_view repo_root, std::string_view abs_path,
                        const BuildOptions& opts, FileEntry* entry);

struct RankedFile {
  std::uint32_t file_id = 0;
  double score = 0.0;
};

struct RankOptions {
  double damping = 0.85;
  std::size_t max_iters = 50;
  double tol = 1e-6;
};

// PageRank over the file graph. Edges are built from identifier references
// where the identifier has at least one matching definition elsewhere.
// Weights use identifier-shape heuristics:
//   * len >= 8 with camelCase / snake_case / kebab-case → ×10
//   * starts with `_`                                   → ×0.1
//   * identifier defined in > 5 files                    → ×0.1 (applied after)
// Returns RankedFile list sorted by score desc, ties broken by rel_path asc.
// When the graph has zero edges, every file gets an equal 1/N score.
std::vector<RankedFile> RankFiles(const Index& idx,
                                  const RankOptions& opts = {});

// Public for testing — identifier shape multiplier used for edge weights.
double IdentifierShapeMultiplier(std::string_view ident);

}  // namespace sg::repomap
