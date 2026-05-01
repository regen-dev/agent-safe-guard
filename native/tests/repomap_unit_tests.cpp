// Unit + adversarial stress tests for sg::repomap.
//
// These tests exercise the bounds added on 2026-05-01 after the daemon ate
// 33 GB of RAM running PageRank in $HOME. See
// `~/.mem/asg-repomap-leak-2026-05-01.md` and the project CLAUDE.md
// "Memory & resource safety" section for the incident and the rules.
//
// Build with sanitizer enabled (`-DSG_SANITIZER=address`) so leaks and
// out-of-bounds accesses are caught here, not in production.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "sg/repomap_index.hpp"
#include "sg/repomap_parser.hpp"
#include "sg/repomap_service.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

class TempDir {
 public:
  TempDir() {
    auto tmpl = fs::temp_directory_path() / "asg-repomap-test-XXXXXX";
    std::string s = tmpl.string();
    std::vector<char> buf(s.begin(), s.end());
    buf.push_back('\0');
    if (mkdtemp(buf.data()) == nullptr) {
      throw std::runtime_error("mkdtemp failed");
    }
    path_ = buf.data();
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

// Writes a minimal but real .ts file at `rel` so the parser produces tags.
void WriteTsFile(const fs::path& root, const std::string& rel,
                 const std::string& body = "") {
  const fs::path abs = root / rel;
  fs::create_directories(abs.parent_path());
  std::ofstream f(abs);
  if (!body.empty()) {
    f << body;
  } else {
    f << "export class Thing { do() { return 1; } }\n";
  }
}

void MakeGitMarker(const fs::path& root) {
  fs::create_directories(root / ".git");
}

// Build a synthetic Index with N files and an injected popular identifier.
// The identifier is defined in `pop_def_count` files and referenced in
// `pop_ref_count` files, exercising the N×M PageRank explosion path.
sg::repomap::Index MakeAdversarialIndex(std::size_t n_files,
                                        std::size_t pop_def_count,
                                        std::size_t pop_ref_count,
                                        const std::string& popular = "i") {
  sg::repomap::Index idx;
  idx.repo_root = "/synthetic";
  idx.files.reserve(n_files);
  for (std::size_t i = 0; i < n_files; ++i) {
    sg::repomap::FileEntry e;
    e.rel_path = "f" + std::to_string(i) + ".ts";
    idx.files.push_back(std::move(e));
  }
  // Distribute the popular identifier across the requested files.
  for (std::size_t i = 0; i < pop_def_count && i < n_files; ++i) {
    idx.defines[popular].push_back(static_cast<std::uint32_t>(i));
  }
  for (std::size_t i = 0; i < pop_ref_count && i < n_files; ++i) {
    idx.references[popular].push_back(static_cast<std::uint32_t>(i));
  }
  // A small amount of "real" signal so PageRank has something to converge on.
  if (n_files >= 2) {
    idx.defines["MyClass"].push_back(0);
    idx.references["MyClass"].push_back(1);
  }
  return idx;
}

}  // namespace

// =============================================================================
// CollectSourceFiles — file count cap
// =============================================================================

TEST_CASE("CollectSourceFiles caps at max_files") {
  TempDir dir;
  for (int i = 0; i < 50; ++i) {
    WriteTsFile(dir.path(), "f" + std::to_string(i) + ".ts");
  }
  std::vector<std::string> out;
  sg::repomap::BuildOptions opts;
  opts.max_files = 10;
  const auto status =
      sg::repomap::CollectSourceFiles(dir.path().string(), &out, opts);
  CHECK(status == sg::repomap::WalkStatus::kFileCapHit);
  CHECK(out.size() == 10);
}

TEST_CASE("CollectSourceFiles with max_files=0 means unlimited") {
  TempDir dir;
  for (int i = 0; i < 5; ++i) {
    WriteTsFile(dir.path(), "f" + std::to_string(i) + ".ts");
  }
  std::vector<std::string> out;
  sg::repomap::BuildOptions opts;
  opts.max_files = 0;
  const auto status =
      sg::repomap::CollectSourceFiles(dir.path().string(), &out, opts);
  CHECK(status == sg::repomap::WalkStatus::kOk);
  CHECK(out.size() == 5);
}

TEST_CASE("CollectSourceFiles reports kRootMissing for nonexistent dir") {
  std::vector<std::string> out;
  const auto status = sg::repomap::CollectSourceFiles(
      "/definitely/does/not/exist/asg-test", &out);
  CHECK(status == sg::repomap::WalkStatus::kRootMissing);
  CHECK(out.empty());
}

// =============================================================================
// EnsureFresh — refusal of unsafe roots and non-git dirs
// =============================================================================

TEST_CASE("EnsureFresh refuses /") {
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh("/", opts, &stats, &err);
  CHECK(idx.files.empty());
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kUnsafeRoot);
  CHECK(!err.empty());
}

TEST_CASE("EnsureFresh refuses /home") {
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh("/home", opts, &stats, &err);
  CHECK(idx.files.empty());
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kUnsafeRoot);
}

TEST_CASE("EnsureFresh refuses $HOME") {
  // Set HOME to a known temp dir so the test is hermetic and doesn't
  // depend on the developer's actual $HOME.
  TempDir fake_home;
  setenv("HOME", fake_home.path().string().c_str(), 1);
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh(fake_home.path().string(), opts,
                                            &stats, &err);
  CHECK(idx.files.empty());
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kUnsafeRoot);
}

TEST_CASE("EnsureFresh refuses non-git directory by default") {
  TempDir dir;
  WriteTsFile(dir.path(), "code.ts");  // file present, but no .git/
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx =
      sg::repomap::EnsureFresh(dir.path().string(), opts, &stats, &err);
  CHECK(idx.files.empty());
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kNotGitRepo);
}

TEST_CASE("EnsureFresh accepts non-git dir when allow_unsafe_root=true") {
  TempDir dir;
  WriteTsFile(dir.path(), "code.ts");
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  opts.allow_unsafe_root = true;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx =
      sg::repomap::EnsureFresh(dir.path().string(), opts, &stats, &err);
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kNone);
  CHECK_FALSE(idx.files.empty());
}

TEST_CASE("EnsureFresh accepts a git working tree") {
  TempDir dir;
  MakeGitMarker(dir.path());
  WriteTsFile(dir.path(), "code.ts");
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx =
      sg::repomap::EnsureFresh(dir.path().string(), opts, &stats, &err);
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kNone);
  CHECK_FALSE(idx.files.empty());
}

TEST_CASE("EnsureFresh marks file_cap_hit when walker truncates") {
  TempDir dir;
  MakeGitMarker(dir.path());
  for (int i = 0; i < 20; ++i) {
    WriteTsFile(dir.path(), "f" + std::to_string(i) + ".ts");
  }
  sg::repomap::EnsureOptions opts;
  opts.persist_cache = false;
  opts.write_git_exclude = false;
  opts.build.max_files = 5;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx =
      sg::repomap::EnsureFresh(dir.path().string(), opts, &stats, &err);
  CHECK(stats.skip_reason == sg::repomap::EnsureSkipReason::kFileCapHit);
  // Partial index is still returned — better than nothing.
  CHECK(idx.files.size() <= 5);
}

TEST_CASE("IsUnsafeRoot recognizes hardcoded paths") {
  CHECK(sg::repomap::IsUnsafeRoot("/"));
  CHECK(sg::repomap::IsUnsafeRoot("/tmp"));
  CHECK(sg::repomap::IsUnsafeRoot("/home"));
  CHECK(sg::repomap::IsUnsafeRoot("/var"));
  CHECK_FALSE(sg::repomap::IsUnsafeRoot("/home/wendel/src/something"));
}

// =============================================================================
// RankFilesEx — popularity skip + deadline
// =============================================================================

TEST_CASE("RankFilesEx skips popular identifiers (no N*M explosion)") {
  // 200 files, an identifier defined in 150 of them and referenced in 150.
  // Pre-fix: 22500 inserts into per_src maps before convergence.
  // Post-fix: skipped because 150 > popular_def_threshold (default 100).
  auto idx = MakeAdversarialIndex(200, 150, 150);
  sg::repomap::RankOptions opts;
  // Default threshold is 100; explicit here for clarity.
  opts.popular_def_threshold = 100;
  const auto res = sg::repomap::RankFilesEx(idx, opts);
  CHECK(res.status == sg::repomap::RankStatus::kOk);
  CHECK(res.skipped_idents >= 1);
  CHECK(res.ranked.size() == idx.files.size());
}

TEST_CASE("RankFilesEx skips identifiers exceeding max_edges_per_ident") {
  // Asymmetric blow-up: 50 defs × 250 refs = 12500 edges > 10000 default cap.
  auto idx = MakeAdversarialIndex(300, 50, 250);
  sg::repomap::RankOptions opts;
  // Bump the def threshold so popularity *alone* doesn't trip; force the
  // edge cap to be the gating check.
  opts.popular_def_threshold = 1000;
  opts.max_edges_per_ident = 10000;
  const auto res = sg::repomap::RankFilesEx(idx, opts);
  CHECK(res.skipped_idents >= 1);
}

TEST_CASE("RankFilesEx respects deadline (already-passed)") {
  auto idx = MakeAdversarialIndex(500, 10, 10);
  sg::repomap::RankOptions opts;
  // Deadline in the past — should bail out quickly.
  opts.deadline = std::chrono::steady_clock::now() - 1ms;
  const auto t0 = std::chrono::steady_clock::now();
  const auto res = sg::repomap::RankFilesEx(idx, opts);
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  CHECK(res.status == sg::repomap::RankStatus::kDeadlineExceeded);
  CHECK(elapsed < 1s);  // bailed out, not chewed through
}

TEST_CASE("RankFilesEx completes the regression workload in <5s") {
  // 1000 files with a popular identifier (defs=200, refs=200). Pre-fix
  // this is the kind of workload that explodes the inner loop. Post-fix,
  // the popularity skip kicks in and the rest converges quickly.
  auto idx = MakeAdversarialIndex(1000, 200, 200);
  sg::repomap::RankOptions opts;  // defaults: thresholds + no deadline
  const auto t0 = std::chrono::steady_clock::now();
  const auto res = sg::repomap::RankFilesEx(idx, opts);
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  CHECK(res.status == sg::repomap::RankStatus::kOk);
  CHECK(elapsed < 5s);
}

TEST_CASE("Backward-compatible RankFiles still returns a vector") {
  auto idx = MakeAdversarialIndex(10, 2, 2);
  const auto v = sg::repomap::RankFiles(idx);
  CHECK(v.size() == idx.files.size());
}
