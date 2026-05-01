#include "sg/repomap_format.hpp"
#include "sg/repomap_index.hpp"
#include "sg/repomap_parser.hpp"
#include "sg/repomap_service.hpp"
#include "sg/repomap_store.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>

namespace {

int PrintUsage(FILE* stream) {
  std::fputs(
      "usage: asg-repomap <command> [options]\n"
      "\n"
      "commands:\n"
      "  build --file <path> [--tags]    parse one source file (stdout):\n"
      "                                  node count, optionally def/ref tags\n"
      "  build --root <path> [--force]   build + cache the full repo index\n"
      "  update --root <path>            incremental: reparse only changed files\n"
      "  rank --root <path>              print ranked file list\n"
      "  render --root <path>            render map under token budget\n"
      "         [--budget N] [--refs]\n"
      "  stats --root <path>             print cache stats (file/tag/byte counts)\n"
      "  clean --root <path>             remove the repomap cache dir\n",
      stream);
  return 2;
}

int RunBuild(int argc, char** argv) {
  std::string file;
  std::string root;
  bool want_tags = false;
  bool force = false;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--file") {
      if (i + 1 >= argc) {
        std::fputs("error: --file requires a value\n", stderr);
        return 2;
      }
      file = argv[++i];
      continue;
    }
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    if (arg == "--tags") {
      want_tags = true;
      continue;
    }
    if (arg == "--force") {
      force = true;
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (!file.empty() && !root.empty()) {
    std::fputs("error: pass either --file or --root, not both\n", stderr);
    return 2;
  }
  if (!file.empty()) {
    const auto result = sg::repomap::ParseFile(file, want_tags);
    if (!result.stats.ok) {
      std::fprintf(stderr, "error: %s\n", result.error.c_str());
      return 1;
    }
    std::printf("ok lang=%s bytes=%zu node_count=%zu tag_count=%zu\n",
                sg::repomap::LanguageName(result.stats.language),
                result.stats.bytes, result.stats.node_count,
                result.stats.tag_count);
    if (want_tags) {
      for (const auto& tag : result.tags) {
        std::printf("%u %s %s %s\n", tag.line,
                    sg::repomap::TagKindName(tag.kind), tag.subkind.c_str(),
                    tag.name.c_str());
      }
    }
    return 0;
  }
  if (root.empty()) {
    std::fputs("error: build requires either --file <path> or --root <path>\n",
               stderr);
    return 2;
  }

  sg::repomap::EnsureOptions opts;
  opts.force_rebuild = force;
  // The CLI is a developer tool: when the user passes --root explicitly,
  // trust them. The unsafe-root + git-repo gate exists to protect the
  // daemon path from accidental $HOME walks; the CLI trusts its caller.
  opts.allow_unsafe_root = true;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh(root, opts, &stats, &err);
  if (idx.files.empty()) {
    std::fprintf(stderr, "error: no source files found%s%s\n",
                 err.empty() ? "" : ": ", err.c_str());
    return 1;
  }
  std::printf("ok files=%zu reparsed=%zu added=%zu dropped=%zu "
              "used_cache=%s wrote_cache=%s\n",
              stats.files_total, stats.files_reparsed, stats.files_added,
              stats.files_dropped, stats.used_cache ? "yes" : "no",
              stats.wrote_cache ? "yes" : "no");
  return 0;
}

int RunUpdate(int argc, char** argv) {
  std::string root;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (root.empty()) {
    std::fputs("error: update requires --root <path>\n", stderr);
    return 2;
  }
  sg::repomap::EnsureOptions opts;
  opts.force_rebuild = false;
  // CLI: trust explicit --root.
  opts.allow_unsafe_root = true;
  sg::repomap::EnsureStats stats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh(root, opts, &stats, &err);
  if (idx.files.empty()) {
    std::fprintf(stderr, "error: no source files found%s%s\n",
                 err.empty() ? "" : ": ", err.c_str());
    return 1;
  }
  std::printf("ok files=%zu reparsed=%zu added=%zu dropped=%zu "
              "used_cache=%s wrote_cache=%s\n",
              stats.files_total, stats.files_reparsed, stats.files_added,
              stats.files_dropped, stats.used_cache ? "yes" : "no",
              stats.wrote_cache ? "yes" : "no");
  return 0;
}

int RunStats(int argc, char** argv) {
  std::string root;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (root.empty()) {
    std::fputs("error: stats requires --root <path>\n", stderr);
    return 2;
  }
  if (!sg::repomap::CacheExists(root)) {
    std::fputs("no cache — run `asg-repomap build --root <path>` first\n",
               stderr);
    return 1;
  }
  sg::repomap::Index idx;
  std::string err;
  if (!sg::repomap::ReadCache(root, &idx, &err)) {
    std::fprintf(stderr, "error: %s\n", err.c_str());
    return 1;
  }
  std::size_t total_tags = 0;
  std::size_t total_bytes = 0;
  for (const auto& f : idx.files) {
    total_tags += f.tags.size();
    total_bytes += f.size_bytes;
  }
  std::error_code ec;
  const auto cache_size = std::filesystem::file_size(
      sg::repomap::CacheFileForRoot(root), ec);
  std::printf("files=%zu tags=%zu src_bytes=%zu cache_bytes=%zu "
              "defines=%zu references=%zu cache=%s\n",
              idx.files.size(), total_tags, total_bytes,
              ec ? 0UL : static_cast<std::size_t>(cache_size),
              idx.defines.size(), idx.references.size(),
              sg::repomap::CacheFileForRoot(root).string().c_str());
  return 0;
}

int RunClean(int argc, char** argv) {
  std::string root;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (root.empty()) {
    std::fputs("error: clean requires --root <path>\n", stderr);
    return 2;
  }
  std::string err;
  if (!sg::repomap::RemoveCache(root, &err)) {
    std::fprintf(stderr, "error: %s\n", err.c_str());
    return 1;
  }
  std::puts("ok");
  return 0;
}

}  // namespace

int RunRank(int argc, char** argv) {
  std::string root;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (root.empty()) {
    std::fputs("error: rank requires --root <path>\n", stderr);
    return 2;
  }
  const auto idx = sg::repomap::BuildIndex(root);
  if (idx.files.empty()) {
    std::fputs("error: no source files found under root\n", stderr);
    return 1;
  }
  std::printf("ok files=%zu defines=%zu references=%zu\n", idx.files.size(),
              idx.defines.size(), idx.references.size());
  const auto ranked = sg::repomap::RankFiles(idx);
  for (const auto& r : ranked) {
    std::printf("%.6f %s\n", r.score, idx.files[r.file_id].rel_path.c_str());
  }
  return 0;
}

int RunRender(int argc, char** argv) {
  std::string root;
  std::size_t budget = 1024;
  bool include_refs = false;
  std::size_t max_tags_per_file = 40;
  for (int i = 0; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--root") {
      if (i + 1 >= argc) {
        std::fputs("error: --root requires a value\n", stderr);
        return 2;
      }
      root = argv[++i];
      continue;
    }
    if (arg == "--budget") {
      if (i + 1 >= argc) {
        std::fputs("error: --budget requires a value\n", stderr);
        return 2;
      }
      try {
        budget = static_cast<std::size_t>(std::stoul(argv[++i]));
      } catch (...) {
        std::fprintf(stderr, "error: invalid --budget: %s\n", argv[i]);
        return 2;
      }
      continue;
    }
    if (arg == "--refs") {
      include_refs = true;
      continue;
    }
    if (arg == "--max-tags-per-file") {
      if (i + 1 >= argc) {
        std::fputs("error: --max-tags-per-file requires a value\n", stderr);
        return 2;
      }
      try {
        max_tags_per_file = static_cast<std::size_t>(std::stoul(argv[++i]));
      } catch (...) {
        return 2;
      }
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (root.empty()) {
    std::fputs("error: render requires --root <path>\n", stderr);
    return 2;
  }
  // Render is a *read* op from the user's perspective — don't write the
  // cache as a side effect. Users write via `build` / `update`. This also
  // keeps the test fixture under version control pristine.
  sg::repomap::EnsureOptions eopts;
  eopts.persist_cache = false;
  eopts.write_git_exclude = false;
  // CLI: trust explicit --root.
  eopts.allow_unsafe_root = true;
  sg::repomap::EnsureStats estats;
  std::string err;
  const auto idx = sg::repomap::EnsureFresh(root, eopts, &estats, &err);
  if (idx.files.empty()) {
    std::fprintf(stderr, "error: no source files%s%s\n",
                 err.empty() ? "" : ": ", err.c_str());
    return 1;
  }
  const auto ranked = sg::repomap::RankFiles(idx);

  sg::repomap::RenderOptions opts;
  opts.max_tokens = budget;
  opts.include_refs = include_refs;
  opts.max_tags_per_file = max_tags_per_file;
  const auto result = sg::repomap::RenderTopN(idx, ranked, opts);
  std::fprintf(stderr,
               "ok files=%zu/%zu tags=%zu tokens=%zu budget=%zu%s cache=%s\n",
               result.file_count, idx.files.size(), result.tag_count,
               result.token_estimate, budget,
               result.truncated ? " truncated" : "",
               estats.used_cache ? "yes" : "no");
  std::fwrite(result.text.data(), 1, result.text.size(), stdout);
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return PrintUsage(stderr);
  }
  const std::string_view cmd(argv[1]);
  if (cmd == "build") {
    return RunBuild(argc - 2, argv + 2);
  }
  if (cmd == "rank") {
    return RunRank(argc - 2, argv + 2);
  }
  if (cmd == "render") {
    return RunRender(argc - 2, argv + 2);
  }
  if (cmd == "update") {
    return RunUpdate(argc - 2, argv + 2);
  }
  if (cmd == "stats") {
    return RunStats(argc - 2, argv + 2);
  }
  if (cmd == "clean") {
    return RunClean(argc - 2, argv + 2);
  }
  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    PrintUsage(stdout);
    return 0;
  }
  std::fprintf(stderr, "error: unknown command: %s\n", argv[1]);
  PrintUsage(stderr);
  return 2;
}
