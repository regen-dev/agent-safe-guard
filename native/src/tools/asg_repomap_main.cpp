#include "sg/repomap_index.hpp"
#include "sg/repomap_parser.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

namespace {

int PrintUsage(FILE* stream) {
  std::fputs(
      "usage: asg-repomap <command> [options]\n"
      "\n"
      "commands:\n"
      "  build --file <path> [--tags]   parse one source file\n"
      "                                 (default: node count only; --tags also\n"
      "                                  prints one `line kind subkind name` per tag)\n"
      "  rank --root <path>             walk root, build index, run PageRank,\n"
      "                                 print one `score rel_path` per file\n",
      stream);
  return 2;
}

int RunBuild(int argc, char** argv) {
  std::string file;
  bool want_tags = false;
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
    if (arg == "--tags") {
      want_tags = true;
      continue;
    }
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (file.empty()) {
    std::fputs("error: build requires --file <path>\n", stderr);
    return 2;
  }

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
  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    PrintUsage(stdout);
    return 0;
  }
  std::fprintf(stderr, "error: unknown command: %s\n", argv[1]);
  PrintUsage(stderr);
  return 2;
}
