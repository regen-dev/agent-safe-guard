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
      "commands (phase 0 — parse smoke only):\n"
      "  build --file <path>   parse one source file and print node count\n",
      stream);
  return 2;
}

int RunBuild(int argc, char** argv) {
  std::string file;
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
    std::fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
    return 2;
  }
  if (file.empty()) {
    std::fputs("error: build requires --file <path>\n", stderr);
    return 2;
  }

  const auto result = sg::repomap::ParseFile(file);
  if (!result.stats.ok) {
    std::fprintf(stderr, "error: %s\n", result.error.c_str());
    return 1;
  }
  std::printf("ok lang=%s bytes=%zu node_count=%zu\n",
              sg::repomap::LanguageName(result.stats.language),
              result.stats.bytes, result.stats.node_count);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return PrintUsage(stderr);
  }
  const std::string_view cmd(argv[1]);
  if (cmd == "build") {
    return RunBuild(argc - 2, argv + 2);
  }
  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    PrintUsage(stdout);
    return 0;
  }
  std::fprintf(stderr, "error: unknown command: %s\n", argv[1]);
  PrintUsage(stderr);
  return 2;
}
