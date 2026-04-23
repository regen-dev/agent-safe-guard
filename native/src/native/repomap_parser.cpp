#include "sg/repomap_parser.hpp"

#include <tree_sitter/api.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

extern "C" {
const TSLanguage* tree_sitter_typescript();
const TSLanguage* tree_sitter_javascript();
}

namespace sg::repomap {

namespace {

bool HasSuffix(std::string_view path, std::string_view suffix) {
  if (suffix.size() > path.size()) return false;
  return path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::size_t CountNodes(TSNode root) {
  // Iterative preorder walk — tree-sitter has no direct "tree size" accessor,
  // so we visit every node once using ts_tree_cursor_goto_*.
  std::size_t n = 0;
  TSTreeCursor cursor = ts_tree_cursor_new(root);
  while (true) {
    ++n;
    if (ts_tree_cursor_goto_first_child(&cursor)) continue;
    while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
      if (!ts_tree_cursor_goto_parent(&cursor)) {
        ts_tree_cursor_delete(&cursor);
        return n;
      }
    }
  }
}

bool ReadEntireFile(std::string_view path, std::string* out, std::string* err) {
  std::string path_str(path);
  std::ifstream in(path_str, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    *err = "cannot read " + path_str + ": " + std::strerror(errno);
    return false;
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  *out = oss.str();
  return true;
}

}  // namespace

const char* LanguageName(Language lang) {
  switch (lang) {
    case Language::kTypeScript: return "typescript";
    case Language::kJavaScript: return "javascript";
    case Language::kUnknown:    return "unknown";
  }
  return "unknown";
}

Language DetectLanguage(std::string_view path) {
  if (HasSuffix(path, ".ts") || HasSuffix(path, ".mts") ||
      HasSuffix(path, ".cts")) {
    return Language::kTypeScript;
  }
  if (HasSuffix(path, ".js") || HasSuffix(path, ".mjs") ||
      HasSuffix(path, ".cjs")) {
    return Language::kJavaScript;
  }
  return Language::kUnknown;
}

ParseResult ParseFile(std::string_view path) {
  ParseResult result;
  result.stats.language = DetectLanguage(path);
  if (result.stats.language == Language::kUnknown) {
    result.error = "unsupported language for path: " + std::string(path);
    return result;
  }

  std::string source;
  if (!ReadEntireFile(path, &source, &result.error)) {
    return result;
  }
  result.stats.bytes = source.size();

  TSParser* parser = ts_parser_new();
  if (parser == nullptr) {
    result.error = "tree-sitter: ts_parser_new returned null";
    return result;
  }
  const TSLanguage* lang = result.stats.language == Language::kTypeScript
                               ? tree_sitter_typescript()
                               : tree_sitter_javascript();
  if (!ts_parser_set_language(parser, lang)) {
    ts_parser_delete(parser);
    result.error = "tree-sitter: grammar/core ABI mismatch";
    return result;
  }

  TSTree* tree = ts_parser_parse_string(parser, nullptr, source.data(),
                                        static_cast<uint32_t>(source.size()));
  if (tree == nullptr) {
    ts_parser_delete(parser);
    result.error = "tree-sitter: parse returned null tree";
    return result;
  }

  const TSNode root = ts_tree_root_node(tree);
  result.stats.node_count = CountNodes(root);
  result.stats.ok = true;

  ts_tree_delete(tree);
  ts_parser_delete(parser);
  return result;
}

}  // namespace sg::repomap
