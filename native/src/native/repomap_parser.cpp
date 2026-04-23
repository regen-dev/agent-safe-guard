#include "sg/repomap_parser.hpp"

#include "sg/repomap_queries_embed.hpp"

#include <tree_sitter/api.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>

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

// Capture names are like "name.definition.function" / "name.reference.type".
// Return TagKind + subkind ("function"), or nullopt if the capture should be
// ignored (e.g. container captures without a name. prefix).
struct CaptureInfo {
  TagKind kind;
  std::string subkind;
};

bool DecodeCaptureName(std::string_view capture, CaptureInfo* out) {
  constexpr std::string_view kDefPrefix = "name.definition.";
  constexpr std::string_view kRefPrefix = "name.reference.";
  if (capture.substr(0, kDefPrefix.size()) == kDefPrefix) {
    out->kind = TagKind::kDef;
    out->subkind = std::string(capture.substr(kDefPrefix.size()));
    return true;
  }
  if (capture.substr(0, kRefPrefix.size()) == kRefPrefix) {
    out->kind = TagKind::kRef;
    out->subkind = std::string(capture.substr(kRefPrefix.size()));
    return true;
  }
  return false;
}

bool IsNoiseName(std::string_view name, TagKind kind) {
  if (name.empty()) return true;
  if (name == "constructor") return true;
  if (kind == TagKind::kRef) {
    static const std::unordered_set<std::string_view> kNoise = {
        "require", "Symbol",  "Boolean", "Number", "String", "Array",
        "Object",  "Error",   "Promise", "Map",    "Set",    "Date",
        "Math",    "JSON",    "console", "parseInt", "parseFloat",
        "isNaN",   "isFinite",
    };
    if (kNoise.contains(name)) return true;
  }
  return false;
}

bool ExtractTags(const TSLanguage* lang, const std::string& source,
                 TSNode root, const char* query_source,
                 std::vector<Tag>* out, std::string* err) {
  std::uint32_t error_offset = 0;
  TSQueryError query_error = TSQueryErrorNone;
  TSQuery* query = ts_query_new(lang, query_source,
                                static_cast<std::uint32_t>(std::strlen(query_source)),
                                &error_offset, &query_error);
  if (query == nullptr) {
    *err = "tree-sitter query compile failed at offset " +
           std::to_string(error_offset) + " (error=" +
           std::to_string(query_error) + ")";
    return false;
  }

  TSQueryCursor* cursor = ts_query_cursor_new();
  ts_query_cursor_exec(cursor, query, root);

  TSQueryMatch match;
  while (ts_query_cursor_next_match(cursor, &match)) {
    for (std::uint16_t i = 0; i < match.capture_count; ++i) {
      const TSQueryCapture& cap = match.captures[i];
      std::uint32_t name_len = 0;
      const char* name_ptr =
          ts_query_capture_name_for_id(query, cap.index, &name_len);
      const std::string_view capture_name(name_ptr, name_len);

      CaptureInfo info;
      if (!DecodeCaptureName(capture_name, &info)) continue;

      const std::uint32_t start = ts_node_start_byte(cap.node);
      const std::uint32_t end = ts_node_end_byte(cap.node);
      if (end > source.size() || start >= end) continue;

      std::string name = source.substr(start, end - start);
      if (IsNoiseName(name, info.kind)) continue;

      Tag tag;
      tag.line = ts_node_start_point(cap.node).row + 1;
      tag.kind = info.kind;
      tag.subkind = std::move(info.subkind);
      tag.name = std::move(name);
      out->push_back(std::move(tag));
    }
  }

  ts_query_cursor_delete(cursor);
  ts_query_delete(query);
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

const char* TagKindName(TagKind kind) {
  switch (kind) {
    case TagKind::kDef: return "def";
    case TagKind::kRef: return "ref";
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

ParseResult ParseFile(std::string_view path, bool extract_tags) {
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
                                        static_cast<std::uint32_t>(source.size()));
  if (tree == nullptr) {
    ts_parser_delete(parser);
    result.error = "tree-sitter: parse returned null tree";
    return result;
  }

  const TSNode root = ts_tree_root_node(tree);
  result.stats.node_count = CountNodes(root);

  if (extract_tags) {
    const char* query_src =
        result.stats.language == Language::kTypeScript
            ? embedded::kTypeScriptTagsQuery
            : embedded::kJavaScriptTagsQuery;
    if (!ExtractTags(lang, source, root, query_src, &result.tags,
                     &result.error)) {
      ts_tree_delete(tree);
      ts_parser_delete(parser);
      return result;
    }
    result.stats.tag_count = result.tags.size();
  }

  result.stats.ok = true;
  ts_tree_delete(tree);
  ts_parser_delete(parser);
  return result;
}

}  // namespace sg::repomap
