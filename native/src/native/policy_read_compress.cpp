#include "sg/policy_read_compress.hpp"

#include "sg/json_extract.hpp"
#include "sg/policy_bridge.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

const RuleMetadata kReadCompressRule = {
    300400,
    "read-defense",
    "read_compress_structure_extract",
    "",
    RulePhase::kReadCompress,
    RuleSeverity::kMedium,
};

std::string JsonModify(std::string_view text) {
  return "{\"modifyOutput\":\"" + JsonEscape(text) + "\"}";
}

bool IsSubagent(std::string_view transcript_path) {
  return transcript_path.find("/subagents/") != std::string_view::npos ||
         transcript_path.find("/tmp/") != std::string_view::npos;
}

int CountLines(std::string_view text) {
  if (text.empty()) {
    return 0;
  }
  std::istringstream in{std::string(text)};
  std::string line;
  int count = 0;
  while (std::getline(in, line)) {
    ++count;
  }
  return count;
}

std::string TrimTrailingBlankLines(const std::string& input) {
  std::vector<std::string> lines;
  std::istringstream in(input);
  std::string line;
  while (std::getline(in, line)) {
    lines.push_back(line);
  }

  while (!lines.empty()) {
    const auto has_non_space = std::any_of(lines.back().begin(), lines.back().end(),
                                           [](unsigned char ch) {
                                             return std::isspace(ch) == 0;
                                           });
    if (has_non_space) {
      break;
    }
    lines.pop_back();
  }

  std::ostringstream out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i > 0) {
      out << '\n';
    }
    out << lines[i];
  }
  return out.str();
}

std::string StripSystemReminder(const std::string& input) {
  std::istringstream in(input);
  std::ostringstream out;
  std::string line;
  bool skipping = false;
  bool first = true;

  while (std::getline(in, line)) {
    if (line == "<system-reminder>") {
      skipping = true;
      continue;
    }
    if (line == "</system-reminder>") {
      skipping = false;
      continue;
    }
    if (skipping) {
      continue;
    }
    if (!first) {
      out << '\n';
    }
    out << line;
    first = false;
  }
  return TrimTrailingBlankLines(out.str());
}

std::string FileExt(std::string_view file_path) {
  const auto dot = file_path.find_last_of('.');
  if (dot == std::string_view::npos || dot + 1 >= file_path.size()) {
    return std::string(file_path);
  }
  return std::string(file_path.substr(dot + 1));
}

bool IsSkipCompressionExt(std::string_view ext) {
  return ext == "txt" || ext == "md" || ext == "markdown" || ext == "rst" ||
         ext == "log" || ext == "csv" || ext == "tsv" || ext == "env" ||
         ext == "conf" || ext == "gitignore" || ext == "dockerignore";
}

std::string JoinLines(const std::vector<std::string>& lines) {
  std::ostringstream out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i > 0) {
      out << '\n';
    }
    out << lines[i];
  }
  return out.str();
}

std::string ExtractByPatterns(std::string_view content,
                              const std::vector<std::regex>& patterns,
                              int max_lines) {
  std::istringstream in{std::string(content)};
  std::string line;
  std::vector<std::string> out;
  out.reserve(static_cast<std::size_t>(max_lines));

  while (std::getline(in, line)) {
    bool match = false;
    for (const auto& rx : patterns) {
      if (std::regex_search(line, rx)) {
        match = true;
        break;
      }
    }
    if (!match) {
      continue;
    }
    out.push_back(line);
    if (static_cast<int>(out.size()) >= max_lines) {
      break;
    }
  }

  return JoinLines(out);
}

std::string ExtractConfigSummary(std::string_view ext, std::string_view content) {
  if (ext == "json") {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(^[ \t]{0,4}"[^"]+":)")};
    return ExtractByPatterns(content, patterns, 150);
  }
  if (ext == "yml" || ext == "yaml") {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(^---)"), std::regex(R"(^[a-zA-Z_][a-zA-Z0-9_-]*:)"),
        std::regex(R"(^- [a-zA-Z])")};
    return ExtractByPatterns(content, patterns, 150);
  }
  if (ext == "toml" || ext == "cfg" || ext == "ini") {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(^\[)"),
        std::regex(R"(^[a-zA-Z_][a-zA-Z0-9_-]* *=)")};
    return ExtractByPatterns(content, patterns, 150);
  }
  if (ext == "xml" || ext == "svg" || ext == "html") {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(^[ \t]*<[a-zA-Z][^>]*>)")};
    return ExtractByPatterns(content, patterns, 100);
  }
  return "";
}

std::string ExtractCodeSummary(std::string_view content) {
  static const std::vector<std::regex> patterns = {
      std::regex(R"(^import [a-zA-Z])"),
      std::regex(R"(^from [a-zA-Z].* import )"),
      std::regex(R"(^class [a-zA-Z])"),
      std::regex(R"(^def [a-zA-Z])"),
      std::regex(R"(^async def [a-zA-Z])"),
      std::regex(R"(^import .* from )"),
      std::regex(R"(^export (default |const |let |function |class |interface |type |enum ))"),
      std::regex(R"(^const [a-zA-Z].*=)"),
      std::regex(R"(^function [a-zA-Z])"),
      std::regex(R"(^async function [a-zA-Z])"),
      std::regex(R"(^interface [a-zA-Z])"),
      std::regex(R"(^type [a-zA-Z])"),
      std::regex(R"(^use [a-zA-Z])"),
      std::regex(R"(^pub (fn |struct |enum |trait |mod |type |use |const ))"),
      std::regex(R"(^fn [a-zA-Z])"),
      std::regex(R"(^impl [a-zA-Z])"),
      std::regex(R"(^struct [a-zA-Z])"),
      std::regex(R"(^enum [a-zA-Z])"),
      std::regex(R"(^trait [a-zA-Z])"),
      std::regex(R"(^mod [a-zA-Z])"),
      std::regex(R"(^package [a-zA-Z])"),
      std::regex(R"(^import \()"),
      std::regex(R"(^func [a-zA-Z\(])"),
      std::regex(R"(^<\?php)"),
      std::regex(R"(^namespace [a-zA-Z])"),
      std::regex(R"(^#{2,4} )"),
      std::regex(R"(^[ \t]+(pub fn |async fn |def |async def |public function |private function |protected function ))"),
      std::regex(R"(^[ \t]+(public |private |protected )[a-zA-Z].*\()")};
  return ExtractByPatterns(content, patterns, 200);
}

std::string BuildExtractedOutput(std::string_view summary, int lines, int summary_lines,
                                 std::string_view suffix) {
  return std::string(summary) + "\n\n[Structure extracted: " +
         std::to_string(lines) + " lines -> " + std::to_string(summary_lines) +
         " " + std::string(suffix) + "]";
}

}  // namespace

std::string EvaluateReadCompressImpl(std::string_view request_json) {
  const std::string tool_name =
      FindJsonString(request_json, "tool_name").value_or("");
  if (tool_name != "Read") {
    return "";
  }

  const std::string transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");
  const std::string file_path =
      FindJsonString(request_json, "file_path").value_or("");
  std::string content = FindJsonString(request_json, "text").value_or("");
  if (content.empty()) {
    return "";
  }

  bool reminder_stripped = false;
  if (content.find("<system-reminder>") != std::string::npos) {
    content = StripSystemReminder(content);
    reminder_stripped = true;
  }

  const auto exit_maybe_stripped = [&]() -> std::string {
    if (reminder_stripped) {
      return JsonModify(content);
    }
    return "";
  };

  const int lines = CountLines(content);
  const std::string ext = FileExt(file_path);

  if (IsSkipCompressionExt(ext)) {
    return exit_maybe_stripped();
  }

  const bool is_subagent = IsSubagent(transcript_path);
  if ((is_subagent && lines <= 300) || (!is_subagent && lines <= 500)) {
    return exit_maybe_stripped();
  }

  const std::string config_summary = ExtractConfigSummary(ext, content);
  if (!config_summary.empty()) {
    const int summary_lines = CountLines(config_summary);
    if (summary_lines >= lines) {
      return exit_maybe_stripped();
    }

    const std::string final_output =
        BuildExtractedOutput(config_summary, lines, summary_lines,
                             "keys/sections") +
        "\n[Use Read with offset/limit for full content]";
    return JsonModify(final_output);
  }

  const std::string code_summary = ExtractCodeSummary(content);
  const int summary_lines = CountLines(code_summary);
  if (summary_lines >= lines) {
    return exit_maybe_stripped();
  }

  const std::string final_output =
      BuildExtractedOutput(code_summary, lines, summary_lines, "signatures") +
      "\n[Use Read with offset/limit for implementation details]";
  return JsonModify(final_output);
}

std::vector<RuleMetadata> ListReadCompressRules() {
  return {kReadCompressRule};
}

std::string EvaluateReadCompress(std::string_view request_json) {
  const std::string tool_name =
      FindJsonString(request_json, "tool_name").value_or("");
  const std::string content = FindJsonString(request_json, "text").value_or("");
  if (tool_name != "Read" || content.empty()) {
    return EvaluateReadCompressImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kReadCompress, request_json, "Read");
  const PackageMode mode = ResolveEffectiveRuleMode(kReadCompressRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateReadCompressImpl(request_json);
  const RuleAction action =
      InferBridgeAction(response, response.empty() ? RuleAction::kAllow
                                                   : RuleAction::kModifyOutput);
  AppendBridgeRuleMatch(tx, kReadCompressRule, mode, action,
                        mode == PackageMode::kOn, "read_compress hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
