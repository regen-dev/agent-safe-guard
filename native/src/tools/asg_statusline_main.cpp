#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kFeatureKey = "SG_FEATURE_STATUSLINE";
constexpr std::string_view kFallbackOutput = "[Claude] Ctx 0%";
constexpr std::string_view kGreen = "\033[32m";
constexpr std::string_view kYellow = "\033[33m";
constexpr std::string_view kRed = "\033[31m";
constexpr std::string_view kReset = "\033[0m";
constexpr std::string_view kDim = "\033[2m";

std::string Trim(std::string_view input) {
  std::size_t first = 0;
  while (first < input.size() &&
         std::isspace(static_cast<unsigned char>(input[first])) != 0) {
    ++first;
  }
  std::size_t last = input.size();
  while (last > first &&
         std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
    --last;
  }
  return std::string(input.substr(first, last - first));
}

std::vector<std::string> Split(std::string_view text, char delim) {
  std::vector<std::string> out;
  std::string current;
  for (char ch : text) {
    if (ch == delim) {
      out.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  out.push_back(current);
  return out;
}

std::optional<long long> ParseInt(std::string_view raw) {
  const std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  char* end = nullptr;
  errno = 0;
  const long long value = std::strtoll(trimmed.c_str(), &end, 10);
  if (end == trimmed.c_str() || *end != '\0' || errno != 0) {
    return std::nullopt;
  }
  return value;
}

long long NumOrZero(std::string_view raw) {
  return ParseInt(raw).value_or(0);
}

std::optional<double> ParseDouble(std::string_view raw) {
  std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
    trimmed = trimmed.substr(1, trimmed.size() - 2);
  }
  char* end = nullptr;
  errno = 0;
  const double value = std::strtod(trimmed.c_str(), &end);
  if (end == trimmed.c_str() || *end != '\0' || errno != 0) {
    return std::nullopt;
  }
  return value;
}

std::string FormatFixed(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  return out.str();
}

bool IsTruthy(std::string_view raw) {
  std::string lowered = Trim(raw);
  for (char& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return lowered == "1" || lowered == "true" || lowered == "yes" ||
         lowered == "on";
}

std::optional<std::string> FindRawAtPath(
    std::string_view json, const std::vector<std::string>& path) {
  if (path.empty()) {
    return std::nullopt;
  }
  std::string current_storage(json);
  std::string_view current = current_storage;
  for (std::size_t i = 0; i + 1 < path.size(); ++i) {
    auto next = sg::FindJsonObject(current, path[i]);
    if (!next.has_value()) {
      return std::nullopt;
    }
    current_storage = *next;
    current = current_storage;
  }
  return sg::FindJsonRaw(current, path.back());
}

std::optional<std::string> FindStringAtPath(
    std::string_view json, const std::vector<std::string>& path) {
  if (path.empty()) {
    return std::nullopt;
  }
  std::string current_storage(json);
  std::string_view current = current_storage;
  for (std::size_t i = 0; i + 1 < path.size(); ++i) {
    auto next = sg::FindJsonObject(current, path[i]);
    if (!next.has_value()) {
      return std::nullopt;
    }
    current_storage = *next;
    current = current_storage;
  }
  return sg::FindJsonString(current, path.back());
}

std::optional<std::string> FindFirstRaw(
    std::string_view json, const std::vector<std::vector<std::string>>& paths) {
  for (const auto& path : paths) {
    auto value = FindRawAtPath(json, path);
    if (value.has_value()) {
      return value;
    }
  }
  return std::nullopt;
}

std::string FormatTokens(long long value) {
  if (value >= 1000000) {
    const long long whole = value / 1000000;
    const long long dec = (value % 1000000) / 100000;
    if (dec == 0) {
      return std::to_string(whole) + "M";
    }
    return std::to_string(whole) + "." + std::to_string(dec) + "M";
  }
  if (value >= 1000) {
    const long long whole = value / 1000;
    const long long dec = (value % 1000) / 100;
    if (dec == 0) {
      return std::to_string(whole) + "k";
    }
    return std::to_string(whole) + "." + std::to_string(dec) + "k";
  }
  return std::to_string(value);
}

std::string FormatPercentFromTenths(long long tenths) {
  const long long whole = tenths / 10;
  const long long dec = std::llabs(tenths % 10);
  if (dec == 0) {
    return std::to_string(whole);
  }
  return std::to_string(whole) + "." + std::to_string(dec);
}

std::string NormalizeCostUsd(std::string_view raw, long long total_tokens) {
  std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return "0";
  }
  if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
    trimmed = trimmed.substr(1, trimmed.size() - 2);
  }
  for (char ch : trimmed) {
    if (!(std::isdigit(static_cast<unsigned char>(ch)) != 0 || ch == '.')) {
      return "0";
    }
  }
  if (trimmed.find('.') != std::string::npos) {
    return trimmed;
  }

  const auto integer_value = ParseInt(trimmed).value_or(0);
  if (total_tokens > 0 &&
      static_cast<double>(integer_value) / static_cast<double>(total_tokens) >
          1.0) {
    return FormatFixed(static_cast<double>(integer_value) / 1000000.0, 6);
  }
  if (integer_value >= 1000) {
    return FormatFixed(static_cast<double>(integer_value) / 1000000.0, 6);
  }
  return trimmed;
}

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

bool AtomicWrite(const std::filesystem::path& path, const std::string& content) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  const auto tmp =
      path.string() + ".tmp." + std::to_string(static_cast<long long>(::getpid()));
  {
    std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
    if (!out) {
      return false;
    }
    out << content;
    if (!out) {
      return false;
    }
  }
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return false;
  }
  return true;
}

std::optional<long long> FileMtime(const std::filesystem::path& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) {
    return std::nullopt;
  }
  return static_cast<long long>(st.st_mtime);
}

struct StatusInput {
  std::string session_id;
  std::string model = "Unknown";
  long long context_size = 0;
  long long total_input = 0;
  long long total_output = 0;
  std::string used_pct_raw;
  bool has_current_usage = false;
  long long curr_in = 0;
  long long curr_out = 0;
  long long cache_create = 0;
  long long cache_read = 0;
  std::string tool_count_raw = "0";
  std::string cost_raw = "0";
  long long duration_ms = 0;
  long long api_duration_ms = 0;
  long long lines_added = 0;
  long long lines_removed = 0;
  bool valid = false;
};

StatusInput ParseStatusInput(std::string_view json) {
  StatusInput input;
  input.session_id = FindStringAtPath(json, {"session_id"}).value_or("");
  input.model = FindStringAtPath(json, {"model", "display_name"})
                    .value_or(FindStringAtPath(json, {"model", "id"})
                                  .value_or("Unknown"));

  auto context_obj = sg::FindJsonObject(json, "context_window");
  if (!context_obj.has_value()) {
    return input;
  }

  input.context_size =
      NumOrZero(FindRawAtPath(*context_obj, {"context_window_size"}).value_or("0"));
  input.total_input =
      NumOrZero(FindRawAtPath(*context_obj, {"total_input_tokens"}).value_or("0"));
  input.total_output =
      NumOrZero(FindRawAtPath(*context_obj, {"total_output_tokens"}).value_or("0"));
  input.used_pct_raw =
      FindRawAtPath(*context_obj, {"used_percentage"}).value_or("");

  auto current_usage = sg::FindJsonObject(*context_obj, "current_usage");
  input.has_current_usage = current_usage.has_value();
  if (current_usage.has_value()) {
    input.curr_in =
        NumOrZero(FindRawAtPath(*current_usage, {"input_tokens"}).value_or("0"));
    input.curr_out =
        NumOrZero(FindRawAtPath(*current_usage, {"output_tokens"}).value_or("0"));
    input.cache_create = NumOrZero(
        FindRawAtPath(*current_usage, {"cache_creation_input_tokens"})
            .value_or("0"));
    input.cache_read =
        NumOrZero(FindRawAtPath(*current_usage, {"cache_read_input_tokens"})
                      .value_or("0"));
  }

  input.tool_count_raw =
      FindFirstRaw(json,
                   {std::vector<std::string>{"tool_count"},
                    std::vector<std::string>{"tool_counts", "total"},
                    std::vector<std::string>{"tools", "total"},
                    std::vector<std::string>{"tool_usage", "total"},
                    std::vector<std::string>{"tool_usage", "total_calls"},
                    std::vector<std::string>{"usage", "tools", "total"}})
          .value_or("0");

  auto cost_obj = sg::FindJsonObject(json, "cost");
  if (cost_obj.has_value()) {
    input.cost_raw =
        FindRawAtPath(*cost_obj, {"total_cost_usd"}).value_or("0");
    input.duration_ms =
        NumOrZero(FindRawAtPath(*cost_obj, {"total_duration_ms"}).value_or("0"));
    input.api_duration_ms = NumOrZero(
        FindRawAtPath(*cost_obj, {"total_api_duration_ms"}).value_or("0"));
    input.lines_added =
        NumOrZero(FindRawAtPath(*cost_obj, {"total_lines_added"}).value_or("0"));
    input.lines_removed = NumOrZero(
        FindRawAtPath(*cost_obj, {"total_lines_removed"}).value_or("0"));
  }

  input.valid = true;
  return input;
}

std::optional<long long> ParsePercentageTenths(std::string_view raw) {
  std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
    trimmed = trimmed.substr(1, trimmed.size() - 2);
  }
  const auto pos = trimmed.find('.');
  if (pos == std::string::npos) {
    auto whole = ParseInt(trimmed);
    if (!whole.has_value()) {
      return std::nullopt;
    }
    return *whole * 10;
  }
  auto whole = ParseInt(trimmed.substr(0, pos));
  if (!whole.has_value()) {
    return std::nullopt;
  }
  int dec = 0;
  if (pos + 1 < trimmed.size() &&
      std::isdigit(static_cast<unsigned char>(trimmed[pos + 1])) != 0) {
    dec = trimmed[pos + 1] - '0';
  }
  return *whole * 10 + dec;
}

void PrintFallback() { std::cout << kFallbackOutput << "\n"; }

}  // namespace

int main() {
  if (!sg::IsFeatureEnabled(kFeatureKey)) {
    return 0;
  }

  const std::string input_json = sg::ReadAllStdin();
  if (input_json.empty()) {
    PrintFallback();
    return 0;
  }

  const StatusInput input = ParseStatusInput(input_json);
  if (!input.valid) {
    PrintFallback();
    return 0;
  }

  long long total = input.total_input + input.total_output;
  std::string cost_usd = NormalizeCostUsd(input.cost_raw, total);

  long long ctx_used = 0;
  long long pct_tenths = 0;
  std::string used_pct_display = "0";
  if (input.has_current_usage) {
    ctx_used =
        input.curr_in + input.curr_out + input.cache_create + input.cache_read;
    if (input.context_size > 0) {
      pct_tenths = ctx_used * 1000 / input.context_size;
      used_pct_display = FormatPercentFromTenths(pct_tenths);
    }
  } else {
    auto maybe_pct = ParsePercentageTenths(input.used_pct_raw);
    if (maybe_pct.has_value()) {
      pct_tenths = *maybe_pct;
      used_pct_display = FormatPercentFromTenths(pct_tenths);
      if (input.context_size > 0) {
        ctx_used = input.context_size * pct_tenths / 1000;
      }
    }
  }

  const long long percent_int =
      NumOrZero(used_pct_display.substr(0, used_pct_display.find('.')));
  const std::string_view color =
      percent_int < 50 ? kGreen : (percent_int < 80 ? kYellow : kRed);

  const std::filesystem::path state_dir =
      std::filesystem::path(std::getenv("HOME")) / ".claude/.statusline";
  const std::filesystem::path state_file = state_dir / "state";
  const std::filesystem::path reason_file = state_dir / "reset-reason";
  std::error_code ec;
  std::filesystem::create_directories(state_dir, ec);

  std::string prev_session;
  long long prev_total_in = 0;
  long long prev_total_out = 0;
  long long prev_ctx = 0;
  std::string prev_cost_usd = "0";
  long long reset_ts = 0;
  std::string reset_reason;

  const std::string prev_state = ReadFile(state_file);
  if (!prev_state.empty()) {
    auto parts = Split(prev_state.substr(0, prev_state.find('\n')), '|');
    if (!parts.empty()) {
      prev_session = parts[0];
    }
    if (parts.size() >= 15) {
      prev_total_in = NumOrZero(parts[1]);
      prev_total_out = NumOrZero(parts[2]);
      prev_ctx = NumOrZero(parts[3]);
      prev_cost_usd = parts[5];
      reset_ts = NumOrZero(parts[13]);
      reset_reason = parts[14];
    } else if (parts.size() >= 5) {
      prev_total_in = NumOrZero(parts[1]);
      prev_total_out = 0;
      prev_ctx = NumOrZero(parts[2]);
      reset_ts = NumOrZero(parts[3]);
      reset_reason = parts[4];
    }
  }

  const long long now_ts = sg::UnixNow();
  bool reset_now = false;
  if (!input.session_id.empty() && !prev_session.empty() &&
      input.session_id != prev_session) {
    reset_now = true;
    reset_reason = "session";
  }

  const long long prev_total = prev_total_in + prev_total_out;
  prev_cost_usd = NormalizeCostUsd(prev_cost_usd, prev_total);
  const bool same_session =
      !input.session_id.empty() && prev_session == input.session_id;

  if (same_session && prev_total > 0 && total < prev_total) {
    reset_now = true;
    reset_reason = "reset";
  }

  bool ctx_clear_now = false;
  long long delta = 0;
  if (same_session && prev_ctx > 0 && ctx_used < prev_ctx) {
    delta = prev_ctx - ctx_used;
    if (delta >= 2000) {
      reset_now = true;
      reset_reason = "context";
      ctx_clear_now = true;
    }
  }
  if (reset_now) {
    reset_ts = now_ts;
  }

  long long clr_count = 0;
  long long clr_ctx_lost = 0;
  std::string clr_cost_at_clear = "0";

  if (!input.session_id.empty() && !prev_session.empty() &&
      input.session_id != prev_session) {
    std::filesystem::remove(state_dir / ("clears-" + prev_session), ec);
    std::filesystem::remove(state_dir / ("peak-" + prev_session), ec);
  }

  if (!input.session_id.empty()) {
    const auto clr_file = state_dir / ("clears-" + input.session_id);
    const std::string clr_text = ReadFile(clr_file);
    if (!clr_text.empty()) {
      auto parts = Split(clr_text.substr(0, clr_text.find('\n')), '|');
      if (parts.size() >= 3) {
        clr_count = NumOrZero(parts[0]);
        clr_ctx_lost = NumOrZero(parts[1]);
        clr_cost_at_clear = parts[2];
      }
    }
    if (ctx_clear_now) {
      ++clr_count;
      clr_ctx_lost += delta;
      clr_cost_at_clear = cost_usd;
      AtomicWrite(clr_file, std::to_string(clr_count) + "|" +
                                std::to_string(clr_ctx_lost) + "|" +
                                clr_cost_at_clear + "\n");
    }
  }

  {
    std::ostringstream state_line;
    state_line << input.session_id << "|" << input.total_input << "|"
               << input.total_output << "|" << ctx_used << "|"
               << input.context_size << "|" << cost_usd << "|"
               << input.duration_ms << "|" << input.api_duration_ms << "|"
               << input.lines_added << "|" << input.lines_removed << "|"
               << input.cache_read << "|" << input.cache_create << "|"
               << input.model << "|" << reset_ts << "|" << reset_reason
               << "\n";
    AtomicWrite(state_file, state_line.str());
  }

  std::string reset_label;
  bool show_reset = false;
  if (reset_ts > 0 && (now_ts - reset_ts) <= 45 && reset_reason == "reset") {
    show_reset = true;
  }

  const std::string reason_text = ReadFile(reason_file);
  if (!reason_text.empty()) {
    auto parts = Split(reason_text.substr(0, reason_text.find('\n')), '|');
    if (parts.size() >= 2) {
      const long long reason_ts = NumOrZero(parts[0]);
      if (reason_ts > 0 && (now_ts - reason_ts) <= 120) {
        reset_label = parts[1];
        show_reset = true;
      }
    }
  }

  std::string tool_count;
  if (ParseInt(input.tool_count_raw).has_value() &&
      NumOrZero(input.tool_count_raw) >= 0) {
    tool_count = std::to_string(NumOrZero(input.tool_count_raw));
  }

  if (!input.session_id.empty()) {
    const auto session_state_file = state_dir / ("session-" + input.session_id);
    const std::string session_state = ReadFile(session_state_file);
    if (!session_state.empty()) {
      auto parts = Split(session_state.substr(0, session_state.find('\n')), '|');
      if (tool_count.empty() && !parts.empty() && ParseInt(parts[0]).has_value()) {
        tool_count = parts[0];
      }
    }
    if (tool_count.empty()) {
      const auto count_file =
          state_dir / ("tool-count-" + input.session_id);
      const std::string count_text = ReadFile(count_file);
      if (!count_text.empty()) {
        auto parts = Split(count_text.substr(0, count_text.find('\n')), '|');
        if (parts.size() >= 2 && parts[0] == input.session_id) {
          tool_count = parts[1];
        }
      }
    }
  }

  long long sub_count = 0;
  const std::string sub_count_text = ReadFile(state_dir / "subagent-count");
  if (!sub_count_text.empty()) {
    auto parts = Split(sub_count_text.substr(0, sub_count_text.find('\n')), '|');
    if (parts.size() >= 2 && parts[0] == input.session_id) {
      sub_count = NumOrZero(parts[1]);
    }
  }

  const std::string ctx_total_fmt = FormatTokens(input.context_size);
  const std::string total_cost_fmt =
      ParseDouble(cost_usd).value_or(0.0) > 0.0 ? FormatFixed(ParseDouble(cost_usd).value(), 2)
                                               : "";

  double turn_cost_value = 0.0;
  bool has_valid_delta = false;
  std::string turn_cost_fmt;
  if (const auto cost_double = ParseDouble(cost_usd);
      cost_double.has_value() && *cost_double != 0.0) {
    if (same_session) {
      const auto prev_cost_double = ParseDouble(prev_cost_usd);
      if (prev_cost_double.has_value() && *prev_cost_double != 0.0) {
        turn_cost_value = *cost_double - *prev_cost_double;
        if (turn_cost_value < 0.0) {
          turn_cost_value = 0.0;
        }
        has_valid_delta = true;
      }
    }
    turn_cost_fmt = FormatFixed(turn_cost_value, 2);
  }

  std::string peak_cost_fmt;
  std::filesystem::path peak_file;
  if (!input.session_id.empty()) {
    peak_file = state_dir / ("peak-" + input.session_id);
    double peak_cost = 0.0;
    const std::string peak_text = Trim(ReadFile(peak_file));
    if (const auto peak = ParseDouble(peak_text); peak.has_value()) {
      peak_cost = *peak;
    }
    if (has_valid_delta && turn_cost_value > peak_cost) {
      peak_cost = turn_cost_value;
      AtomicWrite(peak_file, FormatFixed(peak_cost, 4) + "\n");
    }
    if (peak_cost > 0.0) {
      peak_cost_fmt = FormatFixed(peak_cost, 2);
    }
    if (!peak_cost_fmt.empty() && !total_cost_fmt.empty() &&
        ParseDouble(peak_cost_fmt).value_or(0.0) >
            ParseDouble(total_cost_fmt).value_or(0.0)) {
      peak_cost_fmt.clear();
      std::filesystem::remove(peak_file, ec);
    }
  }

  std::string cache_hit_pct;
  if (input.cache_create > 0 || input.cache_read > 0) {
    const long long total_cache = input.cache_create + input.cache_read;
    if (total_cache > 0) {
      cache_hit_pct = std::to_string(input.cache_read * 100 / total_cache);
    }
  }

  std::string api_pct;
  if (input.duration_ms > 0 && input.api_duration_ms > 0) {
    api_pct = std::to_string(input.api_duration_ms * 100 / input.duration_ms);
  }

  std::string budget_pct;
  const auto budget_cache = state_dir / "budget-export";
  if (const auto mtime = FileMtime(budget_cache);
      mtime.has_value() && (now_ts - *mtime) <= 5) {
    const std::string budget_json = ReadFile(budget_cache);
    const long long consumed =
        NumOrZero(sg::FindJsonRaw(budget_json, "consumed").value_or("0"));
    const long long limit =
        NumOrZero(sg::FindJsonRaw(budget_json, "limit").value_or("0"));
    if (limit > 0) {
      const long long pct = consumed * 100 / limit;
      if (pct > 0) {
        budget_pct = std::to_string(pct);
      }
    }
  }

  std::string g1 =
      "[" + input.model + "] " + std::string(color) + used_pct_display + "%" +
      std::string(kReset);
  if (input.context_size > 0) {
    g1 += "/" + ctx_total_fmt;
  }
  if (!total_cost_fmt.empty()) {
    g1 += " $" + total_cost_fmt;
  }

  std::string g2;
  if (!total_cost_fmt.empty() && has_valid_delta) {
    g2 = std::string(kDim) + "+$" + turn_cost_fmt + std::string(kReset);
  }
  if (!peak_cost_fmt.empty() && peak_cost_fmt != "0.00") {
    if (!g2.empty()) {
      g2 += " ";
    }
    g2 += std::string(kDim) + "pk:$" + peak_cost_fmt + std::string(kReset);
  }
  if (!tool_count.empty() && tool_count != "0") {
    if (!g2.empty()) {
      g2 += " ";
    }
    g2 += "T:" + tool_count;
  }
  if (!cache_hit_pct.empty()) {
    if (!g2.empty()) {
      g2 += " ";
    }
    const long long cache_pct_value = NumOrZero(cache_hit_pct);
    if (cache_pct_value >= 60) {
      g2 += "Cache:" + std::string(kGreen) + cache_hit_pct + "%" +
            std::string(kReset);
    } else if (cache_pct_value <= 30) {
      g2 += "Cache:" + std::string(kYellow) + cache_hit_pct + "%" +
            std::string(kReset);
    } else {
      g2 += "Cache:" + cache_hit_pct + "%";
    }
  }
  if (input.lines_added > 0 || input.lines_removed > 0) {
    if (!g2.empty()) {
      g2 += " ";
    }
    g2 += std::string(kGreen) + "+" + std::to_string(input.lines_added) +
          std::string(kReset) + "/" + std::string(kRed) + "-" +
          std::to_string(input.lines_removed) + std::string(kReset);
  }
  if (!api_pct.empty()) {
    if (!g2.empty()) {
      g2 += " ";
    }
    const long long api_pct_value = NumOrZero(api_pct);
    if (api_pct_value <= 40) {
      g2 += "API:" + std::string(kYellow) + api_pct + "%" +
            std::string(kReset);
    } else {
      g2 += std::string(kDim) + "API:" + api_pct + "%" + std::string(kReset);
    }
  }

  std::string g3;
  if (sub_count > 0) {
    g3 = "Sub:" + std::to_string(sub_count);
  }
  if (clr_count > 0) {
    std::string_view clr_color = clr_count >= 3 ? kRed : (clr_count >= 2 ? kYellow : kGreen);
    if (!g3.empty()) {
      g3 += " ";
    }
    g3 += std::string(clr_color) + "Clr:" + std::to_string(clr_count) +
          std::string(kReset);
  }
  if (!budget_pct.empty()) {
    if (!g3.empty()) {
      g3 += " ";
    }
    const long long budget_value = NumOrZero(budget_pct);
    if (budget_value >= 90) {
      g3 += std::string(kRed) + "Bgt:" + budget_pct + "%" +
            std::string(kReset);
    } else if (budget_value >= 75) {
      g3 += std::string(kYellow) + "Bgt:" + budget_pct + "%" +
            std::string(kReset);
    } else {
      g3 += "Bgt:" + budget_pct + "%";
    }
  }
  if (show_reset) {
    if (!g3.empty()) {
      g3 += " ";
    }
    if (!reset_label.empty()) {
      g3 += std::string(kYellow) + "Reset " + reset_label +
            std::string(kReset);
    } else {
      g3 += std::string(kYellow) + "Reset" + std::string(kReset);
    }
  }

  std::string out = g1;
  if (!g2.empty()) {
    out += " | " + g2;
  }
  if (!g3.empty()) {
    out += " | " + g3;
  }
  std::cout << out << "\n";
  return 0;
}
