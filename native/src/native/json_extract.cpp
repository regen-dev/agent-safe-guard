#include "sg/json_extract.hpp"

#include <cctype>
#include <sstream>

namespace sg {
namespace {

std::size_t SkipWhitespace(std::string_view input, std::size_t i) {
  while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i])) != 0) {
    ++i;
  }
  return i;
}

char HexToNibble(char ch) {
  if (ch >= '0' && ch <= '9') {
    return static_cast<char>(ch - '0');
  }
  if (ch >= 'a' && ch <= 'f') {
    return static_cast<char>(10 + ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return static_cast<char>(10 + ch - 'A');
  }
  return -1;
}

std::optional<std::pair<std::size_t, std::size_t>> FindJsonValueRange(
    std::string_view json, std::string_view key) {
  const std::string needle = "\"" + std::string(key) + "\"";
  std::size_t pos = 0;

  while (true) {
    pos = json.find(needle, pos);
    if (pos == std::string_view::npos) {
      return std::nullopt;
    }

    std::size_t i = SkipWhitespace(json, pos + needle.size());
    if (i >= json.size() || json[i] != ':') {
      pos += needle.size();
      continue;
    }

    i = SkipWhitespace(json, i + 1);
    if (i >= json.size()) {
      return std::nullopt;
    }

    const std::size_t start = i;
    const char first = json[i];
    if (first == '"') {
      ++i;
      bool escaped = false;
      while (i < json.size()) {
        const char ch = json[i++];
        if (escaped) {
          escaped = false;
          continue;
        }
        if (ch == '\\') {
          escaped = true;
          continue;
        }
        if (ch == '"') {
          return std::make_pair(start, i);
        }
      }
      return std::nullopt;
    }

    if (first == '{' || first == '[') {
      const char open = first;
      const char close = first == '{' ? '}' : ']';
      int depth = 0;
      bool in_string = false;
      bool escaped = false;
      while (i < json.size()) {
        const char ch = json[i++];
        if (in_string) {
          if (escaped) {
            escaped = false;
          } else if (ch == '\\') {
            escaped = true;
          } else if (ch == '"') {
            in_string = false;
          }
          continue;
        }
        if (ch == '"') {
          in_string = true;
          continue;
        }
        if (ch == open) {
          ++depth;
          continue;
        }
        if (ch == close) {
          --depth;
          if (depth == 0) {
            return std::make_pair(start, i);
          }
          continue;
        }
      }
      return std::nullopt;
    }

    while (i < json.size()) {
      const char ch = json[i];
      if (ch == ',' || ch == '}' || ch == ']' ||
          std::isspace(static_cast<unsigned char>(ch)) != 0) {
        break;
      }
      ++i;
    }
    return std::make_pair(start, i);
  }
}

}  // namespace

std::optional<std::string> FindJsonRaw(std::string_view json,
                                       std::string_view key) {
  const auto range = FindJsonValueRange(json, key);
  if (!range.has_value()) {
    return std::nullopt;
  }
  return std::string(json.substr(range->first, range->second - range->first));
}

std::optional<std::string> FindJsonString(std::string_view json,
                                          std::string_view key) {
  const auto raw = FindJsonRaw(json, key);
  if (!raw.has_value() || raw->size() < 2 || raw->front() != '"' ||
      raw->back() != '"') {
    return std::nullopt;
  }

  std::string out;
  out.reserve(raw->size());
  for (std::size_t i = 1; i + 1 < raw->size();) {
    char ch = (*raw)[i++];
    if (ch != '\\') {
      out.push_back(ch);
      continue;
    }
    if (i >= raw->size() - 1) {
      return std::nullopt;
    }

    const char esc = (*raw)[i++];
    switch (esc) {
      case '"':
      case '\\':
      case '/':
        out.push_back(esc);
        break;
      case 'b':
        out.push_back('\b');
        break;
      case 'f':
        out.push_back('\f');
        break;
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case 'u': {
        if (i + 3 >= raw->size() - 1) {
          return std::nullopt;
        }
        const char h1 = HexToNibble((*raw)[i]);
        const char h2 = HexToNibble((*raw)[i + 1]);
        const char h3 = HexToNibble((*raw)[i + 2]);
        const char h4 = HexToNibble((*raw)[i + 3]);
        if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) {
          return std::nullopt;
        }
        const unsigned int codepoint =
            (static_cast<unsigned int>(h1) << 12) |
            (static_cast<unsigned int>(h2) << 8) |
            (static_cast<unsigned int>(h3) << 4) |
            static_cast<unsigned int>(h4);
        if (codepoint <= 0x7F) {
          out.push_back(static_cast<char>(codepoint));
        } else {
          out.push_back('?');
        }
        i += 4;
        break;
      }
      default:
        return std::nullopt;
    }
  }
  return out;
}

std::optional<std::string> FindJsonObject(std::string_view json,
                                          std::string_view key) {
  const auto raw = FindJsonRaw(json, key);
  if (!raw.has_value() || raw->empty() || raw->front() != '{') {
    return std::nullopt;
  }
  return raw;
}

std::string JsonEscape(std::string_view input) {
  std::ostringstream out;
  for (const unsigned char ch : input) {
    switch (ch) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (ch < 0x20) {
          out << "\\u";
          out.width(4);
          out.fill('0');
          out << std::hex << static_cast<int>(ch);
          out << std::dec;
        } else {
          out << static_cast<char>(ch);
        }
        break;
    }
  }
  return out.str();
}

}  // namespace sg
