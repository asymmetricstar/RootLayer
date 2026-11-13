// console/core/text.cpp
#include "core/text.h"

#include <cctype>
#include <cstdlib>

std::string trim(const std::string& text) {
    const size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    const size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::string to_lower(std::string text) {
    for (char& c : text) {
        c = (char)std::tolower((unsigned char)c);
    }
    return text;
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= text.size()) {
        size_t hit = text.find(separator, start);
        if (hit == std::string::npos) hit = text.size();
        const std::string part = trim(text.substr(start, hit - start));
        if (!part.empty()) out.push_back(part);
        if (hit >= text.size()) break;
        start = hit + 1;
    }
    return out;
}

std::vector<std::string> split_fields(const std::string& record) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= record.size()) {
        size_t hit = record.find('|', start);
        if (hit == std::string::npos) hit = record.size();
        out.push_back(record.substr(start, hit - start));
        if (hit >= record.size()) break;
        start = hit + 1;
    }
    return out;
}

bool parse_int(const std::string& text, int* out) {
    if (text.empty()) return false;
    char* end = nullptr;
    const long value = std::strtol(text.c_str(), &end, 10);
    if (end == nullptr || *end != '\0') return false;
    if (value < -2147483647L || value > 2147483647L) return false;
    if (out != nullptr) *out = (int)value;
    return true;
}

std::string token_value(const std::string& text, const std::string& key) {
    const std::string marker = key + ":";
    size_t pos = 0;
    while ((pos = text.find(marker, pos)) != std::string::npos) {
        const bool boundary = (pos == 0) || text[pos - 1] == ' ' || text[pos - 1] == '\t' ||
                              text[pos - 1] == '\r' || text[pos - 1] == '\n';
        if (!boundary) {
            pos += marker.size();
            continue;
        }
        const size_t begin = pos + marker.size();
        size_t end = begin;
        while (end < text.size() && text[end] != ' ' && text[end] != '\t' &&
               text[end] != '\r' && text[end] != '\n') {
            ++end;
        }
        return text.substr(begin, end - begin);
    }
    return "";
}

std::vector<std::string> token_records(const std::string& text, const std::string& key) {
    return split(token_value(text, key), ';');
}

bool find_option(const std::vector<std::string>& args, const std::string& name, std::string& value) {
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] != name) continue;
        value = (i + 1 < args.size()) ? args[i + 1] : std::string();
        return true;
    }
    return false;
}

std::vector<std::string> positional_args(const std::vector<std::string>& args) {
    std::vector<std::string> out;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i].size() > 1 && args[i][0] == '-' && args[i][1] == '-') {
            ++i;  // skip the flag and its value
            continue;
        }
        out.push_back(args[i]);
    }
    return out;
}

std::string sanitize_token(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '|' || c == ':') {
            out.push_back('_');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// Standard base64 with padding. The token protocol splits on spaces, so a
// value like "Jane Doe" only survives the trip in this form.
std::string base64_encode(const std::string& in) {
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    size_t index = 0;
    while (index + 3 <= in.size()) {
        const unsigned int chunk = ((unsigned char)in[index] << 16) |
                                   ((unsigned char)in[index + 1] << 8) |
                                   (unsigned char)in[index + 2];
        out.push_back(kTable[(chunk >> 18) & 0x3F]);
        out.push_back(kTable[(chunk >> 12) & 0x3F]);
        out.push_back(kTable[(chunk >> 6) & 0x3F]);
        out.push_back(kTable[chunk & 0x3F]);
        index += 3;
    }

    const size_t rest = in.size() - index;
    if (rest == 1) {
        const unsigned int chunk = (unsigned char)in[index] << 16;
        out.push_back(kTable[(chunk >> 18) & 0x3F]);
        out.push_back(kTable[(chunk >> 12) & 0x3F]);
        out += "==";
    } else if (rest == 2) {
        const unsigned int chunk = ((unsigned char)in[index] << 16) |
                                   ((unsigned char)in[index + 1] << 8);
        out.push_back(kTable[(chunk >> 18) & 0x3F]);
        out.push_back(kTable[(chunk >> 12) & 0x3F]);
        out.push_back(kTable[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

std::string base64_decode(const std::string& in) {
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> table(256, -1);
    for (int i = 0; i < 64; ++i) {
        table[(unsigned char)alphabet[i]] = i;
    }

    std::string out;
    int value = 0;
    int bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        const int decoded = table[c];
        if (decoded == -1) continue;  // whitespace and stray characters
        value = (value << 6) + decoded;
        bits += 6;
        if (bits >= 0) {
            out.push_back((char)((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}
