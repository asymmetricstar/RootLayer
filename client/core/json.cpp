// client/core/json.cpp - JSON event output on stdout.
#include "core/win_headers.h"
#include "core/json.h"

// ------------------------------------------------------------ JSON output

static std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

std::string json_string_field(const std::string& key, const std::string& value) {
    return "\"" + key + "\":\"" + json_escape(value) + "\"";
}

std::string json_number_field(const std::string& key, long long value) {
    return "\"" + key + "\":" + std::to_string(value);
}

static std::mutex json_mutex;

// One JSON object per line on stdout.
void json_event(const std::string& event, const std::string& fields) {
    std::lock_guard<std::mutex> lock(json_mutex);
    std::cout << "{\"event\":\"" << event << "\"";
    if (!fields.empty()) {
        std::cout << "," << fields;
    }
    std::cout << "}" << std::endl;
}
