// server/core/log.cpp - sectioned, column aligned console output.
#include "core/log.h"

#include <cstdio>
#include <mutex>

namespace srvlog {
namespace {

const size_t kTagWidth = 11;
const size_t kHwWidth = 17;
const size_t kIpWidth = 15;
const size_t kRuleWidth = 78;

// One writer at a time: the relay, session and DNS threads all log, and a row
// must never be interleaved with another row half way through.
std::mutex g_log_mutex;

std::string stamp() {
    SYSTEMTIME now;
    GetLocalTime(&now);
    char text[16] = {0};
    std::snprintf(text, sizeof(text), "%02d:%02d:%02d", now.wHour, now.wMinute, now.wSecond);
    return text;
}

// Exactly width characters plus one separating space, so a value that happens
// to fill the column keeps every following column aligned.
std::string pad(const std::string& text, size_t width) {
    std::string value = text.empty() ? std::string("-") : text;
    if (value.size() > width) {
        value.resize(width);
    }
    value.resize(width, ' ');
    return value + " ";
}

void write_row(FILE* stream, const std::string& tag, const std::string& hw_id,
               const std::string& virtual_ip, const std::string& detail) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::fprintf(stream, "%s  %s%s%s%s\n", stamp().c_str(), pad(tag, kTagWidth).c_str(),
                 pad(hw_id, kHwWidth).c_str(), pad(virtual_ip, kIpWidth).c_str(), detail.c_str());
    std::fflush(stream);
}

}  // namespace

void events_header() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::printf("%-8s  %-11s %-17s %-15s %s\n", "TIME", "EVENT", "HW ID", "VIRTUAL IP", "DETAIL");
    std::printf("%s\n", std::string(kRuleWidth, '-').c_str());
    std::fflush(stdout);
}

void section(const std::string& title) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::string head = "== " + title + " ";
    if (head.size() < kRuleWidth) {
        head += std::string(kRuleWidth - head.size(), '=');
    }
    std::printf("\n%s\n", head.c_str());
    std::fflush(stdout);
}

void item(const std::string& label, const std::string& value) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::printf("  %s %s\n", pad(label, 14).c_str(), value.c_str());
    std::fflush(stdout);
}

void event(const std::string& tag, const std::string& hw_id, const std::string& virtual_ip,
           const std::string& detail) {
    write_row(stdout, tag, hw_id, virtual_ip, detail);
}

void error(const std::string& tag, const std::string& hw_id, const std::string& virtual_ip,
           const std::string& detail) {
    write_row(stderr, tag, hw_id, virtual_ip, detail);
}

}  // namespace srvlog
