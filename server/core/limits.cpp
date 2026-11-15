// server/core/limits.cpp - defaults, runtime overrides and CSV listing.
#include "core/limits.h"

#include "core/globals.h"
#include "core/ratelimit.h"
#include "session/session.h"

#include <map>
#include <mutex>
#include <string>

namespace limits {
namespace {

struct Entry {
    double up = 0.0;    // bytes/second
    double down = 0.0;
};

std::mutex g_mutex;
double g_default_up = 0.0;
double g_default_down = 0.0;
// Keyed by virtual IP or hardware id; both are matched when a session starts.
std::map<std::string, Entry> g_overrides;

}  // namespace

void set_defaults(double up_bytes_per_sec, double down_bytes_per_sec) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_default_up = up_bytes_per_sec > 0.0 ? up_bytes_per_sec : 0.0;
    g_default_down = down_bytes_per_sec > 0.0 ? down_bytes_per_sec : 0.0;
}

void defaults(double& up_bytes_per_sec, double& down_bytes_per_sec) {
    std::lock_guard<std::mutex> lock(g_mutex);
    up_bytes_per_sec = g_default_up;
    down_bytes_per_sec = g_default_down;
}

void rates_for(const std::string& virtual_ip, const std::string& hw_id,
               double& up_bytes_per_sec, double& down_bytes_per_sec) {
    std::lock_guard<std::mutex> lock(g_mutex);
    up_bytes_per_sec = g_default_up;
    down_bytes_per_sec = g_default_down;
    auto ip_entry = g_overrides.find(virtual_ip);
    if (ip_entry != g_overrides.end()) {
        up_bytes_per_sec = ip_entry->second.up;
        down_bytes_per_sec = ip_entry->second.down;
        return;
    }
    auto hw_entry = g_overrides.find(hw_id);
    if (hw_entry != g_overrides.end()) {
        up_bytes_per_sec = hw_entry->second.up;
        down_bytes_per_sec = hw_entry->second.down;
    }
}

void apply(Session& session) {
    double up = 0.0;
    double down = 0.0;
    rates_for(session.virtual_ip, session.hw_id, up, down);
    session.upload.set_rate(up);
    session.download.set_rate(down);
}

bool set_for(const std::string& key, double up_bytes_per_sec, double down_bytes_per_sec) {
    if (key.empty()) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        Entry entry;
        entry.up = up_bytes_per_sec > 0.0 ? up_bytes_per_sec : 0.0;
        entry.down = down_bytes_per_sec > 0.0 ? down_bytes_per_sec : 0.0;
        g_overrides[key] = entry;
    }

    // Live sessions pick the new rate up at once. g_mutex is already released
    // here, so this never nests the two locks in the opposite order of apply().
    std::lock_guard<std::mutex> slock(sessions_mutex);
    bool matched = false;
    for (const auto& session : online) {
        if (session->virtual_ip != key && session->hw_id != key) {
            continue;
        }
        session->upload.set_rate(up_bytes_per_sec);
        session->download.set_rate(down_bytes_per_sec);
        matched = true;
    }
    return matched;
}

bool clear(const std::string& key) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        removed = g_overrides.erase(key) > 0;
    }

    std::lock_guard<std::mutex> slock(sessions_mutex);
    for (const auto& session : online) {
        if (session->virtual_ip != key && session->hw_id != key) {
            continue;
        }
        session->upload.set_rate(g_default_up);
        session->download.set_rate(g_default_down);
    }
    return removed;
}

std::string list_csv() {
    // Snapshot under the lock, format outside of it.
    std::map<std::string, Entry> copy;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        copy = g_overrides;
    }
    std::string out;
    for (const auto& item : copy) {
        if (!out.empty()) {
            out += ";";
        }
        const double up_kbps = item.second.up * 8.0 / 1000.0;
        const double down_kbps = item.second.down * 8.0 / 1000.0;
        char text[64];
        std::snprintf(text, sizeof(text), "%s|%.0f|%.0f", item.first.c_str(), up_kbps,
                      down_kbps);
        out += text;
    }
    return out;
}

}  // namespace limits
