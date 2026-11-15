// server/core/guard.cpp - connection cap, per-IP limits, fair share and AIMD.
#include "core/guard.h"
#include "core/log.h"

#include <algorithm>
#include <mutex>
#include <string>
#include <unordered_map>

namespace guard {
namespace {

// Hard limits: server.ini tunes the values in between, but cannot switch the
// shields off entirely.
const int kHardMinPps = 100;
const int kHardMaxPps = 500000;
const int kMinPerSourcePps = 40;
const int kHardMaxConnections = 100000;
const int kHardMaxSources = 1000000;

struct Source {
    double tokens = 0.0;
    unsigned long long last_token_ms = 0;
    unsigned long long seen_ms = 0;
    unsigned long long connect_window_ms = 0;
    int connect_count = 0;
};

std::mutex g_mutex;
std::unordered_map<uint32_t, Source> g_sources;

// Live values derived from guard::Settings (server.ini).
int g_max_connections = 128;
int g_connect_limit = 10;
unsigned long long g_connect_window_ms = 10000;
size_t g_max_sources = 4096;
unsigned long long g_source_idle_ms = 30000;
unsigned long long g_log_interval_ms = 30000;
double g_min_budget = 5000.0;
double g_max_budget = 200000.0;
double g_budget = 20000.0;
int g_per_source_max_pps = 4000;

int g_active_connections = 0;

unsigned long long g_window_start_ms = 0;
unsigned long long g_window_packets = 0;
unsigned long long g_window_drops = 0;
unsigned long long g_window_refused = 0;

unsigned long long g_total_packets = 0;
unsigned long long g_total_drops = 0;
unsigned long long g_total_refused = 0;
unsigned long long g_last_log_ms = 0;
unsigned long long g_last_logged_drops = 0;
unsigned long long g_last_logged_refused = 0;
unsigned long long g_peak_pps = 0;

int clamp_int(int value, int low, int high) {
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

bool is_loopback(uint32_t ip) {
    return (ip & 0xFF000000u) == 0x7F000000u;
}

// Rendered while g_mutex is already held. It must not lock anything (the
// public stats() below is the locking entry point).
std::string render_stats_locked() {
    char text[320];
    const double drop_pct = g_total_packets == 0
                                ? 0.0
                                : 100.0 * (double)g_total_drops / (double)g_total_packets;
    std::snprintf(text, sizeof(text),
                  "budget %.0f pps (peak %llu), connections %d/%d, tracked sources %d, "
                  "dropped %llu (%.2f%%), refused %llu",
                  g_budget, g_peak_pps, g_active_connections, g_max_connections,
                  (int)g_sources.size(), g_total_drops, drop_pct, g_total_refused);
    return text;
}

// One second of burst, refilled continuously. Caller holds g_mutex.
bool take_token(Source& source, double rate, unsigned long long now) {
    const double elapsed = source.last_token_ms == 0
                               ? 1.0
                               : (double)(now - source.last_token_ms) / 1000.0;
    source.last_token_ms = now;
    source.tokens = std::min(rate, source.tokens + elapsed * rate);
    if (source.tokens < 1.0) {
        return false;
    }
    source.tokens -= 1.0;
    return true;
}

// Null when the table is full: a new (possibly spoofed) source is refused
// instead of growing the table without bound. Established senders keep their
// buckets and therefore their service. Caller holds g_mutex.
Source* source_for(uint32_t ip, unsigned long long now) {
    auto it = g_sources.find(ip);
    if (it != g_sources.end()) {
        it->second.seen_ms = now;
        return &it->second;
    }
    if (g_sources.size() >= g_max_sources) {
        return NULL;
    }
    Source fresh;
    fresh.seen_ms = now;
    return &g_sources.emplace(ip, fresh).first->second;
}

// Drop helper: caller holds g_mutex.
bool drop_locked() {
    g_window_drops++;
    g_total_drops++;
    return false;
}

void roll_window_locked(unsigned long long now) {
    if (g_window_start_ms == 0) {
        g_window_start_ms = now;
        return;
    }
    const unsigned long long elapsed = now - g_window_start_ms;
    if (elapsed < 1000) {
        return;
    }

    const double seconds = (double)elapsed / 1000.0;
    const double observed = (double)g_window_packets / seconds;
    g_peak_pps = std::max(g_peak_pps, (unsigned long long)observed);

    // AIMD: any drop inside the window means the relay is behind, so the budget
    // comes down; a clean window lets it creep back up. This is what makes the
    // server settle on a rate it can actually serve.
    if (g_window_drops > 0) {
        g_budget = std::max(g_min_budget, g_budget * 0.5);
    } else {
        g_budget = std::min(g_max_budget, g_budget * 1.1);
    }

    if (now - g_last_log_ms >= g_log_interval_ms) {
        const bool changed = g_total_drops != g_last_logged_drops ||
                             g_total_refused != g_last_logged_refused;
        if (changed) {
            g_last_log_ms = now;
            g_last_logged_drops = g_total_drops;
            g_last_logged_refused = g_total_refused;
            // srvlog has its own mutex and never calls back into guard, so
            // logging from here is safe; what is NOT safe is calling stats()
            // itself, because that would re-lock g_mutex on this thread.
            srvlog::event("GUARD", "", "", render_stats_locked());
        }
    }

    g_window_start_ms = now;
    g_window_packets = 0;
    g_window_drops = 0;
    g_window_refused = 0;
}

}  // namespace

void configure(const Settings& values) {
    std::lock_guard<std::mutex> lock(g_mutex);

    g_max_connections = clamp_int(values.max_connections, 1, kHardMaxConnections);

    g_max_budget = (double)clamp_int(values.max_budget_pps, kHardMinPps, kHardMaxPps);
    g_min_budget = (double)clamp_int(values.min_pps, kHardMinPps, (int)g_max_budget);
    g_budget = (double)clamp_int(values.max_pps, (int)g_min_budget, (int)g_max_budget);

    g_per_source_max_pps = clamp_int(values.per_ip_pps, kMinPerSourcePps, (int)g_max_budget);

    g_connect_limit = clamp_int(values.connect_limit, 1, kHardMaxConnections);
    g_connect_window_ms =
        (unsigned long long)clamp_int(values.connect_window_sec, 1, 3600) * 1000ull;

    g_max_sources = (size_t)clamp_int(values.source_table, 16, kHardMaxSources);
    g_source_idle_ms =
        (unsigned long long)clamp_int(values.source_idle_sec, 1, 3600) * 1000ull;
    g_log_interval_ms =
        (unsigned long long)clamp_int(values.log_interval_sec, 1, 3600) * 1000ull;

    // The table may have grown past a lowered cap; the eviction in tick() trims
    // it, and new sources are refused until then.
}

Settings settings() {
    std::lock_guard<std::mutex> lock(g_mutex);
    Settings values;
    values.max_connections = g_max_connections;
    values.max_pps = (int)g_budget;
    values.min_pps = (int)g_min_budget;
    values.max_budget_pps = (int)g_max_budget;
    values.per_ip_pps = g_per_source_max_pps;
    values.connect_limit = g_connect_limit;
    values.connect_window_sec = (int)(g_connect_window_ms / 1000ull);
    values.source_table = (int)g_max_sources;
    values.source_idle_sec = (int)(g_source_idle_ms / 1000ull);
    values.log_interval_sec = (int)(g_log_interval_ms / 1000ull);
    return values;
}

bool enter_connection(uint32_t src_ip) {
    const unsigned long long now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_mutex);

    // The local admin console and a client on this same machine must never be
    // refused by the shield.
    if (is_loopback(src_ip)) {
        g_active_connections++;
        return true;
    }

    if (g_active_connections >= g_max_connections) {
        g_window_refused++;
        g_total_refused++;
        return false;
    }

    Source* source = source_for(src_ip, now);
    if (source == NULL) {
        g_window_refused++;
        g_total_refused++;
        return false;
    }

    if (source->connect_window_ms == 0 ||
        now - source->connect_window_ms >= g_connect_window_ms) {
        source->connect_window_ms = now;
        source->connect_count = 0;
    }
    if (source->connect_count >= g_connect_limit) {
        g_window_refused++;
        g_total_refused++;
        return false;
    }
    source->connect_count++;
    g_active_connections++;
    return true;
}

void leave_connection() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_active_connections > 0) {
        g_active_connections--;
    }
}

bool allow_datagram(uint32_t src_ip, int len) {
    // Anything shorter than the smallest IP header cannot be forwarded, so it
    // is rejected before the (much more expensive) session lookup.
    if (len < 20) {
        std::lock_guard<std::mutex> lock(g_mutex);
        roll_window_locked(GetTickCount64());
        g_window_packets++;
        g_total_packets++;
        return drop_locked();
    }

    const unsigned long long now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_mutex);

    roll_window_locked(now);
    g_window_packets++;
    g_total_packets++;

    if (is_loopback(src_ip)) {
        return true;
    }

    // Global ceiling: once the window has spent the budget, everything else is
    // dropped until the next second. Without this a spoofed-source flood would
    // simply be spread over the source table.
    if ((double)g_window_packets > g_budget) {
        return drop_locked();
    }

    Source* source = source_for(src_ip, now);
    if (source == NULL) {
        return drop_locked();
    }

    // Fair share: the budget is divided between the senders that are actually
    // alive right now, so a new flooder increases the divisor and every peer
    // keeps a slice instead of one client taking the whole segment.
    const double active = (double)std::max<size_t>(1, g_sources.size());
    double share = g_budget / active;
    share = std::max<double>(kMinPerSourcePps,
                             std::min<double>(g_per_source_max_pps, share));

    if (!take_token(*source, share, now)) {
        return drop_locked();
    }
    return true;
}

void tick() {
    const unsigned long long now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_mutex);
    roll_window_locked(now);

    // Idle sources are forgotten so the fair-share divisor follows reality.
    for (auto it = g_sources.begin(); it != g_sources.end();) {
        if (now - it->second.seen_ms > g_source_idle_ms) {
            it = g_sources.erase(it);
        } else {
            ++it;
        }
    }
}

std::string stats() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return render_stats_locked();
}

}  // namespace guard
