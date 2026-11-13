// server/session/session.cpp - session registry + IP assignment.
//
// Allocation order of the collision guards:
//   1. screen candidates against live sessions (active_ips) and the database
//      snapshot (db_taken_ips) - in memory, one query per allocation;
//   2. claim the winner atomically in the database (db_save_ip);
//   3. claim it for the session (claim_active_ip) - the final invariant
//      "one address, one session", checked at the point of insertion.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "db/store.h"
#include "session/session.h"
#include "gateway/gateway.h"

namespace {

// A usable pool address: inside the client range and not the server's own
// address (the range already excludes network and broadcast addresses).
bool ip_in_pool(uint32_t u) {
    return u >= virtual_ip_first_client && u <= virtual_ip_last &&
           u != virtual_ip_server;
}

// Screen one candidate: not the excluded address, not held by a live session
// and not mapped to an identity in the database.
bool ip_free(const std::string& candidate, const std::string& exclude,
             const std::unordered_set<std::string>& taken) {
    if (candidate == exclude || ip_active(candidate)) return false;
    return taken.find(candidate) == taken.end();
}

}  // namespace

bool ip_active(const std::string& ip) {
    return active_ips.find(ip) != active_ips.end();
}

// Final session-level guard: takes the address for the calling session.
// Returns false when a live session already holds it, so the caller can
// refuse the connection instead of running two sessions on one address.
// The caller holds sessions_mutex, which is what makes the check atomic.
bool claim_active_ip(const std::string& ip) {
    if (ip.empty()) return false;
    return active_ips.insert(ip).second;
}

std::string static_ip_for(const std::string& identity, const std::string& exclude) {
    // One query for everything already spoken for: the candidate screen below
    // then runs in memory instead of one SQL round trip per address (a /16
    // pool would otherwise issue up to 65k queries for a single client).
    std::unordered_set<std::string> taken = db_taken_ips();

    std::string existing = db_lookup_ip(identity);
    if (!existing.empty()) {
        const bool usable = existing != exclude && !ip_active(existing) &&
                            ip_in_pool(string_to_ip(existing));
        if (usable) {
            return existing;
        }
        // Stale rows (outside the usable range after a config change, or the
        // server address) and addresses seized by another session must not be
        // handed out - otherwise the client TAP configures an out-of-segment
        // IP and local ping never routes. Remap this identity instead.
        std::cerr << "Static address " << existing << " for " << identity
                  << " is stale or in use; assigning a free one" << std::endl;
    }

    // Walk the usable host range and claim the first free address. The claim
    // re-checks ownership inside the database critical section, so even an
    // external writer cannot make us double-book an address; when the claim
    // loses, the address is added to the screen and the walk continues.
    for (uint32_t cand = virtual_ip_first_client; cand <= virtual_ip_last; ++cand) {
        std::string candidate = ip_to_string(cand);
        if (!ip_free(candidate, exclude, taken)) {
            continue;
        }
        if (db_save_ip(identity, candidate)) {
            return candidate;
        }
        taken.insert(candidate);
    }
    return "";
}

std::string random_ip(const std::string& exclude) {
    static std::mt19937 rng((unsigned int)std::chrono::steady_clock::now().time_since_epoch().count());
    std::unordered_set<std::string> taken = db_taken_ips();

    uint32_t range_size = virtual_ip_last > virtual_ip_first_client ? (virtual_ip_last - virtual_ip_first_client + 1) : 0;
    std::uniform_int_distribution<uint32_t> dist(0, range_size > 0 ? range_size - 1 : 0);

    for (int attempt = 0; attempt < 200; ++attempt) {
        uint32_t cand = virtual_ip_first_client + dist(rng);
        std::string candidate = ip_to_string(cand);
        if (ip_free(candidate, exclude, taken)) {
            return candidate;
        }
    }

    // Deterministic fallback: a nearly full pool must not fail just because
    // the random probes happened to miss the few remaining holes.
    for (uint32_t cand = virtual_ip_first_client; cand <= virtual_ip_last; ++cand) {
        std::string candidate = ip_to_string(cand);
        if (ip_free(candidate, exclude, taken)) {
            return candidate;
        }
    }
    return "";
}

std::string assign_virtual_ip(const std::string& identity, const std::string& exclude) {
    if (!identity.empty()) {
        return static_ip_for(identity, exclude);
    }
    return random_ip(exclude);
}
void flood_to_sessions(const char* data, int len, const std::shared_ptr<Session>& except) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (const auto& session : online) {
        if (!session->endpoint_known || session == except) {
            continue;
        }
        sendto(relay_sock, data, len, 0, (sockaddr*)&session->endpoint, sizeof(session->endpoint));
    }
}
