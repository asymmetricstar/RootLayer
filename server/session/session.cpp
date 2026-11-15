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

#include <ctime>
#include <map>
#include <mutex>

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

// Address rows are keyed by the hardware id, so a machine keeps its address
// even if it is reinstalled with a different static identity string.
std::string client_db_key(const std::string& hw_id, const std::string& identity) {
    return hw_id.empty() ? identity : hw_id;
}

std::string static_ip_for(const std::string& client_key, const std::string& exclude) {
    if (client_key.empty()) {
        return "";
    }
    // One query for everything already spoken for: the candidate screen below
    // then runs in memory instead of one SQL round trip per address (a /16
    // pool would otherwise issue up to 65k queries for a single client).
    std::unordered_set<std::string> taken = db_taken_ips();

    std::string existing = db_lookup_ip(client_key);
    if (!existing.empty()) {
        const bool usable = existing != exclude && !ip_active(existing) &&
                            ip_in_pool(string_to_ip(existing));
        if (usable) {
            return existing;
        }
        // Stale rows (outside the usable range after a config change, or the
        // server address) and addresses seized by another session must not be
        // handed out - otherwise the client TAP configures an out-of-segment
        // IP and local ping never routes. Remap this client instead.
        std::cerr << "Persisted address " << existing << " for " << client_key
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
        if (db_save_ip(client_key, candidate)) {
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

std::string assign_virtual_ip(const std::string& client_key, const std::string& exclude) {
    if (!client_key.empty()) {
        return static_ip_for(client_key, exclude);
    }
    return random_ip(exclude);
}
void index_session(const std::shared_ptr<Session>& session) {
    if (!session) return;
    if (!session->virtual_ip.empty()) {
        sessions_by_ip[session->virtual_ip] = session;
    }
    if (session->endpoint_known) {
        sessions_by_endpoint[endpoint_key(session->endpoint)] = session;
    }
}

void unindex_session(const std::shared_ptr<Session>& session) {
    if (!session) return;
    auto ip_entry = sessions_by_ip.find(session->virtual_ip);
    if (ip_entry != sessions_by_ip.end() && ip_entry->second == session) {
        sessions_by_ip.erase(ip_entry);
    }
    if (session->endpoint_known) {
        auto ep_entry = sessions_by_endpoint.find(endpoint_key(session->endpoint));
        if (ep_entry != sessions_by_endpoint.end() && ep_entry->second == session) {
            sessions_by_endpoint.erase(ep_entry);
        }
    }
}

namespace {

// Last time each client key was heard from. Its own lock: the admin console
// reads it while the relay holds sessions_mutex.
std::mutex g_last_seen_mutex;
std::map<std::string, long long> g_last_seen;

}  // namespace

void note_client_seen(const std::string& client_key) {
    if (client_key.empty()) return;
    std::lock_guard<std::mutex> lock(g_last_seen_mutex);
    g_last_seen[client_key] = (long long)std::time(NULL);
}

long long client_last_seen(const std::string& client_key) {
    if (client_key.empty()) return 0;
    std::lock_guard<std::mutex> lock(g_last_seen_mutex);
    auto hit = g_last_seen.find(client_key);
    return hit == g_last_seen.end() ? 0 : hit->second;
}

std::string session_key_for_ip(const std::string& ip) {
    if (ip.empty()) return "";
    std::lock_guard<std::mutex> lock(sessions_mutex);
    auto hit = sessions_by_ip.find(ip);
    if (hit == sessions_by_ip.end() || !hit->second) return "";
    return client_db_key(hit->second->hw_id, hit->second->identity);
}

size_t online_member_count() {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    size_t count = 0;
    for (const auto& session : online) {
        if (!session || session->retired) continue;
        ++count;
    }
    return count;
}

// Same takeover the reconnect path uses: mark retired and close the control
// socket, which makes the client reconnect (release_session logs CLOSED).
bool retire_sessions_for_key(const std::string& client_key) {
    if (client_key.empty()) return false;
    bool retired = false;
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (const auto& session : online) {
        if (!session || session->retired) continue;
        if (client_db_key(session->hw_id, session->identity) != client_key) continue;
        session->retired = true;
        if (session->sock != INVALID_SOCKET) {
            closesocket(session->sock);
        }
        retired = true;
    }
    return retired;
}

void flood_to_sessions(const char* data, int len, const std::shared_ptr<Session>& except) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (const auto& session : online) {
        if (!session->endpoint_known || session == except) {
            continue;
        }
        // Per-client download cap, same bucket the relay uses.
        if (!session->download.allow((size_t)len)) {
            continue;
        }
        sendto(relay_sock, data, len, 0, (sockaddr*)&session->endpoint, sizeof(session->endpoint));
    }
}
