// server/session/session.h
//
// Session registry: every connected client is a member of the shared
// layer-2 segment. IP assignment (static via db, or random).
#ifndef ROOTLAYER_SERVER_SESSION_H
#define ROOTLAYER_SERVER_SESSION_H

#include <memory>

#include "core/ratelimit.h"
#include "core/win_headers.h"

struct Session {
    SOCKET sock = INVALID_SOCKET;
    // Legacy static identity ("static=1" clients). Not used for address
    // persistence any more: client.db is keyed by hw_id; this is only the
    // fallback key for old clients that send no HWID.
    std::string identity;
    // Permanent hardware id the client sends (aa:bb:cc:dd:ee:ff). The server
    // log identifies a member by this, never by its public address.
    std::string hw_id;
    // Random per-process id the client sends with CLIENT_REQ (INSTANCE:).
    // Empty for legacy clients that do not send one.
    std::string instance;
    std::string public_ip;
    uint16_t udp_port = 50000;
    std::string virtual_ip;
    sockaddr_in endpoint;
    bool endpoint_known = false;
    bool retired = false;

    // Per-client bandwidth caps, charged for the frames actually forwarded.
    // upload = client -> segment, download = segment -> client; rate 0 means
    // unlimited. Touched only under sessions_mutex.
    RateLimit upload;
    RateLimit download;
};

bool ip_active(const std::string& ip);

// Keeps sessions_by_ip / sessions_by_endpoint in sync with `online`. Both
// require sessions_mutex to be held and are cheap (two hash operations), so
// call them on join, on endpoint learning and on leave instead of scanning.
void index_session(const std::shared_ptr<Session>& session);
void unindex_session(const std::shared_ptr<Session>& session);

// Atomically take ip for the calling session; false when a live session
// already holds it (caller holds sessions_mutex). Last line of defense
// against handing one address to two sessions.
bool claim_active_ip(const std::string& ip);

// The key that owns a client's address row in client.db: the hardware id
// whenever the client has one (every current client does), else the legacy
// static identity string. This is the single identity used for address
// persistence and for the "one client, one session" checks.
std::string client_db_key(const std::string& hw_id, const std::string& identity);

// Client key of the live session that holds `ip` ("" when no session does).
std::string session_key_for_ip(const std::string& ip);

// How many live members the server currently has. Read on every STATE answer,
// so a connected client sees a peer join or leave without reconnecting.
size_t online_member_count();

// When a client key was last seen (connect or disconnect), in unix seconds;
// 0 means "not seen since this server start". Memory only.
void note_client_seen(const std::string& client_key);
long long client_last_seen(const std::string& client_key);

// Drops the live session(s) of one client key: the socket is closed, so the
// client reconnects and picks up the address the admin just set or cleared.
// Returns true when a session was retired.
bool retire_sessions_for_key(const std::string& client_key);

std::string static_ip_for(const std::string& client_key, const std::string& exclude);
std::string random_ip(const std::string& exclude);
std::string assign_virtual_ip(const std::string& client_key, const std::string& exclude);
void flood_to_sessions(const char* data, int len, const std::shared_ptr<Session>& except);

#endif  // ROOTLAYER_SERVER_SESSION_H
