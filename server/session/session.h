// server/session/session.h
//
// Session registry: every connected client is a member of the shared
// layer-2 segment. IP assignment (static via db, or random).
#ifndef ROOTLAYER_SERVER_SESSION_H
#define ROOTLAYER_SERVER_SESSION_H

#include "core/win_headers.h"

struct Session {
    SOCKET sock = INVALID_SOCKET;
    std::string identity;
    // Random per-process id the client sends with CLIENT_REQ (INSTANCE:).
    // Empty for legacy clients that do not send one.
    std::string instance;
    std::string public_ip;
    uint16_t udp_port = 50000;
    std::string virtual_ip;
    sockaddr_in endpoint;
    bool endpoint_known = false;
    bool retired = false;
};

bool ip_active(const std::string& ip);

// Atomically take ip for the calling session; false when a live session
// already holds it (caller holds sessions_mutex). Last line of defense
// against handing one address to two sessions.
bool claim_active_ip(const std::string& ip);

std::string static_ip_for(const std::string& identity, const std::string& exclude);
std::string random_ip(const std::string& exclude);
std::string assign_virtual_ip(const std::string& identity, const std::string& exclude);
void flood_to_sessions(const char* data, int len, const std::shared_ptr<Session>& except);

#endif  // ROOTLAYER_SERVER_SESSION_H
