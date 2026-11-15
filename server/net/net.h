// server/net/net.h
//
// Relay thread (UDP frames) and the control channel: handle_request() is the
// socket-free protocol handler, signaling_run() (net/signaling.h) drives it from
// one poll loop.
#ifndef ROOTLAYER_SERVER_NET_H
#define ROOTLAYER_SERVER_NET_H

#include "core/win_headers.h"

#include <memory>

struct Session;

void relay_thread();

// Processes one complete control request. Returns the bytes to send back (no
// trailing newline), sets `closes` when the connection ends afterwards and
// hands back the new session for a successful registration.
std::string handle_request(const std::string& request, const sockaddr_in& peer_addr,
                           bool& closes, std::shared_ptr<Session>& session);

// " GATEWAY:... MASK:... TLD:... BAND:up:down" for registration and STATE
// answers. BAND (kbit/s per direction, 0 = unlimited) needs the session, so it
// is only added when one is passed.
std::string server_network_state_tokens(const Session* session = nullptr);

// Removes a session from the registry and logs CLOSED (idempotent).
void release_session(const std::shared_ptr<Session>& session);

#endif  // ROOTLAYER_SERVER_NET_H
