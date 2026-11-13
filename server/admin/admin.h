// server/admin/admin.h
//
// Administrative command surface for the RootLayer console (console/).
//
// The console is a separate project and binary. It changes the server's
// records through this request/answer protocol on the signaling port, so every
// change goes through the RUNNING server: the domain.db write buffer, the live
// TLD set and the in-memory CA stay authoritative. Editing the database file
// behind the server's back would be overwritten by its write-behind buffer.
#ifndef ROOTLAYER_SERVER_ADMIN_H
#define ROOTLAYER_SERVER_ADMIN_H

#include "core/win_headers.h"

// True when the peer may run admin commands: the machine itself (loopback) or
// the single local address the server is bound to.
bool admin_peer_allowed(const sockaddr_in& peer);

// Executes one "ADMIN <COMMAND> [KEY:value ...]" line. Always fills `response`
// with "ADMIN_OK ..." or "ADMIN_ERR:<code>"; returns false when it failed.
bool admin_request(const std::string& request, std::string& response);

#endif  // ROOTLAYER_SERVER_ADMIN_H
