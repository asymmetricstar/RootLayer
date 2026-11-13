// console/net/admin_client.h
//
// Transport only: one request line out, one answer line in, over the server's
// signaling port. The console never opens the server's databases itself.
#ifndef ROOTLAYER_CONSOLE_ADMIN_CLIENT_H
#define ROOTLAYER_CONSOLE_ADMIN_CLIENT_H

#include <string>

#include "core/config.h"

struct AdminResult {
    bool ok = false;                // the server accepted the command
    bool transport_failed = false;  // could not reach or read from the server
    std::string error;              // "ADMIN_ERR:code" code or a transport reason
    std::string response;           // the full answer line
};

class AdminClient {
public:
    explicit AdminClient(const ConsoleConfig& config);

    // Sends "line\n" and reads the answer. Never throws.
    AdminResult request(const std::string& line);

    // request() plus the ADMIN_OK / ADMIN_ERR:<code> verdict.
    AdminResult call(const std::string& line);

private:
    ConsoleConfig config_;
};

#endif  // ROOTLAYER_CONSOLE_ADMIN_CLIENT_H
