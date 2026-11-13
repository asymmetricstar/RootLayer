// server/net/net.h
//
// Relay thread (UDP frame flood) and TCP signaling client handler.
#ifndef ROOTLAYER_SERVER_NET_H
#define ROOTLAYER_SERVER_NET_H

#include "core/win_headers.h"

void relay_thread();
void handle_client(SOCKET client_sock, sockaddr_in client_addr);

#endif  // ROOTLAYER_SERVER_NET_H
