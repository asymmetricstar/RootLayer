
// client/net/signaling.h
//
// Signaling (TCP control channel), relay address handling and UDP bind.
#ifndef ROOTLAYER_SIGNALING_H
#define ROOTLAYER_SIGNALING_H

#include "core/win_headers.h"

// Result of reading one newline-terminated line from a socket.
enum ReadResult {
    READ_OK,
    READ_TIMEOUT,
    READ_FAILED
};

ReadResult read_line_socket(SOCKET sock, std::string& line);

// Every frame travels through the server relay (shared 10.0.0.0/24 segment).
bool update_relay_address();

// One signaling attempt; keeps the connection open as the control channel.
bool request_peer();

// Keeps the control channel alive with PING, reports a lost peer.
void control_thread_fn();

bool bind_udp_socket();

#endif  // ROOTLAYER_SIGNALING_H
