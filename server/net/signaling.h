// server/net/signaling.h
//
// Control plane (TCP signaling) served by one WSAPoll loop instead of one
// thread per client. Every connection is a small state machine with its own
// input/output buffer, so a few thousand clients cost a few thousand buffers
// and no extra threads.
#ifndef ROOTLAYER_SERVER_SIGNALING_H
#define ROOTLAYER_SERVER_SIGNALING_H

#include "core/win_headers.h"

// Runs on the calling thread until relay_running goes false.
void signaling_run(SOCKET listen_sock);

#endif  // ROOTLAYER_SERVER_SIGNALING_H
