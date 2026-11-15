// server/core/guard.h
//
// Basic DoS shields and self regulation for the server:
//
//   control plane (TCP signaling)
//     - hard cap on concurrent connection handlers, so a connection flood
//       cannot spawn unlimited threads; excess clients get "BUSY" and retry
//     - per-IP connect rate limit, so a reconnect loop cannot monopolise the
//       accept loop
//     - loopback (the local admin console and a local client) is never throttled
//
//   data plane (UDP relay)
//     - per-source fair share of a global packet budget: the budget is divided
//       between the active senders, so one flooding peer cannot starve the
//       others
//     - the budget itself moves like AIMD: cut down when datagrams are being
//       dropped, increased slowly while the relay keeps up. That is the "self
//       load balancing" part: the server adapts to the load instead of
//       collapsing under it.
//     - malformed (shorter than an IP header) datagrams are rejected before any
//       session lookup, which is the expensive part of the relay path
//
// Every number below can be changed from server.ini (the guard_* keys); the
// defaults here are what an unconfigured server uses.
#ifndef ROOTLAYER_SERVER_GUARD_H
#define ROOTLAYER_SERVER_GUARD_H

#include "core/win_headers.h"

namespace guard {

struct Settings {
    int max_connections = 128;      // concurrent signaling handlers
    int max_pps = 20000;            // relay packet budget, packets per second
    int min_pps = 5000;             // AIMD lower bound
    int max_budget_pps = 200000;    // AIMD upper bound
    int per_ip_pps = 4000;          // fair-share ceiling for one sender
    int connect_limit = 10;         // new connections per IP per window
    int connect_window_sec = 10;    // length of that window
    int source_table = 4096;        // max tracked senders (memory bound)
    int source_idle_sec = 30;       // forget a sender after this much silence
    int log_interval_sec = 30;      // minimum gap between GUARD log lines
};

// Applies the settings from server.ini. Values are clamped into a sane range,
// so a typo can never disable the shields completely.
void configure(const Settings& settings);

// What is in effect right now (for the startup line and the logs).
Settings settings();

// Control plane: reserve a handler slot for this peer. False means "refuse the
// connection"; the caller answers BUSY and closes. Every successful call must
// be paired with leave_connection().
bool enter_connection(uint32_t src_ip);
void leave_connection();

// Data plane: true when this datagram may be processed.
bool allow_datagram(uint32_t src_ip, int len);

// Housekeeping: rolls the 1 s window, adapts the budget, evicts idle sources
// and writes the periodic GUARD line. Cheap; called once per second.
void tick();

// One line for the log (locks internally, safe to call any time).
std::string stats();

}  // namespace guard

#endif  // ROOTLAYER_SERVER_GUARD_H
