// server/core/globals.h
//
// Global server state shared by config, db, arpa, dns, session, gateway and net.
// Defined once in core/globals.cpp.
#ifndef ROOTLAYER_SERVER_GLOBALS_H
#define ROOTLAYER_SERVER_GLOBALS_H

#include "core/win_headers.h"

#include <unordered_map>

struct Session;

// Configuration (from server.ini)
extern int signaling_port;
extern int relay_port;
extern bool gateway_enabled;
extern bool nat_enabled;

extern std::string arpa_suffix;
extern std::set<std::string> arpa_suffixes;

// IP pool
extern uint32_t virtual_ip_network;
extern uint32_t virtual_ip_mask;
extern int virtual_ip_prefix_len;
extern uint32_t virtual_ip_server;
extern uint32_t virtual_ip_first_client;
extern uint32_t virtual_ip_last;

// Local listen address
extern std::string server_local_ip;
// Message of the day from server.ini (motd=). Sent to every client that
// registers and shown in its panel; empty = no message. It can be changed at
// runtime from the admin console, so readers take a copy through the accessor
// instead of touching the string while it is being replaced.
std::string server_motd_value();
void set_server_motd(const std::string& text);
extern uint32_t server_local_ip_u32;

// SQLite handles
extern sqlite3* client_db;
extern std::mutex db_mutex;
extern sqlite3* arpa_db;
extern std::mutex arpa_mutex;

// Gateway / relay globals
// True while the gateway adapter has an open Wintun session; the relay writes
// every packet that belongs to the segment into it.
extern std::atomic<bool> gateway_active;
extern std::string gateway_adapter_name;
extern SOCKET relay_sock;
extern std::atomic<bool> relay_running;
extern std::atomic<bool> server_ready;

// TAP transmit queue
extern std::mutex tap_tx_mutex;
extern std::condition_variable tap_tx_cv;
extern std::deque<std::vector<char>> tap_tx_queue;
extern bool tap_tx_stop;
extern long long tap_tx_dropped;
extern const size_t tap_tx_max_frames;

// Session registry
extern std::mutex sessions_mutex;
extern std::vector<std::shared_ptr<Session>> online;
extern std::set<std::string> active_ips;

// Fast lookups for the relay hot path. Both are kept in sync with `online`
// under the same mutex:
//   sessions_by_ip       virtual IP -> session (directed forwarding)
//   sessions_by_endpoint (source address << 16 | port) -> session, filled when
//                        the endpoint is learned (steady-state source lookup)
extern std::unordered_map<std::string, std::shared_ptr<Session>> sessions_by_ip;
extern std::unordered_map<unsigned long long, std::shared_ptr<Session>> sessions_by_endpoint;

// Key for sessions_by_endpoint: host-order address in the high bits, port low.
unsigned long long endpoint_key(const sockaddr_in& address);

#endif  // ROOTLAYER_SERVER_GLOBALS_H
