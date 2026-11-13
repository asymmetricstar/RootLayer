// server/core/globals.h
//
// Global server state shared by config, db, arpa, dns, session, gateway and net.
// Defined once in core/globals.cpp.
#ifndef ROOTLAYER_SERVER_GLOBALS_H
#define ROOTLAYER_SERVER_GLOBALS_H

#include "core/win_headers.h"

struct Session;

// Configuration (from server.ini)
extern int signaling_port;
extern int relay_port;
extern bool gateway_enabled;
extern bool nat_enabled;
extern std::string virtual_ip_prefix;
extern int virtual_ip_start_octet;
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
extern uint32_t server_local_ip_u32;

// SQLite handles
extern sqlite3* client_db;
extern std::mutex db_mutex;
extern sqlite3* arpa_db;
extern std::mutex arpa_mutex;

// Gateway / relay globals
extern HANDLE gateway_tap;
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

#endif  // ROOTLAYER_SERVER_GLOBALS_H
