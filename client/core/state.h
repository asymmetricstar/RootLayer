
// client/core/state.h
//
// Global client state shared by the tunnel core, TAP handling, signaling,
// tray and status panel. Defined once in core/state.cpp.
#ifndef ROOTLAYER_STATE_H
#define ROOTLAYER_STATE_H

#include "core/win_headers.h"

// Configuration (from client.ini)
extern std::string signaling_server_ip;
extern int signaling_server_port;
extern uint16_t udp_tunnel_port;

// State filled in by the signaling server
extern std::string virtual_ip;
extern uint16_t relay_port;
extern std::string gateway_ip;
extern std::string tap_mask;
extern std::string configured_ip;
extern std::string configured_gateway;
extern std::string configured_mask;
extern bool ip_applied;

// Set by the tray menu when the user chooses Exit.
extern std::atomic<bool> g_shutdown;

// True when the Qt panel owns the GUI (tunnel then runs in a worker thread).
extern bool g_qt_ui;

// Members reported by the server for the shared segment (shown in the panel).
extern std::atomic<int> peer_count;

// static=1 in client.ini: stable identity so the server assigns the same IP.
extern int static_enabled;
extern std::string client_identity;

// Certificate subject profile (client certificate). The CN is the virtual IP
// the server assigns; these are the human readable fields from client.ini.
extern std::string profile_full_name;  // O  - user name
extern std::string profile_email;      // E  - user@mail.tld
extern std::string profile_city;       // L  - city
extern std::string profile_state;      // ST - state / province
extern std::string profile_country;    // C  - two letter country code

// "--headless" prints JSON events to the terminal, no tray/panel.
extern bool headless_mode;
extern std::string resolve_name;

extern SOCKET udp_sock;
extern HANDLE tap_device;

// Tunnel counters, reported as a "stats" event every few seconds.
extern std::atomic<unsigned long long> frames_from_tap;
extern std::atomic<unsigned long long> frames_to_tap;

// Destination of the UDP tunnel (updated on every reconnect / NAT rewrite).
extern std::mutex tunnel_mutex;
extern sockaddr_in peer_addr;
extern bool peer_valid;

// Fallback target used until the first peer packet arrives so the relay
// learns this client's UDP endpoint (NAT hole punching).
extern sockaddr_in fallback_target;
extern bool fallback_target_valid;

// Control channel to the signaling server (stays open while connected).
extern SOCKET control_sock;
extern std::mutex control_mutex;
extern std::condition_variable control_cv;
extern bool peer_lost;

// Set when a server-pushed STATE line changed the gateway/TLD list: the tunnel
// loop re-applies the adapter and resolver settings without reconnecting.
// Guarded by control_mutex.
extern bool server_config_dirty;

#endif  // ROOTLAYER_STATE_H
