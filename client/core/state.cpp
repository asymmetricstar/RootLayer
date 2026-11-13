// client/core/state.cpp - global client state (see core/state.h).
#include "core/win_headers.h"
#include "core/state.h"

// Configuration variables
std::string signaling_server_ip = "127.0.0.1";
int signaling_server_port = 40000;
uint16_t udp_tunnel_port = 50000;

// State filled in by the signaling server
std::string virtual_ip;
uint16_t relay_port = 40001;
std::string gateway_ip = "";
std::string tap_mask = "255.255.255.0";  // default /24, updated from server MASK: field
std::string configured_ip = "";
std::string configured_gateway = "";
std::string configured_mask = "";
bool ip_applied = false;

// Set by the tray menu when the user chooses Exit.
std::atomic<bool> g_shutdown(false);

// True when the Qt panel owns the GUI: the tunnel then runs in a worker thread
// and the Win32 tray/panel window is not created.
bool g_qt_ui = false;

// Members reported by the server for the shared segment (shown in the panel).
std::atomic<int> peer_count(0);

// static=1 in client.ini: the client sends a stable identity so the server
// always assigns the same virtual IP.
int static_enabled = 0;
std::string client_identity;

// Certificate subject profile: shown in the client certificate (O, E, L, ST,
// C). The CN is the virtual IP, filled in at enrollment time.
std::string profile_full_name;
std::string profile_email;
std::string profile_city;
std::string profile_state;
std::string profile_country;

// ARPA: name this client would register (server-side only, admin adds names
// to domain.db). Kept for reference but disabled: clients do not auto-register.
// std::string arpa_name;

// "--headless" prints the JSON events to the terminal and starts no tray or
// status panel. Without the flag the program is a plain GUI application and
// never shows a console window.
bool headless_mode = false;
std::string resolve_name;

SOCKET udp_sock = INVALID_SOCKET;
HANDLE tap_device = INVALID_HANDLE_VALUE;

// Tunnel counters, reported as a "stats" event every few seconds.
std::atomic<unsigned long long> frames_from_tap(0);
std::atomic<unsigned long long> frames_to_tap(0);

// Destination of the UDP tunnel. Updated on every (re)connection, and switched
// to the source address of incoming packets in case a NAT rewrote the port.
std::mutex tunnel_mutex;
sockaddr_in peer_addr;
bool peer_valid = false;

// Fallback target used until the first peer packet arrives. tap_to_udp_thread
// sends to this address when peer_valid is false, so the relay learns this
// client's UDP endpoint and NAT hole punching works. Without it, all outbound
// TAP frames are dropped and the tunnel stays silent.
sockaddr_in fallback_target;
bool fallback_target_valid = false;

// Control channel to the signaling server. It stays open while the tunnel is
// active so the server can report that the peer disappeared.
SOCKET control_sock = INVALID_SOCKET;
std::mutex control_mutex;
std::condition_variable control_cv;
bool peer_lost = false;
bool server_config_dirty = false;
