// client/ui/shared_state.h
//
// Shared, thread-safe state exchanged between the tunnel core (client.cpp) and
// the Qt status panel (ui/ui_panel_qt.cpp). All accessors are atomic so the UI
// thread can read them without locking the tunnel thread.
#ifndef P2P_SHARED_STATE_H
#define P2P_SHARED_STATE_H

#include <atomic>
#include <string>

extern std::string virtual_ip;
extern std::string gateway_ip;
extern std::atomic<bool> g_shutdown;
extern std::atomic<long long> panel_connected_since;  // unix seconds, 0 = offline
extern std::atomic<int> panel_ping_ms;                // -1 = no answer yet
// Root server domain zone system probed over the signaling port:
// 0 = checking, 1 = zone answering (green), 2 = zone down (red).
extern std::atomic<int> panel_zone_status;
extern std::atomic<unsigned long long> frames_from_tap;
extern std::atomic<unsigned long long> frames_to_tap;
extern std::atomic<int> peer_count;                   // members reported by the server

// Address the panel currently pings: the server-reported gateway, or the
// signaling server when the server offers no gateway. Empty when unknown.
std::string panel_ping_target_value();

// Request a clean shutdown from the tray menu.
void tray_request_exit();

#endif  // P2P_SHARED_STATE_H