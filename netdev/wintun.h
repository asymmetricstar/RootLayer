// netdev/wintun.h
//
// Minimal wrapper around wintun.dll (WireGuard's layer-3 TUN driver for
// Windows), shared by the server gateway and the client tunnel.
//
// The tunnel now carries bare IPv4/IPv6 packets instead of Ethernet frames:
// Wintun is a TUN device, so there is no MAC layer, no ARP and no broadcast at
// the link level. Addresses are configured with netsh on the adapter name.
#ifndef ROOTLAYER_NETDEV_WINTUN_H
#define ROOTLAYER_NETDEV_WINTUN_H

#include <windows.h>

#include <string>

namespace netdev {

// Loads wintun.dll from the executable directory (or PATH). False when the
// file or a required export is missing; error_text() then says why.
bool available();
std::string error_text();

// Creates the adapter, or opens it when a previous run left one behind.
// `name` is also the Windows interface alias used by netsh/PowerShell.
// A fixed `requested_guid` makes the adapter the same PnP device on every run,
// so Windows keeps its MAC address and its network profile (firewall/DNS).
bool create_adapter(const std::string& name, const std::string& tunnel_type,
                    const GUID* requested_guid);

// Starts the packet ring. Call after the adapter exists.
bool start_session();
bool is_open();

// One layer-3 packet (IPv4 or IPv6, no Ethernet header).
// Returns the packet size, 0 on timeout, -1 when the session ended.
int read_packet(char* buffer, int max_size, int timeout_ms);
bool write_packet(const char* data, int len);

// Ends the session and removes the adapter.
void close();

}  // namespace netdev

#endif  // ROOTLAYER_NETDEV_WINTUN_H
