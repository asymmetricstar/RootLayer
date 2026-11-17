// client/tap/tap.h
//
// Tunnel device (Wintun, layer 3) creation and IP/firewall configuration.
// The names keep their historical "tap" prefix so the tunnel code does not
// depend on the driver behind the device.
#ifndef ROOTLAYER_TAP_H
#define ROOTLAYER_TAP_H

#include "core/win_headers.h"

// Adapter creation (Wintun installs its own signed driver).
bool install_tap_driver();
bool find_available_tap_adapter(std::string& instance_guid, std::string& connection_name);
void reset_tap_detection();
bool adapter_connection_exists(const std::string& adapter_name);
bool ensure_tap_adapter();

// Adapter identity: the Windows interface alias, which is also the netsh name.
std::string get_tap_device_name();
std::string get_tap_adapter_name();

// IP, DNS, firewall rule and MTU setup; packet session + link state.
bool configure_tap_adapter(const std::string& ip, const std::string& gateway,
                           const std::string& mask, const std::string& gateway2);
void prepare_tap_adapter(const std::string& adapter);
bool open_tap_device(const std::string& tap_name);
bool set_tap_media_status(bool connected);

// Virtual TLD resolution. Both values come from the server registration
// response (GATEWAY and TLD tokens); the client keeps no built-in address or
// TLD list. An empty list removes every rule this client created.
// Routes for the address blocks of the other federation servers (ROUTES token).
// They point at the tunnel gateway, so traffic for a block that is not part of
// this client's subnet still enters the tunnel. The client's own address, mask
// and configuration never change; the set is reconciled on every server state,
// so a server that joins or leaves adds or removes its route automatically.
void apply_tunnel_routes(const std::vector<std::string>& prefixes);
void clear_tunnel_routes();
// True when the installed routes already match what the server reports.
bool tunnel_routes_current(const std::string& gateway,
                           const std::vector<std::string>& prefixes);

void set_tunnel_dns_namespaces(const std::vector<std::string>& namespaces);
void apply_tunnel_dns_rules(const std::string& gateway);
void clear_tunnel_dns_rules();
bool tunnel_dns_rules_current(const std::string& gateway);

#endif  // ROOTLAYER_TAP_H
