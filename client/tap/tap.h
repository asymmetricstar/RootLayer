
// client/tap/tap.h
//
// TAP driver install, adapter discovery and IP/firewall configuration.
#ifndef ROOTLAYER_TAP_H
#define ROOTLAYER_TAP_H

#include "core/win_headers.h"

// The header lives in resources/tap/. The include path depends on whether the
// including file sits in client/ or client/tap/ and on the -I. project root.
#if defined(__has_include)
#  if __has_include("../../resources/tap/tap-windows.h")
#    include "../../resources/tap/tap-windows.h"
#  elif __has_include("../resources/tap/tap-windows.h")
#    include "../resources/tap/tap-windows.h"
#  else
#    include "resources/tap/tap-windows.h"
#  endif
#else
#  include "../../resources/tap/tap-windows.h"
#endif

// Driver package install + adapter creation (admin).
bool install_tap_driver();
bool find_available_tap_adapter(std::string& instance_guid, std::string& connection_name);
void reset_tap_detection();
bool adapter_connection_exists(const std::string& adapter_name);
bool ensure_tap_adapter();

// Adapter lookup (user mode device path / connection name).
std::string get_tap_device_name();
std::string get_tap_adapter_name();

// IP, DNS, firewall rule and MTU setup; open + media status of the handle.
bool configure_tap_adapter(const std::string& ip, const std::string& gateway,
                           const std::string& mask, const std::string& gateway2);
void prepare_tap_adapter(const std::string& adapter);
bool open_tap_device(const std::string& tap_name);
bool set_tap_media_status(bool connected);

// Virtual TLD resolution. Both values come from the server registration
// response (GATEWAY and TLD tokens); the client keeps no built-in address or
// TLD list. An empty list removes every rule this client created.
void set_tunnel_dns_namespaces(const std::vector<std::string>& namespaces);
void apply_tunnel_dns_rules(const std::string& gateway);
void clear_tunnel_dns_rules();
bool tunnel_dns_rules_current(const std::string& gateway);

#endif  // ROOTLAYER_TAP_H
