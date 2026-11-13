// server/gateway/gateway.h
//
// TAP driver install, adapter discovery, gateway address/firewall/NAT setup,
// and the two TAP <-> relay threads.
#ifndef ROOTLAYER_SERVER_GATEWAY_H
#define ROOTLAYER_SERVER_GATEWAY_H

#include "core/win_headers.h"

#define TAP_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

bool is_admin_server();
bool adapter_connection_exists_server(const std::string& name);
void maybe_rename_gateway_adapter(std::string& adapter, const std::string& netsh);
bool setup_gateway();
void tap_writer_thread();
void gateway_to_relay_thread();
std::vector<std::string> tap_instance_ids_by_registry();
std::string adapter_friendly_name(const std::string& guid);
bool is_tap_friendly_name(const std::string& friendly_name);
bool run_hidden_command(const std::string& command_line, long long* exit_code);
void queue_tap_frame(const char* data, int len);

#endif  // ROOTLAYER_SERVER_GATEWAY_H
