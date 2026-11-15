// server/gateway/gateway.h
//
// Gateway adapter (Wintun, layer 3): address/firewall/NAT setup and the two
// adapter <-> relay threads.
#ifndef ROOTLAYER_SERVER_GATEWAY_H
#define ROOTLAYER_SERVER_GATEWAY_H

#include "core/win_headers.h"

bool is_admin_server();
bool adapter_connection_exists_server(const std::string& name);
bool setup_gateway();
void tap_writer_thread();
void gateway_to_relay_thread();
bool run_hidden_command(const std::string& command_line, long long* exit_code);
void queue_tap_frame(const char* data, int len);

#endif  // ROOTLAYER_SERVER_GATEWAY_H
