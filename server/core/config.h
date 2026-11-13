// server/core/config.h
//
// server.ini create/load + IP pool calculation.
#ifndef ROOTLAYER_SERVER_CONFIG_H
#define ROOTLAYER_SERVER_CONFIG_H

#include "core/win_headers.h"

bool ensure_server_ini_exists(const std::string& ini_file);
bool load_server_config_from_ini(const std::string& ini_file);
std::string server_virtual_ip();

#endif  // ROOTLAYER_SERVER_CONFIG_H
