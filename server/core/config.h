// server/core/config.h
//
// server.ini create/load + IP pool calculation.
#ifndef ROOTLAYER_SERVER_CONFIG_H
#define ROOTLAYER_SERVER_CONFIG_H

#include "core/win_headers.h"

bool ensure_server_ini_exists(const std::string& ini_file);
bool load_server_config_from_ini(const std::string& ini_file);
std::string server_virtual_ip();

// Full path of the server.ini that was loaded, so the admin console can read
// and rewrite the same file the server started from.
std::string server_ini_path();

#endif  // ROOTLAYER_SERVER_CONFIG_H
