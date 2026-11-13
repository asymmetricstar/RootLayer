// console/core/config.h
//
// Where the console connects and how long it waits.
#ifndef ROOTLAYER_CONSOLE_CONFIG_H
#define ROOTLAYER_CONSOLE_CONFIG_H

#include <string>

struct ConsoleConfig {
    std::string server = "127.0.0.1";
    int port = 40000;
    int timeout_ms = 5000;
};

// Defaults from server.ini next to console.exe (local_ip, listening_port).
// A server bound to one local address only answers on that address, so the
// file is what makes the console work without any argument on the server
// machine. Missing file or keys leave the defaults untouched.
void load_ini_defaults(ConsoleConfig& config);

#endif  // ROOTLAYER_CONSOLE_CONFIG_H
