// console/core/config.cpp
#include "core/config.h"

#include <windows.h>

#include "core/files.h"
#include "core/text.h"

void load_ini_defaults(ConsoleConfig& config) {
    const std::string ini = join_path(exe_dir(), "server.ini");
    if (GetFileAttributesA(ini.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    char buffer[256] = {0};
    if (GetPrivateProfileStringA("Settings", "local_ip", "", buffer, sizeof(buffer), ini.c_str()) > 0) {
        const std::string local_ip = trim(buffer);
        if (!local_ip.empty()) {
            config.server = local_ip;
        }
    }

    const unsigned int port = GetPrivateProfileIntA("Settings", "listening_port", 0, ini.c_str());
    if (port > 0 && port <= 65535) {
        config.port = (int)port;
    }
}
