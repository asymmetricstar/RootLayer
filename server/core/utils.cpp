// server/core/utils.cpp - process, path, string and token helpers.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/utils.h"

// Helper to get executable directory
std::string get_exe_dir_server() {
    char buffer[MAX_PATH];
    if (GetModuleFileName(NULL, buffer, MAX_PATH) == 0) {
        return ".";
    }
    std::string exe_path = std::string(buffer);
    size_t pos = exe_path.find_last_of('\\');
    if (pos == std::string::npos) {
        pos = exe_path.find_last_of('/');
    }
    if (pos != std::string::npos) {
        return exe_path.substr(0, pos);
    }
    return ".";
}
std::string trim(const std::string& text) {
    size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}
std::string token_value(const std::string& text, const std::string& key) {
    size_t pos = text.find(key + ":");
    if (pos == std::string::npos) {
        return "";
    }
    size_t start = pos + key.size() + 1;
    size_t end = text.find(' ', start);
    std::string value = (end == std::string::npos) ? text.substr(start) : text.substr(start, end - start);
    return trim(value);
}
int token_int(const std::string& text, const std::string& key, int fallback) {
    size_t pos = text.find(key + ":");
    if (pos == std::string::npos) {
        return fallback;
    }
    size_t start = pos + key.size() + 1;
    size_t end = text.find(' ', start);
    std::string value = (end == std::string::npos) ? text.substr(start) : text.substr(start, end - start);
    value = trim(value);
    if (value.empty()) {
        return fallback;
    }
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}
void send_line(SOCKET sock, const std::string& text) {
    std::string line = text + "\n";
    send(sock, line.c_str(), (int)line.size(), 0);
}
bool socket_alive(SOCKET sock) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);

    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int ready = select(0, &read_set, NULL, NULL, &timeout);
    if (ready == SOCKET_ERROR) {
        return false;
    }
    if (ready == 0) {
        return true;  // nothing pending, assume the connection is still open
    }

    char buffer[64];
    int len = recv(sock, buffer, sizeof(buffer), 0);
    if (len > 0) {
        return true;  // keepalive data
    }
    if (len == 0) {
        return false;
    }
    return WSAGetLastError() == WSAEWOULDBLOCK;
}
