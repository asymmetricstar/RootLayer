// server/core/utils.h
//
// Process, path, string and token helpers used across the server.
#ifndef ROOTLAYER_SERVER_UTILS_H
#define ROOTLAYER_SERVER_UTILS_H

#include "core/win_headers.h"

std::string get_exe_dir_server();
uint32_t string_to_ip(const std::string& ip);
std::string ip_to_string(uint32_t ip);
std::string trim(const std::string& text);
std::string token_value(const std::string& text, const std::string& key);
int token_int(const std::string& text, const std::string& key, int fallback);
void send_line(SOCKET sock, const std::string& text);
bool socket_alive(SOCKET sock);
std::string narrow(const std::wstring& text);

#endif  // ROOTLAYER_SERVER_UTILS_H
