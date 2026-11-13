
// client/core/utils.h
//
// Small process, path, string and INI helpers used across the client.
#ifndef ROOTLAYER_UTILS_H
#define ROOTLAYER_UTILS_H

#include "core/win_headers.h"

bool is_admin();
std::string get_exe_dir();
DWORD run_command(const std::string& command);
long long run_program_captured(const std::string& exe_path, const std::string& arguments,
                               std::string& output, DWORD timeout_ms);
void sleep_or_shutdown(int milliseconds);

// "--headless" / "--resolve <name>" command line parsing (sets resolve_name).
bool has_headless_argument();
void attach_parent_console();

// client.ini create/load + static identity handling.
bool ensure_client_ini_exists(const std::string& ini_file);
bool load_config_from_ini(const std::string& ini_file);
void ensure_client_identity(const std::string& ini_full_path);

std::string trim(const std::string& text);
std::wstring widen(const std::string& text);

// "KEY:value" token parsing of space separated signaling responses.
std::string token_value(const std::string& response, const std::string& key);
int token_int(const std::string& response, const std::string& key, int fallback);

#endif  // ROOTLAYER_UTILS_H
