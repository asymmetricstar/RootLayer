// client/core/utils.cpp - process, path, string and INI helpers.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"

// Helper to check if running as Administrator
bool is_admin() {
    BOOL isAdmin;
    SID_IDENTIFIER_AUTHORITY SIdAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup = NULL;
    if (AllocateAndInitializeSid(&SIdAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &isAdmin);
        FreeSid(pAdministratorsGroup);
    } else {
        isAdmin = FALSE;
    }
    return isAdmin != FALSE;
}

// Helper to get executable directory
std::string get_exe_dir() {
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

// Run a shell command and return its exit code.
DWORD run_command(const std::string& command) {
    std::string full_command = "cmd.exe /c " + command;

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::vector<char> cmdline(full_command.begin(), full_command.end());
    cmdline.push_back('\0');

    if (!CreateProcessA(NULL, cmdline.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create process. Error: " << GetLastError() << std::endl;
        return (DWORD)-1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode;
}

// Runs a program directly (no cmd.exe) and captures its combined output.
// Returns the exit code, -1 when the process could not start and -2 on
// timeout.
long long run_program_captured(const std::string& exe_path, const std::string& arguments, std::string& output, DWORD timeout_ms) {
    SECURITY_ATTRIBUTES security;
    ZeroMemory(&security, sizeof(security));
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    HANDLE read_pipe = NULL;
    HANDLE write_pipe = NULL;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) {
        return -1;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    si.hStdInput = INVALID_HANDLE_VALUE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::string command_line = "\"" + exe_path + "\"";
    if (!arguments.empty()) {
        command_line += " " + arguments;
    }
    std::vector<char> cmdline(command_line.begin(), command_line.end());
    cmdline.push_back('\0');

    if (!CreateProcessA(exe_path.c_str(), cmdline.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return -1;
    }
    CloseHandle(write_pipe);

    output.clear();
    DWORD started = GetTickCount();

    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) {
            break;
        }

        if (available > 0) {
            char buffer[4096];
            DWORD chunk = available > sizeof(buffer) ? (DWORD)sizeof(buffer) : available;
            DWORD read_bytes = 0;
            if (!ReadFile(read_pipe, buffer, chunk, &read_bytes, NULL) || read_bytes == 0) {
                break;
            }
            if (output.size() < 8192) {
                output.append(buffer, read_bytes);
            }
            continue;
        }

        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            break;
        }

        if (GetTickCount() - started > timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(read_pipe);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return -2;
        }

        Sleep(50);
    }

    DWORD exit_code = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(read_pipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code == STILL_ACTIVE) {
        return -2;
    }
    return (long long)exit_code;
}

// Sleep in small steps so the tray Exit item is handled quickly.
void sleep_or_shutdown(int milliseconds) {
    int waited = 0;
    while (waited < milliseconds && !g_shutdown) {
        Sleep(100);
        waited += 100;
    }
}

// True when the program was started with "--headless".
bool has_headless_argument() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        return false;
    }

    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--headless") {
            found = true;
        } else if (std::wstring(argv[i]) == L"--resolve") {
            if (i + 1 < argc) {
                std::wstring name = argv[++i];
                int needed = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), (int)name.size(), NULL, 0, NULL, NULL);
                std::string narrowed(needed, '\0');
                WideCharToMultiByte(CP_UTF8, 0, name.c_str(), (int)name.size(), &narrowed[0], needed, NULL, NULL);
                resolve_name = narrowed;
            }
            found = true;  // resolve implies headless output
        } else if (std::wstring(argv[i]).rfind(L"--resolve=", 0) == 0) {
            std::wstring name = std::wstring(argv[i]).substr(10);
            int needed = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), (int)name.size(), NULL, 0, NULL, NULL);
            std::string narrowed(needed, '\0');
            WideCharToMultiByte(CP_UTF8, 0, name.c_str(), (int)name.size(), &narrowed[0], needed, NULL, NULL);
            resolve_name = narrowed;
            found = true;
        }
    }
    LocalFree(argv);
    return found;
}

// A GUI subsystem process has no console, so the JSON events would vanish in
// a terminal. Attach to the console of the shell that started us - unless
// stdout is already a pipe/file (tests redirect it), which is left alone.
void attach_parent_console() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD type = (out == NULL || out == INVALID_HANDLE_VALUE) ? FILE_TYPE_UNKNOWN : GetFileType(out);

    // If stdout is already a file or pipe (tests redirect it), leave it alone.
    if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE) {
        return;
    }

    // Otherwise we are running in a console window without a console of our
    // own: attach to the parent's console so the JSON events are visible.
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        return;
    }
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
}

// Helper to ensure client.ini exists
bool ensure_client_ini_exists(const std::string& ini_file) {
    std::string exe_dir = get_exe_dir();
    std::string ini_full_path = exe_dir;
    ini_full_path += "\\";
    ini_full_path += ini_file;

    DWORD attr = GetFileAttributesA(ini_full_path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::ofstream out(ini_full_path);
        if (out.is_open()) {
            out << "[Settings]\n";
            out << "# Signaling server settings\n";
            out << "signaling_server_ip=127.0.0.1\n";
            out << "signaling_server_port=40000\n\n";
            out << "# static=1: same address on every start, 0: random address\n";
            out << "static=0\n";
            out << "# identity used when static=1 (generated when empty)\n";
            out << "identity=\n\n";
            out << "# Certificate subject fields (client certificate). The common\n";
            out << "# name (CN) is the virtual IP the server assigns. Empty fields\n";
            out << "# are left out of the certificate.\n";
            out << "user_name=\n";
            out << "user_email=\n";
            out << "city=\n";
            out << "state=\n";
            out << "country=\n\n";
            out << "# UDP tunnel settings\n";
            out << "udp_tunnel_port=50000\n";
            out.close();
        }
    }
    return true;
}

// Helper to load configuration from INI file
bool load_config_from_ini(const std::string& ini_file) {
    ensure_client_ini_exists(ini_file);

    std::string exe_dir = get_exe_dir();
    std::string ini_full_path = exe_dir;
    ini_full_path += "\\";
    ini_full_path += ini_file;

    char ip_buf[64];
    if (GetPrivateProfileStringA("Settings", "signaling_server_ip", "127.0.0.1", ip_buf, sizeof(ip_buf), ini_full_path.c_str())) {
        signaling_server_ip = std::string(ip_buf);
    }

    unsigned long port = GetPrivateProfileIntA("Settings", "signaling_server_port", 40000, ini_full_path.c_str());
    if (port > 0 && port <= 65535) {
        signaling_server_port = (int)port;
    }

    // The gateway (and the virtual TLD list) are never read from client.ini:
    // the signaling server reports both with the registration response, so a
    // moved network or renamed TLDs need no client-side configuration.

    unsigned long udp_port = GetPrivateProfileIntA("Settings", "udp_tunnel_port", 50000, ini_full_path.c_str());
    if (udp_port > 0 && udp_port <= 65535) {
        udp_tunnel_port = (uint16_t)udp_port;
    }

    // Read static/identity manually to avoid GetPrivateProfileString's
    // cross-process cache, which has been observed to return stale/empty
    // values for these keys.
    auto read_ini_value = [&ini_full_path](const std::string& key) -> std::string {
        std::ifstream in(ini_full_path.c_str());
        std::string line;
        bool in_section = false;
        while (std::getline(in, line)) {
            // strip trailing CR
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::string t = line;
            size_t first = t.find_first_not_of(" \t");
            if (first == std::string::npos) continue;
            if (t[first] == '[') {
                in_section = (t.find("[Settings]") != std::string::npos);
                continue;
            }
            if (t[first] == '#' || t[first] == ';') continue;
            if (!in_section) continue;
            size_t eq = t.find('=');
            if (eq == std::string::npos) continue;
            std::string k = t.substr(0, eq);
            size_t kb = k.find_first_not_of(" \t");
            size_t ke = k.find_last_not_of(" \t");
            if (kb == std::string::npos) continue;
            k = k.substr(kb, ke - kb + 1);
            if (k != key) continue;
            std::string v = t.substr(eq + 1);
            size_t vb = v.find_first_not_of(" \t");
            size_t ve = v.find_last_not_of(" \t");
            if (vb == std::string::npos) return "";
            return v.substr(vb, ve - vb + 1);
        }
        return "";
    };

    std::string static_str = read_ini_value("static");
    static_enabled = (static_str == "1");

    std::string id_value = read_ini_value("identity");
    size_t ib = id_value.find_first_not_of(" \t\r\n");
    size_t ie = id_value.find_last_not_of(" \t\r\n");
    client_identity = (ib == std::string::npos) ? "" : id_value.substr(ib, ie - ib + 1);

    // Certificate subject profile (E/CN/O/L/S/C). CN comes from the assigned
    // virtual IP at enrollment; the rest is this machine's user profile.
    profile_email = trim(read_ini_value("user_email"));
    profile_full_name = trim(read_ini_value("user_name"));
    profile_city = trim(read_ini_value("city"));
    profile_state = trim(read_ini_value("state"));
    profile_country = trim(read_ini_value("country"));
    if (profile_full_name.empty()) {
        // O = the Windows account that runs the client.
        char account[128] = {0};
        DWORD account_len = (DWORD)sizeof(account);
        if (GetUserNameA(account, &account_len) && account[0] != '\0') {
            profile_full_name = account;
        }
    }

    return true;
}

std::string trim(const std::string& text) {
    size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

// With static=1 the client keeps one identity and writes it to client.ini, so
// the server can map it to the same virtual IP on every start.
void ensure_client_identity(const std::string& ini_full_path) {
    if (!static_enabled || !client_identity.empty()) {
        return;
    }

    std::random_device device;
    unsigned long long high = ((unsigned long long)device() << 32) ^ (unsigned long long)device();
    unsigned long long low = ((unsigned long long)GetTickCount64() << 32) ^ (unsigned long long)device();

    char identity[33] = {0};
    std::snprintf(identity, sizeof(identity), "%016llx%016llx", high, low);
    client_identity = identity;

    WritePrivateProfileStringA("Settings", "identity", client_identity.c_str(), ini_full_path.c_str());
}

// Read a "KEY:value" token out of a space separated signaling response.
std::string token_value(const std::string& response, const std::string& key) {
    size_t pos = response.find(key + ":");
    if (pos == std::string::npos) {
        return "";
    }
    size_t start = pos + key.size() + 1;
    size_t end = response.find(' ', start);
    if (end == std::string::npos) {
        return trim(response.substr(start));
    }
    return trim(response.substr(start, end - start));
}

int token_int(const std::string& response, const std::string& key, int fallback) {
    std::string value = token_value(response, key);
    if (value.empty()) {
        return fallback;
    }
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0);
    if (len <= 0) {
        return std::wstring();
    }
    std::wstring out((size_t)len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], len);
    return out;
}
