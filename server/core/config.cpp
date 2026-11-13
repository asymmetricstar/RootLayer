// server/core/config.cpp - server.ini create/load + IP pool calculation.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"

// Helper to ensure server.ini exists
bool ensure_server_ini_exists(const std::string& ini_file) {
    std::string exe_dir = get_exe_dir_server();
    std::string ini_full_path = exe_dir + "\\" + ini_file;

    DWORD attr = GetFileAttributesA(ini_full_path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::ofstream out(ini_full_path);
        if (out.is_open()) {
            out << "[Settings]\n";
            out << "# Signaling (control) port\n";
            out << "listening_port=40000\n\n";
            out << "# Relay (data) port: client frames travel through this UDP port\n";
            out << "relay_port=40001\n\n";
            out << "# Act as gateway on 10.0.0.1 (opens the TAP adapter on the server)\n";
            out << "tap_gateway=1\n\n";
            out << "# NAT the virtual network to the internet (admin + WinNat required)\n";
            out << "nat=0\n\n";
            out << "# Local Area IP the server binds to (example: 192.168.1.101).\n";
            out << "# Empty = listen on every interface (0.0.0.0). Relay + signaling use it.\n";
            out << "local_ip=\n\n";
            out << "# TLD name service: name -> virtual IP records (separate domain.db)\n";
            out << "# Virtual IP pool base / gateway (example: 192.168.1.1 to start there)\n";
            out << "gateway_ip=10.0.0.1\n";
            out.close();
            std::cout << "Created default server configuration: " << ini_full_path << std::endl;
        }
    }
    return true;
}
// Helper to load server configuration from INI file
bool load_server_config_from_ini(const std::string& ini_file) {
    ensure_server_ini_exists(ini_file);

    std::string exe_dir = get_exe_dir_server();
    std::string ini_full_path = exe_dir + "\\" + ini_file;

    unsigned long port = GetPrivateProfileIntA("Settings", "listening_port", 40000, ini_full_path.c_str());
    if (port > 0 && port <= 65535) {
        signaling_port = (int)port;
    }

    unsigned long rport = GetPrivateProfileIntA("Settings", "relay_port", 40001, ini_full_path.c_str());
    if (rport > 0 && rport <= 65535) {
        relay_port = (int)rport;
    }

    gateway_enabled = GetPrivateProfileIntA("Settings", "tap_gateway", 1, ini_full_path.c_str()) != 0;
    nat_enabled = GetPrivateProfileIntA("Settings", "nat", 0, ini_full_path.c_str()) != 0;

    // Local Area listen address (e.g. 192.168.1.101). Accepts local_ip,
    // server_ip or listen_ip; empty means bind 0.0.0.0 (all interfaces).
    {
        char lip_buf[64] = {0};
        if (GetPrivateProfileStringA("Settings", "local_ip", "", lip_buf, sizeof(lip_buf), ini_full_path.c_str()) && lip_buf[0] != '\0') {
            std::string v = lip_buf;
            uint32_t u = string_to_ip(v);
            if (u != 0) { server_local_ip = v; server_local_ip_u32 = u; }
        } else if (GetPrivateProfileStringA("Settings", "server_ip", "", lip_buf, sizeof(lip_buf), ini_full_path.c_str()) && lip_buf[0] != '\0') {
            std::string v = lip_buf;
            uint32_t u = string_to_ip(v);
            if (u != 0) { server_local_ip = v; server_local_ip_u32 = u; }
        } else if (GetPrivateProfileStringA("Settings", "listen_ip", "", lip_buf, sizeof(lip_buf), ini_full_path.c_str()) && lip_buf[0] != '\0') {
            std::string v = lip_buf;
            uint32_t u = string_to_ip(v);
            if (u != 0) { server_local_ip = v; server_local_ip_u32 = u; }
        }
    }

    char vip_buf[64];
    if (GetPrivateProfileStringA("Settings", "gateway_ip", "10.0.0.1", vip_buf, sizeof(vip_buf), ini_full_path.c_str())) {
        std::string start = vip_buf;

        // "10.0.0.1" -> prefix "10.0.0." plus start octet 1.
        // Appending '.' to the whole address would produce "10.0.0.1.1".
        size_t last_dot = start.find_last_of('.');
        if (last_dot == std::string::npos) {
            virtual_ip_prefix = "10.0.0.";
            virtual_ip_start_octet = 1;
        } else {
            virtual_ip_prefix = start.substr(0, last_dot + 1);
            virtual_ip_start_octet = std::atoi(start.substr(last_dot + 1).c_str());
            if (virtual_ip_start_octet < 1 || virtual_ip_start_octet > 253) {
                virtual_ip_start_octet = 1;
            }
        }
    }

    // Parse subnet mask (default /24)
    char mask_buf[64] = {0};
    if (GetPrivateProfileStringA("Settings", "virtual_ip_mask", "255.255.255.0", mask_buf, sizeof(mask_buf), ini_full_path.c_str())) {
        virtual_ip_mask = string_to_ip(mask_buf);
        if (virtual_ip_mask == 0) virtual_ip_mask = 0xFFFFFF00; // fallback /24
    }

    // Calculate prefix length from mask
    uint32_t m = virtual_ip_mask;
    virtual_ip_prefix_len = 0;
    for (int b = 31; b >= 0 && (m & (1u << b)); --b) virtual_ip_prefix_len++;

    // Network address from start IP + mask
    uint32_t start_addr = string_to_ip(virtual_ip_prefix + std::to_string(virtual_ip_start_octet));
    virtual_ip_network = start_addr & virtual_ip_mask;
    virtual_ip_server = start_addr;
    virtual_ip_first_client = start_addr + 1;
    uint32_t broadcast = virtual_ip_network | (~virtual_ip_mask & 0xFFFFFFFFu);
    virtual_ip_last = broadcast - 1;

    std::cout << "Server Configuration loaded from: " << ini_full_path << std::endl;
    std::cout << "Listening Port: " << signaling_port << std::endl;
    std::cout << "Relay Port: " << relay_port << std::endl;
    std::cout << "Local IP (listen): " << (server_local_ip.empty() ? std::string("0.0.0.0 (all)") : server_local_ip) << std::endl;
    std::cout << "Virtual IP Pool Start: " << ip_to_string(virtual_ip_server) << std::endl;
    std::cout << "Virtual IP Mask: " << ip_to_string(virtual_ip_mask) << " (/ " << virtual_ip_prefix_len << ")" << std::endl;
    std::cout << "Usable Range: " << ip_to_string(virtual_ip_first_client) << " - " << ip_to_string(virtual_ip_last) << std::endl;
    std::cout << "TLD suffixes: ";
    for (const auto& suf : arpa_suffixes) {
        std::cout << "." << suf << " ";
    }
    std::cout << "(root -> " << ip_to_string(virtual_ip_server) << ")" << std::endl;

    return true;
}
std::string server_virtual_ip() {
    return ip_to_string(virtual_ip_server);
}
