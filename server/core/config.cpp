// server/core/config.cpp - server.ini create/load + IP pool calculation.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/guard.h"
#include "core/limits.h"
#include "core/utils.h"
#include "federation/federation.h"

namespace {

// Contiguous mask for a CIDR length. /31 and /32 leave no room for a gateway
// plus a client, so the accepted range is /8 ... /30.
uint32_t mask_from_prefix(int prefix_len) {
    if (prefix_len < 8 || prefix_len > 30) {
        return 0;
    }
    return 0xFFFFFFFFu << (32 - prefix_len);
}

bool parse_ipv4(const std::string& text, uint32_t& out) {
    unsigned int o[4] = {0, 0, 0, 0};
    char tail = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u%c", &o[0], &o[1], &o[2], &o[3], &tail) != 4) {
        return false;
    }
    for (int i = 0; i < 4; ++i) {
        if (o[i] > 255) return false;
    }
    out = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
    return true;
}

// The file this process actually loaded; the admin console reads and rewrites
// it so a change survives a restart.
std::string g_ini_path;

std::string ini_value(const std::string& ini_full_path, const std::string& key) {
    char buffer[128] = {0};
    GetPrivateProfileStringA("Settings", key.c_str(), "", buffer, sizeof(buffer),
                             ini_full_path.c_str());
    return trim(std::string(buffer));
}

}  // namespace

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
            out << "# Act as gateway on gateway_ip (opens the tunnel adapter on the server)\n";
            out << "tap_gateway=1\n\n";
            out << "# NAT the virtual network to the internet (admin + WinNat required)\n";
            out << "nat=0\n\n";
            out << "# ---- Federation (server to server, clients never change) ---------\n";
            out << "# link: empty or false = this server runs on its own (SINGLE mode).\n";
            out << "# An IPv4 address makes it a replica of that primary server.\n";
            out << "link=\n\n";
            out << "# Peering control (TCP) and federation data (UDP) ports. A SINGLE\n";
            out << "# server always accepts replicas on link_port.\n";
            out << "link_port=40002\n";
            out << "# Port of the primary server, when it differs (NAT / port forward).\n";
            out << "#link_primary_port=40002\n";
            out << "link_data_port=40003\n\n";
            out << "# Unique name of this server in the federation. Empty = derived\n";
            out << "# from the gateway address (srv-10-10-1-1).\n";
            out << "link_id=\n\n";
            out << "# Shared secret both sides must use. Empty = the handshake is\n";
            out << "# not authenticated; set the same value on every server.\n";
            out << "link_secret=\n\n";
            out << "# Remote name/location cache lifetime in seconds.\n";
            out << "link_cache_ttl_sec=60\n\n";
            out << "# Local Area IP the server binds to (example: 192.168.1.101).\n";
            out << "# Empty = listen on every interface (0.0.0.0). Relay + signaling use it.\n";
            out << "local_ip=\n\n";
            out << "# Message of the day: sent to every client that connects and\n";
            out << "# shown in its panel (one line, empty = nothing).\n";
            out << "motd=\n\n";
            out << "# TLD name service: name -> virtual IP records (separate domain.db)\n\n";
            out << "# ---- Virtual network (the shared segment clients join) -----------\n";
            out << "# gateway_ip: the server's own address inside that subnet.\n";
            out << "gateway_ip=10.0.0.1\n\n";
            out << "# Subnet size: a CIDR length here, or a dotted mask in\n";
            out << "# virtual_ip_mask. Anything from /8 to /30 is accepted; when both\n";
            out << "# keys are present virtual_ip_prefix wins.\n";
            out << "virtual_ip_prefix=24\n";
            out << "#virtual_ip_mask=255.255.255.0\n\n";
            out << "# Address range handed to clients. Optional: by default the pool\n";
            out << "# starts right after the gateway and ends one below the broadcast\n";
            out << "# address (capped at 65536 addresses unless pool_end is set).\n";
            out << "#pool_start=10.0.0.2\n";
            out << "#pool_end=10.0.0.254\n";
            out << "\n# ---- DoS / load shield -------------------------------------------\n";
            out << "# Concurrent signaling connections. Beyond this the server answers\n";
            out << "# BUSY and the client retries; it never spawns unbounded threads.\n";
            out << "guard_max_connections=128\n\n";
            out << "# Relay packet budget (packets/second). The server adapts it on its\n";
            out << "# own between guard_min_pps and guard_max_budget_pps: it halves the\n";
            out << "# budget while packets are being dropped and grows it back slowly.\n";
            out << "guard_max_pps=20000\n";
            out << "guard_min_pps=5000\n";
            out << "guard_max_budget_pps=200000\n\n";
            out << "# Fair-share ceiling for one sender (packets/second): the budget is\n";
            out << "# divided between active senders, so one flooder cannot starve all.\n";
            out << "guard_per_ip_pps=4000\n\n";
            out << "# New connections allowed per client IP per window (seconds).\n";
            out << "guard_connect_limit=10\n";
            out << "guard_connect_window_sec=10\n\n";
            out << "# Tracked senders (memory bound), idle timeout and the minimum gap\n";
            out << "# between GUARD log lines, in seconds.\n";
            out << "guard_source_table=4096\n";
            out << "guard_source_idle_sec=30\n";
            out << "guard_log_interval_sec=30\n";
            out << "\n# ---- Per-client bandwidth cap (kbit/s, 0 = unlimited) --------------\n";
            out << "# Applied to every client that does not have an admin override\n";
            out << "# (console: LIMIT_SET IP:<virtual ip> UP:<kbps> DOWN:<kbps>).\n";
            out << "client_upload_kbps=0\n";
            out << "client_download_kbps=0\n";
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
    g_ini_path = ini_full_path;

    unsigned long port = GetPrivateProfileIntA("Settings", "listening_port", 40000, ini_full_path.c_str());
    if (port > 0 && port <= 65535) {
        signaling_port = (int)port;
    }

    unsigned long rport = GetPrivateProfileIntA("Settings", "relay_port", 40001, ini_full_path.c_str());
    if (rport > 0 && rport <= 65535) {
        relay_port = (int)rport;
    }

    // Message of the day (one line, shown in the client panel).
    {
        char motd_buf[256] = {0};
        GetPrivateProfileStringA("Settings", "motd", "", motd_buf, sizeof(motd_buf),
                                 ini_full_path.c_str());
        set_server_motd(trim(std::string(motd_buf)));
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

    // ---- Virtual network: any IPv4 subnet from /8 to /30 -------------------
    // Everything is derived from gateway_ip plus one subnet description, and can
    // be narrowed with pool_start/pool_end. A file that only carries
    // gateway_ip keeps behaving exactly like before (a /24 around it).
    std::string gateway_text = ini_value(ini_full_path, "gateway_ip");
    if (gateway_text.empty()) {
        gateway_text = "10.0.0.1";
    }
    uint32_t gateway = 0;
    if (!parse_ipv4(gateway_text, gateway)) {
        std::cerr << "gateway_ip=\"" << gateway_text
                  << "\" is not an IPv4 address; using 10.0.0.1." << std::endl;
        gateway_text = "10.0.0.1";
        parse_ipv4(gateway_text, gateway);
    }

    uint32_t mask = 0;
    const std::string prefix_text = ini_value(ini_full_path, "virtual_ip_prefix");
    const std::string mask_text = ini_value(ini_full_path, "virtual_ip_mask");
    if (!prefix_text.empty()) {
        mask = mask_from_prefix(std::atoi(prefix_text.c_str()));
        if (mask == 0) {
            std::cerr << "virtual_ip_prefix=\"" << prefix_text
                      << "\" is not a prefix length between 8 and 30; ignoring it." << std::endl;
        }
    }
    if (mask == 0 && !mask_text.empty()) {
        uint32_t dotted = 0;
        if (parse_ipv4(mask_text, dotted)) {
            // Normalise: the pool arithmetic needs a contiguous mask.
            int bits = 0;
            for (int b = 31; b >= 0 && (dotted & (1u << b)); --b) {
                ++bits;
            }
            mask = mask_from_prefix(bits);
        }
        if (mask == 0) {
            std::cerr << "virtual_ip_mask=\"" << mask_text
                      << "\" is not a usable subnet mask; using /24." << std::endl;
        }
    }
    if (mask == 0) {
        mask = mask_from_prefix(24);
    }

    uint32_t network = gateway & mask;
    uint32_t broadcast = network | (~mask & 0xFFFFFFFFu);
    int prefix_len = 0;
    for (int b = 31; b >= 0 && (mask & (1u << b)); --b) {
        ++prefix_len;
    }

    // The gateway must be a real host address in that subnet: a gateway on the
    // network or broadcast address would hand clients an unroutable range.
    if ((gateway & mask) != network || gateway == network || gateway == broadcast) {
        std::cerr << "gateway_ip=" << ip_to_string(gateway) << " is not a usable host inside "
                  << ip_to_string(network) << "/" << prefix_len
                  << "; falling back to 10.0.0.1/24." << std::endl;
        mask = mask_from_prefix(24);
        prefix_len = 24;
        network = 0x0A000000u;
        broadcast = network | (~mask & 0xFFFFFFFFu);
        gateway = 0x0A000001u;
    }

    // Default pool: from the first host (skipping the gateway) to one below the
    // broadcast address.
    uint32_t first = network + 1;
    uint32_t last = broadcast - 1;
    if (last == gateway && last > first) {
        --last;
    }
    if (first == gateway) {
        ++first;
    }

    const std::string pool_start_text = ini_value(ini_full_path, "pool_start");
    if (!pool_start_text.empty()) {
        uint32_t value = 0;
        if (parse_ipv4(pool_start_text, value) && value > network && value < broadcast &&
            value != gateway) {
            first = value;
        } else {
            std::cerr << "pool_start=\"" << pool_start_text
                      << "\" is not a usable host inside " << ip_to_string(network) << "/"
                      << prefix_len << "; ignored." << std::endl;
        }
    }

    const std::string pool_end_text = ini_value(ini_full_path, "pool_end");
    bool pool_end_configured = false;
    if (!pool_end_text.empty()) {
        uint32_t value = 0;
        if (parse_ipv4(pool_end_text, value) && value > network && value < broadcast) {
            last = value;
            pool_end_configured = true;
        } else {
            std::cerr << "pool_end=\"" << pool_end_text
                      << "\" is not a usable host inside " << ip_to_string(network) << "/"
                      << prefix_len << "; ignored." << std::endl;
        }
    }

    // A /8 would otherwise walk millions of candidates for every client. The
    // cap applies to the derived default only: an explicit pool_end is honoured.
    const uint32_t kDefaultPoolCap = 65536;
    if (!pool_end_configured && last > first && (last - first + 1) > kDefaultPoolCap) {
        last = first + kDefaultPoolCap - 1;
        std::cout << "Client pool capped at " << kDefaultPoolCap
                  << " addresses; set pool_end in server.ini to widen it." << std::endl;
    }

    if (first > last) {
        std::cerr << "No client address left in " << ip_to_string(network) << "/" << prefix_len
                  << ": gateway_ip takes the only usable host." << std::endl;
    }

    // ---- DoS / load shield ------------------------------------------------
    // Every key is optional: an absent key keeps the default from
    // guard::Settings, so an old server.ini keeps working unchanged.
    guard::Settings shield;
    auto read_limit = [&](const char* key, int fallback) -> int {
        const std::string text = ini_value(ini_full_path, key);
        if (text.empty()) return fallback;
        const int value = std::atoi(text.c_str());
        if (value <= 0) {
            std::cerr << key << "=\"" << text << "\" is not a positive number; using "
                      << fallback << "." << std::endl;
            return fallback;
        }
        return value;
    };
    shield.max_connections = read_limit("guard_max_connections", shield.max_connections);
    shield.max_pps = read_limit("guard_max_pps", shield.max_pps);
    shield.min_pps = read_limit("guard_min_pps", shield.min_pps);
    shield.max_budget_pps = read_limit("guard_max_budget_pps", shield.max_budget_pps);
    shield.per_ip_pps = read_limit("guard_per_ip_pps", shield.per_ip_pps);
    shield.connect_limit = read_limit("guard_connect_limit", shield.connect_limit);
    shield.connect_window_sec =
        read_limit("guard_connect_window_sec", shield.connect_window_sec);
    shield.source_table = read_limit("guard_source_table", shield.source_table);
    shield.source_idle_sec = read_limit("guard_source_idle_sec", shield.source_idle_sec);
    shield.log_interval_sec = read_limit("guard_log_interval_sec", shield.log_interval_sec);
    guard::configure(shield);

    // ---- Per-client bandwidth caps (kbit/s, 0 = unlimited) ------------------
    auto read_kbps = [&](const char* key) -> double {
        const std::string text = ini_value(ini_full_path, key);
        if (text.empty()) return 0.0;
        const int kbps = std::atoi(text.c_str());
        if (kbps < 0) {
            std::cerr << key << "=\"" << text << "\" is negative; unlimited is used."
                      << std::endl;
            return 0.0;
        }
        return (double)kbps * 1000.0 / 8.0;
    };
    limits::set_defaults(read_kbps("client_upload_kbps"), read_kbps("client_download_kbps"));

    virtual_ip_network = network;
    virtual_ip_mask = mask;
    virtual_ip_prefix_len = prefix_len;
    virtual_ip_server = gateway;
    virtual_ip_first_client = first;
    virtual_ip_last = last;

    // Federation settings live in their own module: link target/role, peering
    // ports, this server's identity and the shared secret.
    fed::load_settings(ini_full_path);

    std::cout << "Server Configuration loaded from: " << ini_full_path << std::endl;
    std::cout << "Listening Port: " << signaling_port << std::endl;
    std::cout << "Relay Port: " << relay_port << std::endl;
    std::cout << "Local IP (listen): " << (server_local_ip.empty() ? std::string("0.0.0.0 (all)") : server_local_ip) << std::endl;
    std::cout << "Virtual Network: " << ip_to_string(virtual_ip_network) << "/"
              << virtual_ip_prefix_len << " (mask " << ip_to_string(virtual_ip_mask)
              << ", broadcast " << ip_to_string(broadcast) << ")" << std::endl;
    std::cout << "Gateway (server) IP: " << ip_to_string(virtual_ip_server) << std::endl;
    if (virtual_ip_first_client <= virtual_ip_last) {
        std::cout << "Client Pool: " << ip_to_string(virtual_ip_first_client) << " - "
                  << ip_to_string(virtual_ip_last) << " ("
                  << (virtual_ip_last - virtual_ip_first_client + 1) << " addresses)"
                  << std::endl;
    } else {
        std::cout << "Client Pool: empty" << std::endl;
    }
    std::cout << "Federation: "
              << (fed::link_target.empty()
                      ? std::string("single (primary) on TCP ") + std::to_string(fed::link_port)
                      : std::string("linked to ") + fed::link_target + ":" +
                            std::to_string(fed::link_primary_port))
              << ", data UDP " << fed::link_data_port << ", id " << fed::link_id
              << std::endl;
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

std::string server_ini_path() {
    return g_ini_path;
}
