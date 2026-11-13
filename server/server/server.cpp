// server/server.cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <set>
#include <random>
#include <atomic>
#include <sstream>
#include <ctime>
#include "sqlite3.h"

// ------------------------------------------------------------ Configuration
int signaling_port = 40000;
int relay_port = 40001;
bool gateway_enabled = true;
bool nat_enabled = false;
std::string virtual_ip_prefix = "10.0.0.";  // e.g. "10.0.0."
int virtual_ip_start_octet = 1;             // e.g. 1 -> 10.0.0.1

// Scalable IP distribution: supports /24 (default) up to /16 and beyond.
// All internal IP math uses uint32 (host byte order).
uint32_t virtual_ip_network = 0;      // network address (e.g. 10.0.0.0)
uint32_t virtual_ip_mask = 0;         // subnet mask (e.g. 255.255.255.0)
int virtual_ip_prefix_len = 24;       // CIDR prefix length
uint32_t virtual_ip_server = 0;       // server's own address
uint32_t virtual_ip_first_client = 0; // first address handed to clients
uint32_t virtual_ip_last = 0;         // last usable host address

// Optional LAN listen address (e.g. 192.168.1.101). When set, the signaling
// (TCP 40000) and relay (UDP 40001) sockets bind to this Local Area address
// instead of 0.0.0.0. The virtual pool start stays separate (gateway_ip).
std::string server_local_ip = "";
uint32_t server_local_ip_u32 = 0;

// Multi-suffix support: domain.db can hold several TLDs (p2p, abc, name, etc.).
// Each domain.db has its own set of suffixes.
std::set<std::string> arpa_suffixes;

// Convert dotted-quad string to uint32 (host byte order).
uint32_t string_to_ip(const std::string& ip) {
    uint32_t result = 0;
    int octets[4] = {0, 0, 0, 0};
    int count = 0;
    const char* p = ip.c_str();
    for (int i = 0; i < 4 && *p; ++i) {
        octets[i] = atoi(p);
        p = strchr(p, '.');
        if (p) ++p;
        count++;
    }
    if (count != 4) return 0;
    result = ((uint32_t)octets[0] << 24) | ((uint32_t)octets[1] << 16) |
             ((uint32_t)octets[2] << 8) | (uint32_t)octets[3];
    return result;
}

// Convert uint32 to dotted-quad string.
std::string ip_to_string(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(buf);
}

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

std::string arpa_suffix = "p2p";

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
            out << "# ARPA root service: name -> virtual IP records (separate domain.db)\n";
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
    std::cout << "ARPA suffixes: ";
    for (const auto& suf : arpa_suffixes) {
        std::cout << "." << suf << " ";
    }
    std::cout << "(root -> " << ip_to_string(virtual_ip_server) << ")" << std::endl;

    return true;
}

// The first address of the pool always belongs to the server itself.
std::string server_virtual_ip() {
    return ip_to_string(virtual_ip_server);
}

// ------------------------------------------------------------ SQLite store
//
// Clients that run with static=1 send their identity with every request. The
// identity -> address mapping lives in server.db so the same client always gets
// the same address, also across server restarts.

sqlite3* client_db = NULL;
std::mutex db_mutex;

// Root ARP service: a separate database keeps the name -> virtual IP records
// (our own TLD, like Tor's .onion) away from the identity table.
sqlite3* arpa_db = NULL;
std::mutex arpa_mutex;

bool db_open(const std::string& exe_dir) {
    std::string db_path = exe_dir + "\\server.db";
    if (sqlite3_open(db_path.c_str(), &client_db) != SQLITE_OK) {
        std::cerr << "Could not open " << db_path << ": " << sqlite3_errmsg(client_db) << std::endl;
        if (client_db != NULL) {
            sqlite3_close(client_db);
            client_db = NULL;
        }
        return false;
    }

    sqlite3_busy_timeout(client_db, 5000);

    const char* schema =
        "CREATE TABLE IF NOT EXISTS client_ips ("
        " identity TEXT PRIMARY KEY,"
        " ip TEXT NOT NULL UNIQUE,"
        " created_at INTEGER NOT NULL);";

    char* error = NULL;
    if (sqlite3_exec(client_db, schema, NULL, NULL, &error) != SQLITE_OK) {
        std::cerr << "Could not create client_ips table: " << (error ? error : "?") << std::endl;
        sqlite3_free(error);
        sqlite3_close(client_db);
        client_db = NULL;
        return false;
    }
    return true;
}

std::string db_lookup_ip(const std::string& identity) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (client_db == NULL || identity.empty()) {
        return "";
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT ip FROM client_ips WHERE identity = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
    std::string ip;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) {
            ip = reinterpret_cast<const char*>(text);
        }
    }
    sqlite3_finalize(stmt);
    return ip;
}

bool db_ip_taken(const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (client_db == NULL || ip.empty()) {
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT 1 FROM client_ips WHERE ip = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    bool taken = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return taken;
}

bool db_save_ip(const std::string& identity, const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (client_db == NULL) {
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "INSERT OR REPLACE INTO client_ips (identity, ip, created_at) VALUES (?1, ?2, ?3)", -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)std::time(NULL));

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

// Drop identity rows whose IP is outside the current usable range (or is the
// server address). These accumulate after ini changes and break routing
// because static_ip_for would otherwise hand the stale IP back.
void db_prune_stale_rows() {
    if (client_db == NULL) return;
    std::lock_guard<std::mutex> lock(db_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT identity, ip FROM client_ips", -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    std::vector<std::string> stale;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        std::string ip = (text != NULL) ? reinterpret_cast<const char*>(text) : "";
        uint32_t u = string_to_ip(ip);
        if (u < virtual_ip_first_client || u > virtual_ip_last || u == virtual_ip_server) {
            const unsigned char* id = sqlite3_column_text(stmt, 0);
            if (id != NULL) stale.push_back(reinterpret_cast<const char*>(id));
        }
    }
    sqlite3_finalize(stmt);
    for (const auto& id : stale) {
        sqlite3_stmt* del = NULL;
        if (sqlite3_prepare_v2(client_db, "DELETE FROM client_ips WHERE identity = ?1", -1, &del, NULL) == SQLITE_OK) {
            sqlite3_bind_text(del, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(del);
            sqlite3_finalize(del);
            std::cerr << "Pruned stale identity row: " << id << std::endl;
        }
    }
}

// ------------------------------------------------------------ ARPA root service
//
// Separate SQLite store (domain.db) holding name -> virtual IP records. Names
// live in our own TLD (arpa_suffix, default "p2p"), like Tor's .onion addresses,
// and are resolved by the root server at 10.0.0.1.

// Get a string setting from domain.db settings table.
std::string arpa_db_get_setting(const std::string& key) {
    if (arpa_db == NULL || key.empty()) return "";
    std::lock_guard<std::mutex> lock(arpa_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT value FROM settings WHERE key = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    std::string value;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) value = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);
    return value;
}

// Set a string setting in domain.db settings table.
bool arpa_db_set_setting(const std::string& key, const std::string& value) {
    if (arpa_db == NULL || key.empty()) return false;
    std::lock_guard<std::mutex> lock(arpa_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)", -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

bool arpa_open(const std::string& exe_dir) {
    std::string db_path = exe_dir + "\\domain.db";
    if (sqlite3_open(db_path.c_str(), &arpa_db) != SQLITE_OK) {
        std::cerr << "Could not open " << db_path << ": "
                  << (arpa_db ? sqlite3_errmsg(arpa_db) : "?") << std::endl;
        if (arpa_db != NULL) { sqlite3_close(arpa_db); arpa_db = NULL; }
        return false;
    }
    sqlite3_busy_timeout(arpa_db, 5000);

    const char* schema =
        "CREATE TABLE IF NOT EXISTS tld_list ("
        " id INTEGER PRIMARY KEY,"
        " suffix TEXT NOT NULL UNIQUE);"
        "CREATE TABLE IF NOT EXISTS domain_list ("
        " name TEXT PRIMARY KEY,"
        " identity TEXT NOT NULL,"
        " ip TEXT NOT NULL,"
        " ttl INTEGER NOT NULL DEFAULT 60,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL);";

    char* error = NULL;
    if (sqlite3_exec(arpa_db, schema, NULL, NULL, &error) != SQLITE_OK) {
        std::cerr << "Could not create domain tables: " << (error ? error : "?") << std::endl;
        sqlite3_free(error);
        sqlite3_close(arpa_db);
        arpa_db = NULL;
        return false;
    }

    // Load suffixes from tld_list table into arpa_suffixes set.
    // Each row is one TLD (p2p, abc, name, vpn, mesh, etc.).
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT suffix FROM tld_list", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            if (text != NULL) {
                std::string suf = reinterpret_cast<const char*>(text);
                std::string lowered;
                for (char c : suf) lowered.push_back((char)tolower((unsigned char)c));
                if (!lowered.empty()) {
                    arpa_suffixes.insert(lowered);
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // If no suffixes in database, add defaults: p2p, abc, name
    if (arpa_suffixes.empty()) {
        arpa_suffixes.insert("p2p");
        arpa_suffixes.insert("abc");
        arpa_suffixes.insert("name");
    }

    // Persist current suffix set to tld_list table (id, suffix).
    for (const auto& suf : arpa_suffixes) {
        sqlite3_stmt* ins = NULL;
        if (sqlite3_prepare_v2(arpa_db, "INSERT OR IGNORE INTO tld_list (suffix) VALUES (?1)", -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins, 1, suf.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(ins);
            sqlite3_finalize(ins);
        }
    }

    return true;
}

static std::string arpa_normalize(const std::string& raw) {
    std::string value = raw;
    size_t begin = value.find_first_not_of(" \t\r\n");
    size_t end = value.find_last_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    value = value.substr(begin, end - begin + 1);

    // lowercase
    std::string lowered;
    for (char c : value) {
        lowered.push_back((char)tolower((unsigned char)c));
    }

    // strip a single trailing dot
    if (!lowered.empty() && lowered.back() == '.') {
        lowered.pop_back();
    }

    // Check if name already ends with a configured suffix (e.g. mypc.p2p, mypc.abc).
    // If not, append the first configured suffix.
    bool has_suffix = false;
    for (const auto& suf : arpa_suffixes) {
        std::string sfx_dot = "." + suf;
        if (lowered.size() >= sfx_dot.size() &&
            lowered.compare(lowered.size() - sfx_dot.size(), sfx_dot.size(), sfx_dot) == 0) {
            has_suffix = true;
            break;
        }
    }
    if (!has_suffix && !arpa_suffixes.empty()) {
        lowered += "." + *arpa_suffixes.begin();
    }

    // validate every label
    if (lowered.empty() || lowered.size() > 253) return "";
    size_t pos = 0;
    while (pos < lowered.size()) {
        size_t dot = lowered.find('.', pos);
        if (dot == std::string::npos) dot = lowered.size();
        std::string label = lowered.substr(pos, dot - pos);
        if (label.empty() || label.size() > 63) return "";
        if (label.front() == '-' || label.back() == '-') return "";
        for (char c : label) {
            if (!(isalnum((unsigned char)c) || c == '-')) return "";
        }
        pos = dot + 1;
    }

    // reserve the root label for the server itself
    std::string first_label = lowered.substr(0, lowered.find('.'));
    if (first_label == "root") {
        return "";   // handled separately by the server
    }
    return lowered;
}

// Returns "ok", "invalid", "reserved", "identity_required", "taken", "storage".
// ttl: DNS time-to-live in seconds for the A record (default 60).
std::string arpa_set(const std::string& raw_name, const std::string& identity,
                     const std::string& ip, int ttl, std::string* canonical_out) {
    std::string name = arpa_normalize(raw_name);
    if (name.empty()) {
        // distinguish reserved root
        std::string lowered = raw_name;
        for (char& c : lowered) c = (char)tolower((unsigned char)c);
        size_t b = lowered.find_first_not_of(" \t\r\n");
        size_t e = lowered.find_last_not_of(" \t\r\n");
        std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
        if (t == "root" || t == "root." + arpa_suffix) {
            return "reserved";
        }
        return "invalid";
    }
    if (identity.size() < 8 || identity.size() > 64) {
        return "identity_required";
    }
    if (arpa_db == NULL) {
        return "storage";
    }

    std::lock_guard<std::mutex> lock(arpa_mutex);

    // check ownership
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT identity FROM domain_list WHERE name = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "storage";
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::string owner;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) owner = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);

    if (!owner.empty() && owner != identity) {
        return "taken";
    }

    if (owner.empty()) {
        if (sqlite3_prepare_v2(arpa_db, "INSERT INTO domain_list (name, identity, ip, ttl, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", -1, &stmt, NULL) != SQLITE_OK) return "storage";
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, ttl);
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)std::time(NULL));
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)std::time(NULL));
    } else {
        if (sqlite3_prepare_v2(arpa_db, "UPDATE domain_list SET ip = ?2, ttl = ?4, updated_at = ?5 WHERE name = ?1", -1, &stmt, NULL) != SQLITE_OK) return "storage";
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, ttl);
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)std::time(NULL));
    }

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok) return "storage";

    if (canonical_out != NULL) *canonical_out = name;
    return "ok";
}

std::string arpa_get(const std::string& raw_name, std::string* owner_out) {
    std::string name = arpa_normalize(raw_name);
    // allow root even though normalize() rejects it
    if (name.empty()) {
        std::string lowered = raw_name;
        for (char& c : lowered) c = (char)tolower((unsigned char)c);
        size_t b = lowered.find_first_not_of(" \t\r\n");
        size_t e = lowered.find_last_not_of(" \t\r\n");
        std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
        bool is_root = (t == "root");
        for (const auto& suf : arpa_suffixes) {
            if (t == "root." + suf) { is_root = true; break; }
        }
        if (is_root && !arpa_suffixes.empty()) {
            name = "root." + *arpa_suffixes.begin();
        } else {
            return "";
        }
    }
    if (arpa_db == NULL) return "";

    std::lock_guard<std::mutex> lock(arpa_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT identity, ip FROM domain_list WHERE name = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::string ip, owner;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* o = sqlite3_column_text(stmt, 0);
        const unsigned char* i = sqlite3_column_text(stmt, 1);
        if (o != NULL) owner = reinterpret_cast<const char*>(o);
        if (i != NULL) ip = reinterpret_cast<const char*>(i);
    }
    sqlite3_finalize(stmt);
    if (owner_out != NULL) *owner_out = owner;
    return ip;
}

void arpa_reserve_root(const std::string& ip, int ttl = 60) {
    if (arpa_db == NULL || ip.empty()) return;
    std::lock_guard<std::mutex> lock(arpa_mutex);
    for (const auto& suf : arpa_suffixes) {
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(arpa_db, "INSERT OR IGNORE INTO domain_list (name, identity, ip, ttl, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", -1, &stmt, NULL) != SQLITE_OK) {
            continue;
        }
        std::string name = "root." + suf;
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, "server", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, ttl);
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)std::time(NULL));
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)std::time(NULL));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

// Forward declaration (defined in main area below)
extern std::atomic<bool> relay_running;

// ------------------------------------------------------------ DNS name server (multi-TLD)
//
// Minimal UDP DNS server on port 53. It answers A-record queries for names
// ending in any configured suffix (.p2p, .abc, .name, etc.) by looking them
// up in domain.db. All other queries get NXDOMAIN. This lets users point their
// OS DNS resolver at 10.0.0.1 and resolve names like root.p2p, mypc.abc,
// server.name exactly like Tor's .onion, but via standard DNS.

// Returns the IP and fills out_ttl (seconds). Empty IP = not found.
std::string dns_lookup_name(const std::string& name, int& out_ttl) {
    out_ttl = 60;
    // normalize: lowercase, strip trailing dot
    std::string n = name;
    for (char& c : n) c = (char)tolower((unsigned char)c);
    if (!n.empty() && n.back() == '.') n.pop_back();

    // must end with one of our suffixes (only our own TLDs, nothing else)
    bool has_suffix = false;
    for (const auto& suf : arpa_suffixes) {
        std::string sfx_dot = "." + suf;
        if (n.size() >= sfx_dot.size() + 1 &&
            n.compare(n.size() - sfx_dot.size(), sfx_dot.size(), sfx_dot) == 0) {
            has_suffix = true;
            break;
        }
    }
    if (!has_suffix) return "";
    if (arpa_db == NULL) return "";

    std::lock_guard<std::mutex> lock(arpa_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT ip, ttl FROM domain_list WHERE name = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, n.c_str(), -1, SQLITE_TRANSIENT);
    std::string ip;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) ip = reinterpret_cast<const char*>(text);
        out_ttl = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);
    return ip;
}

// Build a minimal DNS response: copy the query header, set QR+RA+AA,
// set ANCOUNT=1 if we have an answer, otherwise ANCOUNT=0 and RCODE=NXDOMAIN.
int build_dns_response(const unsigned char* query, int qlen,
                       unsigned char* out, int out_size,
                       const std::string& answer_ip, int ttl) {
    if (qlen < 12 || out_size < 12) return -1;

    memcpy(out, query, 12);

    // Flags: set QR (response), AA (authoritative), RA (recursion available)
    unsigned char* flags = out + 2;
    flags[0] = 0x84;  // QR=1, OPCODE=0, AA=1, TC=0, RD=0
    flags[1] = 0x00;  // RA=0, Z=0, RCODE=0

    // QDCOUNT stays as-is.
    // ANCOUNT: 1 if answer, 0 if NXDOMAIN
    unsigned char* ancount = out + 6;
    if (!answer_ip.empty()) {
        ancount[0] = 0x00;
        ancount[1] = 0x01;
        // RCODE = 0 (no error)
        out[3] = (out[3] & 0xF0) | 0x00;
    } else {
        ancount[0] = 0x00;
        ancount[1] = 0x00;
        // RCODE = 3 (NXDOMAIN)
        out[3] = (out[3] & 0xF0) | 0x03;
    }

    // NSCOUNT and ARCOUNT stay 0.
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    int offset = 12;

    // Copy the question section verbatim from the query.
    // QNAME is length-prefixed labels, then QTYPE (2), QCLASS (2).
    int qname_end = 12;
    while (qname_end < qlen && query[qname_end] != 0) {
        qname_end += 1 + (unsigned char)query[qname_end];
    }
    qname_end += 1;  // null terminator
    int qtype_qclass = qname_end + 4;  // +2 QTYPE +2 QCLASS
    if (qtype_qclass > qlen) return -1;

    int qsection_len = qtype_qclass - 12;
    if (offset + qsection_len > out_size) return -1;
    memcpy(out + offset, query + 12, qsection_len);
    offset += qsection_len;

    if (answer_ip.empty()) {
        return offset;  // NXDOMAIN, no answer section
    }

    // Answer section: NAME pointer to question, TYPE=A, CLASS=IN, TTL,
    // RDLENGTH=4, RDATA=4 bytes. Use a local ans_offset so we don't confuse
    // it with the out-buffer offset.
    int ans_offset = offset;

    out[ans_offset] = 0xC0; out[ans_offset + 1] = 0x0C;  // pointer to QNAME (12)
    ans_offset += 2;

    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x01;  // TYPE A
    ans_offset += 2;
    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x01;  // CLASS IN
    ans_offset += 2;
    out[ans_offset] = (unsigned char)((ttl >> 24) & 0xFF);
    out[ans_offset + 1] = (unsigned char)((ttl >> 16) & 0xFF);
    out[ans_offset + 2] = (unsigned char)((ttl >> 8) & 0xFF);
    out[ans_offset + 3] = (unsigned char)(ttl & 0xFF);
    ans_offset += 4;
    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x04;  // RDLENGTH 4
    ans_offset += 2;

    // Parse answer IP into 4 bytes.
    unsigned char ipbytes[4] = {0, 0, 0, 0};
    int parsed = 0;
    const char* p = answer_ip.c_str();
    for (int i = 0; i < 4 && p != NULL; ++i) {
        ipbytes[i] = (unsigned char)atoi(p);
        p = strchr(p, '.');
        if (p) ++p;
        parsed++;
    }
    if (parsed != 4) return -1;

    out[ans_offset] = ipbytes[0];
    out[ans_offset + 1] = ipbytes[1];
    out[ans_offset + 2] = ipbytes[2];
    out[ans_offset + 3] = ipbytes[3];
    ans_offset += 4;

    return ans_offset;
}

// Parse the QNAME from a DNS query into a dotted string.
std::string dns_parse_qname(const unsigned char* query, int qlen, int& offset) {
    std::string name;
    bool first = true;
    while (offset < qlen) {
        unsigned char len = query[offset++];
        if (len == 0) break;
        if (len & 0xC0) {  // pointer
            offset += 1;
            break;
        }
        if (!first) name += '.';
        first = false;
        if (offset + len > qlen) return "";
        name.append(reinterpret_cast<const char*>(query + offset), len);
        offset += len;
    }
    return name;
}

// DNS server thread: listens on UDP 53, answers .p2p queries from domain.db.
void dns_thread() {
    SOCKET dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_sock == INVALID_SOCKET) {
        std::cerr << "DNS socket creation failed: " << WSAGetLastError() << std::endl;
        return;
    }

    int reuse = 1;
    setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in dns_addr;
    ZeroMemory(&dns_addr, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_addr.s_addr = INADDR_ANY;  // answer on all interfaces incl. TAP

    if (bind(dns_sock, (sockaddr*)&dns_addr, sizeof(dns_addr)) == SOCKET_ERROR) {
        std::cerr << "DNS bind failed on port 53: " << WSAGetLastError()
                  << " (another DNS server may be running)." << std::endl;
        closesocket(dns_sock);
        return;
    }

    // The startup sequence reports the DNS listener itself, so a late client
    // never sees this line after the "Ready" banner.
    char query_buf[2048];
    char resp_buf[2048];

    while (relay_running) {
        sockaddr_in sender;
        int sender_len = sizeof(sender);
        int qlen = recvfrom(dns_sock, query_buf, sizeof(query_buf), 0,
                            (sockaddr*)&sender, &sender_len);
        if (qlen <= 0) {
            if (!relay_running) break;
            Sleep(1);
            continue;
        }

        if (qlen < 12) continue;

        // Only answer standard queries (QR=0, OPCODE=0).
        if ((query_buf[2] & 0x80) != 0) continue;  // QR must be 0
        if ((query_buf[2] & 0x78) != 0) continue;  // OPCODE must be 0

        int qoffset = 12;
        std::string qname = dns_parse_qname((unsigned char*)query_buf, qlen, qoffset);
        if (qname.empty()) continue;

        int dns_ttl = 60;
        std::string answer_ip = dns_lookup_name(qname, dns_ttl);

        int rlen = build_dns_response((unsigned char*)query_buf, qlen,
                                      (unsigned char*)resp_buf, sizeof(resp_buf),
                                      answer_ip, dns_ttl);
        if (rlen > 0) {
            sendto(dns_sock, resp_buf, rlen, 0,
                   (sockaddr*)&sender, sender_len);
        }
    }

    closesocket(dns_sock);
}

// ------------------------------------------------------------ Session registry
//
// Every connected client is a member of one shared layer-2 segment. The server
// never pairs two clients any more: frames received from one member are flooded
// to all others, so 10.0.0.0/24 behaves like a single switch.

struct Session {
    SOCKET sock = INVALID_SOCKET;
    std::string identity;
    std::string public_ip;
    uint16_t udp_port = 50000;
    std::string virtual_ip;
    sockaddr_in endpoint;
    bool endpoint_known = false;
    bool retired = false;
};

std::mutex sessions_mutex;
std::vector<std::shared_ptr<Session>> online;
std::set<std::string> active_ips;

bool ip_active(const std::string& ip) {
    return active_ips.find(ip) != active_ips.end();
}

// Static identities get a stable address starting at .3. An address that is in
// use right now is skipped, otherwise two members would share a segment address.
std::string static_ip_for(const std::string& identity, const std::string& exclude) {
    std::string existing = db_lookup_ip(identity);
    if (!existing.empty() && existing != exclude && !ip_active(existing)) {
        uint32_t existing_u = string_to_ip(existing);
        // Stale rows (outside the usable range after a config change, or the
        // server address) must not be handed out — otherwise the client TAP
        // configures an out-of-segment IP and local ping never routes, which
        // is exactly what "delete the table and it works" was masking.
        if (existing_u >= virtual_ip_first_client && existing_u <= virtual_ip_last &&
            existing_u != virtual_ip_server) {
            return existing;
        }
    }

    // Iterate through the full usable host range of the subnet.
    for (uint32_t cand = virtual_ip_first_client; cand <= virtual_ip_last; ++cand) {
        std::string candidate = ip_to_string(cand);
        if (candidate == exclude || ip_active(candidate) || db_ip_taken(candidate)) {
            continue;
        }
        if (db_save_ip(identity, candidate)) {
            return candidate;
        }
    }
    return "";
}

// Without an identity the address is random for every session.
std::string random_ip(const std::string& exclude) {
    static std::mt19937 rng((unsigned int)std::chrono::steady_clock::now().time_since_epoch().count());
    uint32_t range_size = virtual_ip_last > virtual_ip_first_client ? (virtual_ip_last - virtual_ip_first_client + 1) : 0;
    std::uniform_int_distribution<uint32_t> dist(0, range_size > 0 ? range_size - 1 : 0);

    for (int attempt = 0; attempt < 200; ++attempt) {
        uint32_t cand = virtual_ip_first_client + dist(rng);
        std::string candidate = ip_to_string(cand);
        if (candidate == exclude || ip_active(candidate) || db_ip_taken(candidate)) {
            continue;
        }
        return candidate;
    }
    return "";
}

// An empty identity means "dynamic"; the server address is never handed out.
std::string assign_virtual_ip(const std::string& identity, const std::string& exclude) {
    if (!identity.empty()) {
        return static_ip_for(identity, exclude);
    }
    return random_ip(exclude);
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

// ------------------------------------------------------------ Gateway (TAP)
//
// With tap_gateway=1 the server joins the virtual segment itself: a TAP adapter
// gets 10.0.0.1/24 and every frame is bridged between that adapter and the
// relay. The address becomes a real host address, so clients can reach the
// server and, with nat=1, the internet through it.

#define TAP_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

HANDLE gateway_tap = INVALID_HANDLE_VALUE;
std::string gateway_adapter_name;
SOCKET relay_sock = INVALID_SOCKET;
std::atomic<bool> relay_running(true);
// False until the gateway, relay socket and signaling listener are all up.
// Clients that arrive before this is true are turned away instead of being
// handed an address the tunnel cannot back yet.
std::atomic<bool> server_ready(false);

// Frames on their way *into* the TAP adapter. The handle uses overlapped I/O
// (see try_find_gateway_tap): a pending synchronous read on the same handle
// makes every concurrent write wait - measured at 0.4-2.8 s per frame - which
// stalled relay_thread and broke the tunnel completely. A dedicated writer
// thread drains a bounded queue instead, so the relay never blocks.
std::mutex tap_tx_mutex;
std::condition_variable tap_tx_cv;
std::deque<std::vector<char>> tap_tx_queue;
bool tap_tx_stop = false;
long long tap_tx_dropped = 0;
const size_t tap_tx_max_frames = 512;

std::string narrow(const std::wstring& text) {
    if (text.empty()) {
        return "";
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 1) {
        return "";
    }
    std::string narrow_text((size_t)len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &narrow_text[0], len, NULL, NULL);
    return narrow_text;
}

// TAP adapters are the only class devices whose ComponentId contains "tap".
std::vector<std::string> tap_instance_ids_by_registry() {
    std::vector<std::string> found;

    HKEY root = NULL;
    const char* class_key = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, class_key, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        return found;
    }

    for (DWORD index = 0; index < 256; ++index) {
        char subkey[16];
        sprintf(subkey, "%04lu", index);

        HKEY device = NULL;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &device) != ERROR_SUCCESS) {
            continue;
        }

        char component[128] = {0};
        DWORD size = sizeof(component);
        DWORD type = 0;
        bool is_tap = false;
        if (RegQueryValueExA(device, "ComponentId", NULL, &type, (BYTE*)component, &size) == ERROR_SUCCESS) {
            is_tap = std::string(component).find("tap") != std::string::npos;
        }

        if (is_tap) {
            char guid[128] = {0};
            size = sizeof(guid);
            if (RegQueryValueExA(device, "NetCfgInstanceId", NULL, &type, (BYTE*)guid, &size) == ERROR_SUCCESS) {
                // The registry value already carries braces; the device path and
                // the adapter name expect them in different places, so keep the
                // bare GUID only.
                std::string raw = guid;
                std::string bare;
                for (char c : raw) {
                    if (c != '{' && c != '}') {
                        bare.push_back(c);
                    }
                }
                if (!bare.empty()) {
                    found.push_back(bare);
                }
            }
        }

        RegCloseKey(device);
    }

    RegCloseKey(root);
    return found;
}

// FriendlyName is what netsh expects ("Ethernet 5").
// Resolves the connection name for the TAP device GUID by looking up the
// NETWORK_CONNECTIONS registry key directly. GetAdaptersAddresses matching
// by GUID substring is case-sensitive and can return the physical adapter's
// name ("Local Area Connection") when GUID casing differs.
std::string adapter_friendly_name(const std::string& guid) {
    if (guid.empty()) {
        return "";
    }
    // Try the registry first: the authoritative netsh name for that GUID.
    {
        HKEY hNet;
        const char* net_key = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4d36e972-e325-11ce-bfc1-08002be10318}";
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, net_key, 0, KEY_READ, &hNet) == ERROR_SUCCESS) {
            char enum_guid[256];
            DWORD index = 0;
            for (;;) {
                DWORD guid_len = sizeof(enum_guid);
                if (RegEnumKeyExA(hNet, index++, enum_guid, &guid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                    break;
                }
                std::string enum_str(enum_guid);
                // Compare ignoring braces and case.
                std::string enum_norm = enum_str;
                std::string want_norm = guid;
                for (char& c : enum_norm) {
                    if (c == '{' || c == '}') c = ' ';
                    else c = (char)tolower((unsigned char)c);
                }
                for (char& c : want_norm) {
                    if (c == '{' || c == '}') c = ' ';
                    else c = (char)tolower((unsigned char)c);
                }
                if (enum_norm.find(want_norm) != std::string::npos) {
                    std::string conn_key = std::string(net_key) + "\\" + enum_str + "\\Connection";
                    HKEY hConn;
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key.c_str(), 0, KEY_READ, &hConn) == ERROR_SUCCESS) {
                        char name_buf[256] = {0};
                        DWORD name_len = sizeof(name_buf);
                        DWORD type = 0;
                        std::string result;
                        if (RegQueryValueExA(hConn, "Name", NULL, &type, (LPBYTE)name_buf, &name_len) == ERROR_SUCCESS) {
                            result = std::string(name_buf);
                        }
                        RegCloseKey(hConn);
                        RegCloseKey(hNet);
                        if (!result.empty()) {
                            return result;
                        }
                    }
                    break;
                }
            }
            RegCloseKey(hNet);
        }
    }

    // Fallback: case-insensitive match through GetAdaptersAddresses.
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        return "";
    }

    std::vector<unsigned char> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) {
        return "";
    }

    std::string guid_lower = guid;
    for (char& c : guid_lower) c = (char)tolower((unsigned char)c);

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        std::string name_lower(adapter->AdapterName);
        for (char& c : name_lower) c = (char)tolower((unsigned char)c);
        if (name_lower.find(guid_lower) != std::string::npos) {
            return narrow(std::wstring(adapter->FriendlyName));
        }
    }
    return "";
}

// True only when the friendly name really belongs to a TAP adapter (its
// Description contains "TAP"). Guards against configuring 10.0.0.1 on the
// physical NIC ("Local Area Connection").
bool is_tap_friendly_name(const std::string& friendly_name) {
    if (friendly_name.empty()) {
        return false;
    }
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }
    std::vector<unsigned char> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) {
        return false;
    }
    std::wstring wanted;
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, friendly_name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, friendly_name.c_str(), -1, &wanted[0], wide_len);
    }
    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted == adapter->FriendlyName) {
            std::string desc = narrow(std::wstring(adapter->Description));
            for (char& c : desc) c = (char)tolower((unsigned char)c);
            return desc.find("tap") != std::string::npos;
        }
    }
    return false;
}

bool run_hidden_command(const std::string& command_line, long long* exit_code) {
    STARTUPINFOA startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION process;
    ZeroMemory(&process, sizeof(process));

    std::string mutable_cmd = command_line;
    if (!CreateProcessA(NULL, &mutable_cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        return false;
    }

    DWORD waited = WaitForSingleObject(process.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    if (exit_code != NULL) {
        *exit_code = (waited == WAIT_OBJECT_0) ? (long long)code : -1;
    }
    return waited == WAIT_OBJECT_0;
}

// Flood a frame to every member (optionally skipping the sender).
void flood_to_sessions(const char* data, int len, const std::shared_ptr<Session>& except) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (const auto& session : online) {
        if (!session->endpoint_known || session == except) {
            continue;
        }
        sendto(relay_sock, data, len, 0, (sockaddr*)&session->endpoint, sizeof(session->endpoint));
    }
}

// Frames coming from the TAP adapter belong to the whole segment: send them to
// every connected client.
void queue_tap_frame(const char* data, int len) {
    if (len <= 0) return;
    {
        std::lock_guard<std::mutex> lock(tap_tx_mutex);
        if (tap_tx_queue.size() >= tap_tx_max_frames) {
            tap_tx_queue.pop_front();  // keep latency bounded: drop the oldest
            tap_tx_dropped++;
            if (tap_tx_dropped % 1000 == 1) {
                std::cerr << "Gateway TAP write queue full, dropped " << tap_tx_dropped
                          << " frame(s)." << std::endl;
            }
        }
        tap_tx_queue.emplace_back(data, data + len);
    }
    tap_tx_cv.notify_one();
}

void tap_writer_thread() {
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        std::cerr << "Gateway TAP write event could not be created." << std::endl;
        return;
    }

    for (;;) {
        std::vector<char> frame;
        {
            std::unique_lock<std::mutex> lock(tap_tx_mutex);
            tap_tx_cv.wait(lock, [] { return tap_tx_stop || !tap_tx_queue.empty(); });
            if (tap_tx_queue.empty()) break;  // stop only after draining
            frame = std::move(tap_tx_queue.front());
            tap_tx_queue.pop_front();
        }
        if (gateway_tap == INVALID_HANDLE_VALUE) continue;

        ResetEvent(ov.hEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        DWORD written = 0;
        if (!WriteFile(gateway_tap, frame.data(), (DWORD)frame.size(), &written, &ov)) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                std::cerr << "Gateway TAP write failed: " << error << std::endl;
                Sleep(10);
                continue;
            }
            if (WaitForSingleObject(ov.hEvent, 5000) != WAIT_OBJECT_0 ||
                !GetOverlappedResult(gateway_tap, &ov, &written, FALSE)) {
                std::cerr << "Gateway TAP write did not complete." << std::endl;
                CancelIo(gateway_tap);
            }
        }
    }
    CloseHandle(ov.hEvent);
}

void gateway_to_relay_thread() {
    char buffer[65535];
    DWORD bytes_read = 0;
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        std::cerr << "Gateway TAP read event could not be created." << std::endl;
        return;
    }

    while (gateway_tap != INVALID_HANDLE_VALUE && relay_running) {
        ResetEvent(ov.hEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        bytes_read = 0;

        if (!ReadFile(gateway_tap, buffer, sizeof(buffer), &bytes_read, &ov)) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                if (!relay_running || gateway_tap == INVALID_HANDLE_VALUE) {
                    break;
                }
                if (error == ERROR_OPERATION_ABORTED || error == ERROR_NOT_READY) {
                    Sleep(100);
                    continue;
                }
                std::cerr << "Gateway TAP read failed: " << error << std::endl;
                break;
            }

            // Wait in slices so a shutdown is noticed even mid-read.
            for (;;) {
                if (WaitForSingleObject(ov.hEvent, 500) == WAIT_OBJECT_0) {
                    break;
                }
                if (!relay_running || gateway_tap == INVALID_HANDLE_VALUE) {
                    CancelIo(gateway_tap);
                    CloseHandle(ov.hEvent);
                    return;
                }
            }

            if (!GetOverlappedResult(gateway_tap, &ov, &bytes_read, FALSE)) {
                DWORD done_error = GetLastError();
                if (done_error == ERROR_OPERATION_ABORTED || done_error == ERROR_NOT_READY) {
                    Sleep(10);
                    continue;
                }
                std::cerr << "Gateway TAP read completion failed: " << done_error << std::endl;
                break;
            }
        }

        if (bytes_read > 0) {
            flood_to_sessions(buffer, (int)bytes_read, nullptr);
        }
    }
    CloseHandle(ov.hEvent);
}

// Relay thread: receive a frame from one client, hand it to every other client
// and to the gateway adapter.
void relay_thread() {
    char buffer[65535];

    while (relay_running) {
        sockaddr_in sender;
        int sender_len = sizeof(sender);
        int len = recvfrom(relay_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_len);

        if (len <= 0) {
            if (!relay_running) {
                break;
            }
            Sleep(1);
            continue;
        }

        // Anything that reaches the relay during startup is dropped: there is
        // no gateway or session table to hand it to yet.
        if (!server_ready.load()) continue;

        std::shared_ptr<Session> source;
        std::vector<sockaddr_in> targets;
        bool do_gateway_write = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);

            // Learn the real source endpoint: NAT may rewrite the UDP port that
            // the client announced over the control channel, so the declared port
            // alone is not enough. Fall back to the virtual-IP octet embedded in
            // the HELLO probe, and finally to the only session sharing the
            // sender's public address.
            for (const auto& session : online) {
                if (session->endpoint_known &&
                    session->endpoint.sin_addr.s_addr == sender.sin_addr.s_addr &&
                    session->endpoint.sin_port == sender.sin_port) {
                    source = session;
                    break;
                }
            }

            if (!source) {
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                uint16_t sender_port = ntohs(sender.sin_port);
                for (const auto& session : online) {
                    if (session->public_ip == sender_ip && session->udp_port == sender_port) {
                        source = session;
                        break;
                    }
                }
            }

            // HELLO probe carries the sender's virtual-IP last octet so NAT
            // rewrites do not break endpoint learning.
            if (!source && len >= 7 && (unsigned char)buffer[0] == 0x01 &&
                memcmp(buffer + 1, "HELLO", 5) == 0) {
                unsigned char octet = (unsigned char)buffer[6];
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                std::vector<std::shared_ptr<Session>> candidates;
                for (const auto& session : online) {
                    if (session->public_ip != sender_ip) continue;
                    size_t last_dot = session->virtual_ip.find_last_of('.');
                    if (last_dot == std::string::npos) continue;
                    int vo = std::atoi(session->virtual_ip.c_str() + last_dot + 1);
                    if (vo >= 0 && vo <= 255 && (unsigned char)vo == octet) {
                        candidates.push_back(session);
                    }
                }
                if (candidates.size() == 1) {
                    source = candidates.front();
                }
            }

            if (!source) {
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                std::vector<std::shared_ptr<Session>> matching;
                for (const auto& session : online) {
                    if (session->public_ip == sender_ip) matching.push_back(session);
                }
                if (matching.size() == 1) {
                    source = matching.front();
                }
            }

            if (!source) {
                continue;  // not a registered member, drop the frame
            }

            if (!source->endpoint_known) {
                source->endpoint = sender;
                source->endpoint_known = true;
                std::cout << "Relay endpoint learned for " << source->virtual_ip
                          << ": " << inet_ntoa(sender.sin_addr) << ":" << ntohs(sender.sin_port) << std::endl;
            }

            // Anything shorter than an Ethernet header is a registration probe
            // sent right after connecting: it only teaches us the endpoint.
            if (len < 14) {
                continue;
            }

            for (const auto& session : online) {
                if (!session->endpoint_known || session == source) {
                    continue;
                }
                targets.push_back(session->endpoint);
            }

            do_gateway_write = (gateway_tap != INVALID_HANDLE_VALUE);
        }

        for (const auto& target : targets) {
            sendto(relay_sock, buffer, len, 0, (sockaddr*)&target, sizeof(target));
        }

        if (do_gateway_write) {
            queue_tap_frame(buffer, len);
        }
    }
}

// Bring the server itself onto the virtual segment as 10.0.0.1.
bool is_admin_server() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY SIdAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup = NULL;
    if (AllocateAndInitializeSid(&SIdAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &isAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return isAdmin != FALSE;
}

bool adapter_connection_exists_server(const std::string& name) {
    if (name.empty()) return false;
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) return false;
    std::vector<unsigned char> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) return false;
    std::wstring wanted;
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wanted[0], wide_len);
    }
    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted == adapter->FriendlyName) return true;
    }
    return false;
}

void maybe_rename_gateway_adapter(std::string& adapter, const std::string& netsh) {
    const std::string wanted = "Server Adaptor";
    if (adapter == wanted) return;
    if (adapter_connection_exists_server(wanted)) {
        std::cout << "Gateway adapter keeps name \"" << adapter << "\" (\"" << wanted << "\" already in use)." << std::endl;
        return;
    }
    std::string cmd = "\"" + netsh + "\" interface set interface name=\"" + adapter + "\" newname=\"" + wanted + "\"";
    long long exit_code = 0;
    if (run_hidden_command(cmd, &exit_code) && exit_code == 0 && adapter_connection_exists_server(wanted)) {
        std::cout << "Gateway adapter renamed to \"" << wanted << "\"" << std::endl;
        adapter = wanted;
    } else {
        std::cerr << "Could not rename gateway adapter \"" << adapter << "\" to \"" << wanted << "\" (exit " << exit_code << ")." << std::endl;
    }
}

bool setup_gateway() {
    HANDLE tap = INVALID_HANDLE_VALUE;
    std::string guid;
    std::string adapter;
    // Adapters that failed to take the gateway address are never retried.
    std::set<std::string> rejected_adapters;
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh = std::string(system_dir) + "\\netsh.exe";

    auto try_find_gateway_tap = [&]() -> bool {
        if (tap != INVALID_HANDLE_VALUE) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; }
        std::vector<std::string> candidates = tap_instance_ids_by_registry();
        if (candidates.empty()) return false;

        // The server must claim its own TAP adapter. When a client runs on this
        // same host it renames its adapter to "Client Adaptor". Taking that one
        // leaves the virtual gateway address unassigned, so remote clients can
        // connect and get an IP but never reach 10.0.0.1 or the tunnel
        // ("Gateway disabled: clients will only reach each other").
        std::vector<std::string> ordered;
        for (const auto& candidate : candidates) {
            std::string name = adapter_friendly_name(candidate);
            if (name.empty()) continue;
            if (!is_tap_friendly_name(name)) continue;
            if (!adapter_connection_exists_server(name)) continue;
            if (rejected_adapters.find(name) != rejected_adapters.end()) continue;
            ordered.push_back(candidate);
        }
        std::stable_sort(ordered.begin(), ordered.end(),
                         [](const std::string& a, const std::string& b) {
                             auto rank = [](const std::string& guid) -> int {
                                 std::string name = adapter_friendly_name(guid);
                                 for (char& c : name) c = (char)tolower((unsigned char)c);
                                 if (name == "server adaptor") return 0;
                                 if (name == "client adaptor") return 2;
                                 return 1;
                             };
                             return rank(a) < rank(b);
                         });
        candidates.swap(ordered);
        if (candidates.empty()) return false;
        DWORD last_error = 0;
        for (const auto& candidate : candidates) {
            std::string device_path = "\\\\.\\Global\\{" + candidate + "}.tap";
            // FILE_FLAG_OVERLAPPED: synchronous TAP I/O serialises reads and
            // writes on the same handle, which blocks the relay thread.
            HANDLE h = CreateFileA(device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                tap = h;
                guid = candidate;
                break;
            }
            last_error = GetLastError();
        }
        (void)last_error;
        if (tap == INVALID_HANDLE_VALUE) return false;
        DWORD returned = 0;
        unsigned long media_status = 1;
        DeviceIoControl(tap, TAP_IOCTL_SET_MEDIA_STATUS, &media_status, sizeof(media_status),
                        &media_status, sizeof(media_status), &returned, NULL);
        adapter = adapter_friendly_name(guid);
        if (adapter.empty()) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        if (!is_tap_friendly_name(adapter)) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        if (!adapter_connection_exists_server(adapter)) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        return true;
    };

    if (!try_find_gateway_tap()) {
        if (!is_admin_server()) {
            std::cerr << "No TAP adapter found: gateway address " << server_virtual_ip() << " is not available (run the server as administrator)." << std::endl;
            return false;
        }
        std::string exe_dir = get_exe_dir_server();
        std::string inf_path = exe_dir + "\\resources\\tap\\OemVista.inf";
        std::string devcon_path = exe_dir + "\\resources\\tap\\devcon.exe";
        std::string pnputil = std::string(system_dir) + "\\pnputil.exe";
        long long exit_code = 0;
        (void)run_hidden_command("\"" + pnputil + "\" /add-driver \"" + inf_path + "\"", &exit_code);
        // Do NOT "remove/restart *tap0901*": when a client runs on this same
        // host, "*tap0901*" also hits its "Client Adaptor" and destroys it
        // (ipconfig then shows Client Adaptor without an IP and no
        // Server Adaptor at all). Only ADD one adapter — if the existing
        // TAPs are busy, install creates a second one without touching the
        // first. Disabled adapters are already enabled inside the health
        // check via netsh.
        std::cout << "TAP adapter not found: installing one for gateway..." << std::endl;
        (void)run_hidden_command("\"" + devcon_path + "\" install \"" + inf_path + "\" tap0901", &exit_code);
        Sleep(3000);
        if (!try_find_gateway_tap()) {
            std::cerr << "No TAP adapter found: gateway address " << server_virtual_ip() << " is not available." << std::endl;
            return false;
        }
        std::cout << "TAP adapter recovered for gateway." << std::endl;
    }

    long long exit_code = 0;

    // Bring the adapter up and give it the gateway address. A disabled or stale
    // TAP node accepts CreateFile but rejects the address, so a failed adapter
    // must not disable the gateway while a usable TAP still exists.
    for (;;) {
        std::string original_name = adapter;

        std::string enable_cmd = "\"" + netsh + "\" interface set interface name=\"" + adapter + "\" admin=enabled";
        (void)run_hidden_command(enable_cmd, &exit_code);

        maybe_rename_gateway_adapter(adapter, netsh);

        bool assigned = false;
        if (is_tap_friendly_name(adapter) && adapter_connection_exists_server(adapter)) {
            std::string address_cmd = "\"" + netsh + "\" interface ipv4 set address name=\"" + adapter +
                                      "\" static " + server_virtual_ip() + " " + ip_to_string(virtual_ip_mask);
            if (run_hidden_command(address_cmd, &exit_code) && exit_code == 0) {
                assigned = true;
            } else {
                std::cerr << "Could not assign " << server_virtual_ip() << " to \"" << adapter
                          << "\" (exit " << exit_code << ")." << std::endl;
            }
        } else {
            std::cerr << "Gateway adapter \"" << adapter << "\" did not pass TAP health check." << std::endl;
        }

        if (assigned) {
            break;
        }

        // Try the next TAP instead of leaving the gateway offline.
        rejected_adapters.insert(original_name);
        rejected_adapters.insert(adapter);
        if (tap != INVALID_HANDLE_VALUE) {
            CloseHandle(tap);
            tap = INVALID_HANDLE_VALUE;
        }
        if (!try_find_gateway_tap()) {
            std::cerr << "No further TAP adapter available for " << server_virtual_ip()
                      << "; gateway stays offline." << std::endl;
            return false;
        }
    }

    // The frame travels inside UDP, so the segment MTU has to shrink.
    bool mtu_ran = run_hidden_command("\"" + netsh + "\" interface ipv4 set subinterface \"" + adapter +
                                      "\" mtu=1400 store=persistent", &exit_code);
    if (!mtu_ran || exit_code != 0) {
        std::cerr << "MTU could not be set (exit " << exit_code << ")." << std::endl;
    }

    // "netsh advfirewall firewall add rule" has no interface= parameter, so an
    // interface-bound rule has to be created with New-NetFirewallRule.
    std::string powershell = std::string(system_dir) + "\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::string rule_name = "P2P VPN GW";
    // Interface-specific: a client running on the same machine adds a rule
    // too, so a shared name would make the second one skip ("rule exists").
    std::string icmp_rule_name = "P2P VPN GW ICMP";
    // Interface rules do not cover ICMP: inbound echo requests on the tunnel
    // adapter are still dropped, so clients cannot ping each other.
    std::string fw_script = "if (-not (Get-NetFirewallRule -DisplayName '" + rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + rule_name +
        "' -Direction Inbound -Action Allow -InterfaceAlias '" + adapter + "' -Profile Any | Out-Null }; "
        "if (-not (Get-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias '" + adapter +
        "' -Profile Any | Out-Null }";

    bool fw_ok = run_hidden_command("\"" + powershell + "\" -NoProfile -NonInteractive -Command \"" +
                                    fw_script + "\"", &exit_code) && exit_code == 0;
    if (!fw_ok) {
        std::cerr << "Firewall rule could not be created (exit " << exit_code << ")." << std::endl;
    } else {
        std::cout << "Firewall rule \"" << rule_name << "\" ready for \"" << adapter << "\"" << std::endl;
    }

    if (nat_enabled) {
        std::string powershell = std::string(system_dir) + "\\WindowsPowerShell\\v1.0\\powershell.exe";
        std::string nat_cmd = "\"" + powershell + "\" -NoProfile -Command \"if (-not (Get-NetNat -Name P2PVPN -ErrorAction SilentlyContinue)) "
                              "{ New-NetNat -Name P2PVPN -InternalIPInterfaceAddressPrefix " +
                              virtual_ip_prefix + "0/24 | Out-Null }\"";
        if (!run_hidden_command(nat_cmd, &exit_code) || exit_code != 0) {
            std::cerr << "NAT could not be enabled (WinNat service / administrator rights)." << std::endl;
        } else {
            std::cout << "NAT enabled: " << virtual_ip_prefix << "0/24 -> internet" << std::endl;
        }
    }

    gateway_tap = tap;
    gateway_adapter_name = adapter;

    std::cout << "Gateway active: " << server_virtual_ip() << " on \"" << adapter << "\"" << std::endl;

    std::thread(gateway_to_relay_thread).detach();
    std::thread(tap_writer_thread).detach();
    return true;
}

// ------------------------------------------------------------ Client handling

void handle_client(SOCKET client_sock, sockaddr_in client_addr) {
    char buf[512];
    ZeroMemory(buf, sizeof(buf));
    int len = recv(client_sock, buf, sizeof(buf) - 1, 0);
    std::string request = (len > 0) ? std::string(buf, len) : std::string();

    // Early client: answer clearly and close, so it retries instead of
    // holding a half-configured session.
    if (!server_ready.load()) {
        send_line(client_sock, "SERVER_STARTING Retry in a few seconds.");
        closesocket(client_sock);
        std::cout << "Rejected client " << inet_ntoa(client_addr.sin_addr)
                  << ": server still starting" << std::endl;
        return;
    }

    // One-shot ARPA query: resolve a name without joining the VPN. These
    // connections never become sessions, so they do not consume an address.
    std::string arpa_query = token_value(request, "ARPA_QUERY");
    if (!arpa_query.empty()) {
        std::string owner;
        std::string ip = arpa_get(arpa_query, &owner);
        if (!ip.empty()) {
            send_line(client_sock, "ARPA_IP:" + arpa_query + " ADDR:" + ip);
            std::cout << "ARPA query " << arpa_query << " -> " << ip << std::endl;
        } else {
            std::string normalized = arpa_normalize(arpa_query);
            if (normalized.empty()) {
                // root is the only name normalize() rejects
                std::string lowered = arpa_query;
                for (char& c : lowered) c = (char)tolower((unsigned char)c);
                size_t b = lowered.find_first_not_of(" \t\r\n");
                size_t e = lowered.find_last_not_of(" \t\r\n");
                std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
                if (t == "root" || t == "root." + arpa_suffix) {
                    ip = arpa_get("root." + arpa_suffix, &owner);
                    if (!ip.empty()) {
                        send_line(client_sock, "ARPA_IP:" + arpa_query + " ADDR:" + ip);
                        std::cout << "ARPA query " << arpa_query << " -> " << ip << std::endl;
                        closesocket(client_sock);
                        return;
                    }
                }
            }
            send_line(client_sock, "ARPA_ERR:" + arpa_query + " CODE:not_found");
            std::cout << "ARPA query " << arpa_query << " -> NXDOMAIN" << std::endl;
        }
        closesocket(client_sock);
        return;
    }
    std::string public_ip = inet_ntoa(client_addr.sin_addr);
    std::cout << "Client connected from " << public_ip << ":" << ntohs(client_addr.sin_port)
              << " (" << trim(request) << ")" << std::endl;

    int port = token_int(request, "UDP_PORT", 50000);
    uint16_t udp_port = (port > 0 && port <= 65535) ? (uint16_t)port : (uint16_t)50000;

    std::string identity = token_value(request, "IDENTITY");
    if (identity.size() < 8 || identity.size() > 64) {
        identity.clear();
    }

    size_t member_count = 0;

    auto session = std::make_shared<Session>();
    session->sock = client_sock;
    session->identity = identity;
    session->public_ip = public_ip;
    session->udp_port = udp_port;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);

        // A static client that reconnects while its old session is still open
        // must keep the SAME address. Drop the stale session instead of handing
        // out a different (drifting) IP.
        if (!session->identity.empty()) {
            std::string existing = db_lookup_ip(session->identity);
            if (!existing.empty()) {
                for (const auto& other : online) {
                    if (other != session && other->virtual_ip == existing) {
                        other->retired = true;
                        closesocket(other->sock);
                    }
                }
                online.erase(std::remove_if(online.begin(), online.end(),
                    [session](const std::shared_ptr<Session>& s) {
                        return s != session && s->retired;
                    }), online.end());
                // free the address if no other session still holds it
                bool still_used = false;
                for (const auto& other : online) {
                    if (other != session && other->virtual_ip == existing) { still_used = true; break; }
                }
                if (!still_used) {
                    active_ips.erase(existing);
                }
            }
        }

        session->virtual_ip = assign_virtual_ip(session->identity, "");
        if (session->virtual_ip.empty() || session->virtual_ip == server_virtual_ip()) {
            std::cerr << "No free virtual address left for " << public_ip << ":" << udp_port << std::endl;
            send_line(client_sock, "NO_ADDRESS");
            closesocket(client_sock);
            return;
        }

        active_ips.insert(session->virtual_ip);
        online.push_back(session);
        member_count = online.size();
    }

    std::string response = "YOUR_IP:" + session->virtual_ip +
                           " RELAY_PORT:" + std::to_string(relay_port) +
                           " MEMBERS:" + std::to_string(member_count);
    if (gateway_tap != INVALID_HANDLE_VALUE) {
        response += " GATEWAY:" + server_virtual_ip();
        response += " MASK:" + ip_to_string(virtual_ip_mask);
    }

    // Name registrations are server-side only (admin adds names to domain.db).
    // Clients do not register names over the control channel.

    send_line(client_sock, response);

    std::cout << "Assigned " << session->virtual_ip
              << (session->identity.empty() ? " (dynamic)" : " (static " + session->identity + ")")
              << " to client " << session->public_ip << ":" << session->udp_port
              << " [" << online.size() << " member(s)]" << std::endl;

    // Clients send a keepalive every 5 seconds; give them plenty of slack
    // before declaring the session dead.
    DWORD monitor_timeout = 60000;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&monitor_timeout, sizeof(monitor_timeout));

    char keepalive[128];
    for (;;) {
        int received = recv(client_sock, keepalive, sizeof(keepalive), 0);
        if (received > 0) {
            continue;  // keepalive
        }
        break;         // closed or timed out
    }

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        online.erase(std::remove(online.begin(), online.end(), session), online.end());
        if (!session->retired) {
            active_ips.erase(session->virtual_ip);
        }
    }

    closesocket(client_sock);

    std::cout << "Session closed for " << session->public_ip << ":" << session->udp_port
              << " (" << session->virtual_ip << ")" << std::endl;
}

// Startup runs as an ordered sequence so the network side (TAP adapter,
// gateway address, firewall, NAT) is ready before any port is opened. A client
// that starts early then fails to connect and retries, instead of joining a
// server that cannot carry its traffic yet.
const int kStartupSteps = 7;

void startup_begin(int step, const std::string& label) {
    std::cout << "[" << step << "/" << kStartupSteps << "] " << label << " ... " << std::flush;
}

void startup_ok() { std::cout << "OK" << std::endl; }

int startup_fail(const std::string& label, const std::string& reason) {
    std::cout << "FAILED" << std::endl;
    std::cerr << "\xE2\x9D\x8C Server not ready: " << label << " - " << reason << std::endl;
    return 1;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "RootLayer Server" << std::endl;

    // Configuration first, then the numbered sequence: the printed settings
    // above stay readable instead of being squeezed between step markers.
    load_server_config_from_ini("server.ini");

    startup_begin(1, "Identity database");
    if (!db_open(get_exe_dir_server())) {
        return startup_fail("Identity database", "could not be opened");
    }
    db_prune_stale_rows();
    startup_ok();

    startup_begin(2, "ARPA name database");
    bool name_service = arpa_open(get_exe_dir_server());
    if (name_service) {
        arpa_reserve_root(server_virtual_ip(), 60);
        for (const auto& suf : arpa_suffixes) {
            std::cout << "\n      root." << suf << " -> " << server_virtual_ip() << "  " << std::flush;
        }
    }
    std::cout << (name_service ? "OK" : "OK (name service disabled)") << std::endl;

    startup_begin(3, "Network stack (Winsock)");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return startup_fail("Winsock", "WSAStartup failed");
    }
    startup_ok();

    // Network first: adapter, gateway address, MTU, firewall and NAT.
    startup_begin(4, "TAP adapter, gateway " + server_virtual_ip() + ", firewall and NAT");
    bool gateway_ready = true;
    std::string gateway_note;
    if (!gateway_enabled) {
        std::cout << "skipped (gateway disabled in server.ini)" << std::endl;
    } else if (!is_admin_server()) {
        std::cout << "WARNING" << std::endl;
        gateway_ready = false;
        gateway_note = "server is not elevated, so " + server_virtual_ip() +
                       " cannot be configured; run server.exe as administrator";
        std::cerr << "\xE2\x9D\x8C Gateway: " << gateway_note << std::endl;
    } else if (!setup_gateway()) {
        std::cout << "FAILED" << std::endl;
        gateway_ready = false;
        gateway_note = "no usable TAP adapter took " + server_virtual_ip() +
                       "; clients can reach each other but not the gateway";
        std::cerr << "\xE2\x9D\x8C Gateway: " << gateway_note << std::endl;
    } else {
        startup_ok();
    }

    startup_begin(5, "Relay socket (UDP " + std::to_string(relay_port) + ")");
    relay_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (relay_sock == INVALID_SOCKET) {
        WSACleanup();
        return startup_fail("Relay socket", "creation failed: " + std::to_string(WSAGetLastError()));
    }

    int relay_buffer = 4 * 1024 * 1024;
    setsockopt(relay_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&relay_buffer, sizeof(relay_buffer));
    setsockopt(relay_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&relay_buffer, sizeof(relay_buffer));

    sockaddr_in relay_addr;
    ZeroMemory(&relay_addr, sizeof(relay_addr));
    relay_addr.sin_family = AF_INET;
    relay_addr.sin_port = htons(relay_port);
    if (server_local_ip_u32 != 0) {
        in_addr local_in;
        local_in.s_addr = htonl(server_local_ip_u32);
        relay_addr.sin_addr = local_in;
    } else {
        relay_addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(relay_sock, (sockaddr*)&relay_addr, sizeof(relay_addr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(relay_sock);
        WSACleanup();
        return startup_fail("Relay socket", "bind on UDP " + std::to_string(relay_port) +
                                                " failed (" + std::to_string(error) + ")");
    }
    startup_ok();

    // Signaling listener is the last network resource: from here on a client
    // can connect, so everything above must already be in place.
    startup_begin(6, "Signaling listener (TCP " + std::to_string(signaling_port) + ")");
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        int error = WSAGetLastError();
        closesocket(relay_sock);
        WSACleanup();
        return startup_fail("Signaling socket", "creation failed: " + std::to_string(error));
    }

    BOOL reuse = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in serv_addr;
    ZeroMemory(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(signaling_port);
    if (server_local_ip_u32 != 0) {
        in_addr local_in;
        local_in.s_addr = htonl(server_local_ip_u32);
        serv_addr.sin_addr = local_in;
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(listen_sock, (sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(listen_sock);
        closesocket(relay_sock);
        WSACleanup();
        return startup_fail("Signaling listener", "bind on TCP " + std::to_string(signaling_port) +
                                                       " failed (" + std::to_string(error) + ")");
    }

    if (listen(listen_sock, 5) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        closesocket(listen_sock);
        closesocket(relay_sock);
        WSACleanup();
        return startup_fail("Signaling listener", "listen failed: " + std::to_string(error));
    }
    startup_ok();

    startup_begin(7, "Starting relay, DNS and session workers");
    std::thread(relay_thread).detach();
    // DNS name server for *.p2p (UDP 53) - answers from domain.db
    if (name_service) std::thread(dns_thread).detach();
    server_ready = true;
    startup_ok();

    std::cout << "      Signaling: TCP " << signaling_port << "   Relay: UDP " << relay_port << std::endl;
    if (name_service) {
        std::cout << "      DNS: UDP 53 (*.";
        for (const auto& suf : arpa_suffixes) std::cout << " " << suf;
        std::cout << ")" << std::endl;
    }
    std::cout << "      Gateway " << server_virtual_ip() << "   Pool from "
              << virtual_ip_prefix << (virtual_ip_start_octet + 1) << std::endl;
    if (gateway_ready) {
        std::cout << "\xE2\x9C\x85 Ready Server" << std::endl;
    } else {
        std::cout << "\xE2\x9A\xA0\xEF\xB8\x8F Ready Server (relay only): " << gateway_note << std::endl;
    }
    std::cout << std::flush;

    for (;;) {
        sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, (sockaddr*)&client_addr, &client_len);

        if (client_sock == INVALID_SOCKET) {
            std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }

        // Reading the request must not block the accept loop.
        DWORD io_timeout = 10000;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&io_timeout, sizeof(io_timeout));

        std::thread(handle_client, client_sock, client_addr).detach();
    }

    relay_running = false;
    closesocket(listen_sock);
    closesocket(relay_sock);
    WSACleanup();
    return 0;
}
