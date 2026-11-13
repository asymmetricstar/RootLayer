// server/core/globals.cpp - global server state (see core/globals.h).
#include "core/win_headers.h"
#include "core/globals.h"

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
std::set<std::string> arpa_suffixes;
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
std::string ip_to_string(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(buf);
}
std::string arpa_suffix = "p2p";
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
HANDLE gateway_tap = INVALID_HANDLE_VALUE;
std::string gateway_adapter_name;
SOCKET relay_sock = INVALID_SOCKET;
std::atomic<bool> relay_running(true);
// False until the gateway, relay socket and signaling listener are all up.
// Clients that arrive before this is true are turned away instead of being
// handed an address the tunnel cannot back yet.
std::atomic<bool> server_ready(false);
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

std::mutex sessions_mutex;
std::vector<std::shared_ptr<Session>> online;
std::set<std::string> active_ips;

uint32_t server_local_ip_u32 = 0;
