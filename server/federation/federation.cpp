// server/federation/federation.cpp
//
// Federation control plane (TCP) and data plane (UDP).
//
// Role model (see docs/federation.md):
//   - a server with `link=` empty runs SINGLE and is the PRIMARY the others
//     may link to; it is the only writer of global data;
//   - a server with `link=<primary ip>` runs LINKED: it keeps its own clients,
//     sends registrations and global writes to the primary, and reads global
//     data from it;
//   - when the heartbeat stops the replica goes DEGRADED: reads continue from
//     the synced copy, writes are refused, and it keeps trying to reconnect.
//
// Data plane: an IPv4 packet whose destination is outside this server's own
// address space but inside a peer's prefix is wrapped in a 32 byte envelope and
// sent straight to that peer's UDP data port. One hop only: a received
// envelope is delivered locally and never forwarded again.
#include "federation/federation.h"

#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "arpa/arpa.h"
#include "session/session.h"
#include "gateway/gateway.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdint>
#include <map>
#include <random>

namespace fed {

std::string link_target;
int link_port = 40002;
int link_primary_port = 40002;
int link_data_port = 40003;
std::string link_id;
std::string link_secret;
int cache_ttl_sec = 60;

}  // namespace fed

namespace {

const uint32_t kEnvelopeMagic = 0x524C4E4Bu;  // "RLNK" on the wire
const int kEnvelopeSize = 32;
const int kHeartbeatSec = 5;
const int kHeartbeatTimeoutSec = 15;
const int kMaxConnections = 32;
const size_t kMaxLine = 65536;

#pragma pack(push, 1)
struct Envelope {
    uint32_t magic;
    uint8_t version;
    uint8_t ttl;
    uint16_t payload_len;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint64_t src_id;
    uint64_t dst_id;
};
#pragma pack(pop)
static_assert(sizeof(Envelope) == 32, "federation envelope layout");

struct Prefix {
    uint32_t net = 0;
    uint32_t mask = 0;
    int len = 0;
    bool valid = false;
};

struct PeerState {
    std::string id;
    std::string ip;
    int data_port = 0;
    std::string prefix;
    bool primary = false;
    long long last_seen = 0;
};

// One link connected *to* this server (primary side).
struct ConnState {
    SOCKET sock = INVALID_SOCKET;
    std::mutex write_mutex;
    std::string id;
    std::string ip;
    std::string prefix;
    int data_port = 0;
};

struct NameSlot {
    std::string ip;
    std::string owner;
    long long expires = 0;
};

std::atomic<bool> g_running{false};
std::atomic<int> g_mode{(int)fed::Mode::Single};
std::atomic<bool> g_connector_running{false};
std::atomic<long long> g_epoch{0};
std::atomic<long long> g_last_pong{0};
std::atomic<SOCKET> g_link_sock{(SOCKET)INVALID_SOCKET};

SOCKET g_data_sock = INVALID_SOCKET;
SOCKET g_listen_sock = INVALID_SOCKET;

std::mutex g_mutex;
std::map<std::string, PeerState> g_peers;
std::map<std::string, std::string> g_locations;  // virtual ip -> server id
std::map<std::string, NameSlot> g_names;
std::vector<std::shared_ptr<ConnState>> g_conns;

std::mutex g_write_mutex;
std::mutex g_req_mutex;
std::condition_variable g_req_cv;
std::map<long long, std::string> g_pending;
std::atomic<long long> g_next_rid{1};

// ---------------------------------------------------------------- helpers

long long now_sec() { return (long long)std::time(NULL); }

void log_line(const std::string& text) {
    std::cout << "[link] " << text << std::endl;
}

const char* mode_label(fed::Mode value) {
    switch (value) {
        case fed::Mode::Single: return "SINGLE";
        case fed::Mode::Linking: return "LINKING";
        case fed::Mode::Linked: return "LINKED";
        case fed::Mode::Degraded: return "DEGRADED";
        case fed::Mode::Unlinking: return "UNLINKING";
    }
    return "SINGLE";
}

void set_mode(fed::Mode value, const std::string& detail) {
    const fed::Mode previous = fed::mode();
    if (previous == value) {
        return;
    }
    g_mode.store((int)value);
    std::string text = std::string(mode_label(previous)) + " -> " + mode_label(value);
    if (!detail.empty()) {
        text += ": " + detail;
    }
    log_line(text);
}

std::string sanitize_id(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.') {
            out.push_back(c);
        }
    }
    if (out.size() > 32) out.resize(32);
    return out;
}

std::string random_hex(size_t bytes) {
    static std::mutex rng_mutex;
    static std::mt19937_64 rng(std::random_device{}());
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    std::lock_guard<std::mutex> lock(rng_mutex);
    for (size_t i = 0; i < bytes; ++i) {
        const unsigned int byte = (unsigned int)(rng() & 0xFF);
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

std::string hmac_hex(const std::string& key, const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (HMAC(EVP_sha256(), key.data(), (int)key.size(),
             (const unsigned char*)data.data(), data.size(), digest, &length) == NULL) {
        return "";
    }
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (unsigned int i = 0; i < length; ++i) {
        out.push_back(digits[digest[i] >> 4]);
        out.push_back(digits[digest[i] & 0x0F]);
    }
    return out;
}

uint64_t hash64(const std::string& text) {
    uint64_t hash = 1469598103934665603ULL;  // FNV-1a
    for (unsigned char c : text) {
        hash ^= (uint64_t)c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

uint64_t hton64(uint64_t value) {
    return ((uint64_t)htonl((uint32_t)(value >> 32))) |
           ((uint64_t)htonl((uint32_t)(value & 0xFFFFFFFFu)) << 32);
}

uint64_t ntoh64(uint64_t value) {
    return ((uint64_t)ntohl((uint32_t)(value & 0xFFFFFFFFu)) << 32) |
           (uint64_t)ntohl((uint32_t)(value >> 32));
}

bool parse_bool_off(const std::string& text) {
    std::string value;
    value.reserve(text.size());
    for (char c : text) value.push_back((char)tolower((unsigned char)c));
    return value.empty() || value == "0" || value == "false" || value == "no" ||
           value == "off" || value == "none" || value == "-";
}

// Strict dotted quad (inet_addr() accepts garbage).
bool parse_ipv4_text(const std::string& text, uint32_t& out) {
    unsigned int octets[4] = {0, 0, 0, 0};
    char tail = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2],
                    &octets[3], &tail) != 4) {
        return false;
    }
    for (int i = 0; i < 4; ++i) {
        if (octets[i] > 255) return false;
    }
    out = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
}

uint32_t mask_from_len(int len) {
    if (len <= 0) return 0;
    if (len >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - len);
}

Prefix parse_prefix(const std::string& text) {
    Prefix prefix;
    const size_t slash = text.find('/');
    if (slash == std::string::npos) return prefix;
    uint32_t net = 0;
    if (!parse_ipv4_text(text.substr(0, slash), net)) return prefix;
    const int len = std::atoi(text.c_str() + slash + 1);
    if (len < 8 || len > 32) return prefix;
    prefix.mask = mask_from_len(len);
    prefix.net = net & prefix.mask;
    prefix.len = len;
    prefix.valid = true;
    return prefix;
}

bool prefix_overlap(const Prefix& a, const Prefix& b) {
    return (a.net & b.mask) == (b.net & b.mask) || (b.net & a.mask) == (a.net & a.mask);
}

Prefix own_prefix_parsed() {
    static Prefix cached;
    if (cached.valid) return cached;
    uint32_t first = virtual_ip_first_client;
    uint32_t last = virtual_ip_last;
    if (first == 0 || first > last) {
        cached.mask = mask_from_len(virtual_ip_prefix_len);
        cached.net = virtual_ip_network & cached.mask;
        cached.len = virtual_ip_prefix_len;
        cached.valid = true;
        return cached;
    }
    uint32_t diff = first ^ last;
    int bits = 0;
    while (diff != 0) {
        ++bits;
        diff >>= 1;
    }
    const int len = 32 - bits;
    cached.mask = mask_from_len(len);
    cached.net = first & cached.mask;
    cached.len = len;
    cached.valid = true;
    return cached;
}

bool in_own_space(uint32_t address) {
    const Prefix own = own_prefix_parsed();
    return own.valid && (address & own.mask) == own.net;
}

// The subnet a client is configured with: its tunnel only carries this range,
// everything else leaves through the physical default gateway.
std::string segment_text() {
    return ip_to_string(virtual_ip_network & virtual_ip_mask) + "/" +
           std::to_string(virtual_ip_prefix_len);
}

bool prefix_inside_segment(const Prefix& prefix) {
    if (!prefix.valid) return false;
    const uint32_t network = virtual_ip_network & virtual_ip_mask;
    const uint32_t broadcast = network | (~virtual_ip_mask);
    const uint32_t last = prefix.net | (~prefix.mask);
    return prefix.net >= network && last <= broadcast;
}

// A peer outside this client segment is announced in the ROUTES token, so the
// client installs an explicit route through the tunnel gateway and the packet
// still enters the link. Log it so the operator can see which mechanism is in
// use; older clients that ignore ROUTES need one shared /16 segment instead.
void warn_if_outside_segment(const std::string& peer_id, const std::string& prefix_text) {
    const Prefix prefix = parse_prefix(prefix_text);
    if (!prefix.valid || prefix_inside_segment(prefix)) return;
    log_line("peer " + peer_id + " owns " + prefix_text +
             " outside this client segment " + segment_text() +
             "; announcing it as a client route through the tunnel gateway. "
             "Keeping one shared virtual_ip_prefix on all servers (for example /16 with "
             "one /24 pool slice each) also works and needs no client route.");
}

void send_text(SOCKET sock, const std::string& line) {
    if (sock == INVALID_SOCKET) return;
    const std::string data = line + "\n";
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(sock, data.c_str() + sent, (int)(data.size() - sent), 0);
        if (n <= 0) return;
        sent += (size_t)n;
    }
}

std::vector<std::string> split_char(const std::string& text, char separator) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= text.size()) {
        size_t pos = text.find(separator, start);
        if (pos == std::string::npos) pos = text.size();
        out.push_back(text.substr(start, pos - start));
        if (pos >= text.size()) break;
        start = pos + 1;
    }
    return out;
}

// ---- connection / peer registries ---------------------------------------

std::vector<std::shared_ptr<ConnState>> conns_snapshot() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_conns;
}

void send_to_conn(const std::shared_ptr<ConnState>& conn, const std::string& line) {
    if (!conn) return;
    std::lock_guard<std::mutex> lock(conn->write_mutex);
    send_text(conn->sock, line);
}

void broadcast_replicas(const std::string& line, const std::string& except_id) {
    for (const auto& conn : conns_snapshot()) {
        if (conn && conn->id == except_id) continue;
        send_to_conn(conn, line);
    }
}

bool send_to_primary(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_write_mutex);
    SOCKET sock = g_link_sock.load();
    if (sock == INVALID_SOCKET) return false;
    const std::string data = line + "\n";
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(sock, data.c_str() + sent, (int)(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

void clear_remote_state() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_peers.clear();
    g_locations.clear();
    g_names.clear();
}

void fill_peer_locked(const PeerState& peer) {
    g_peers[peer.id] = peer;
}

std::string peers_csv_locked(const std::string& except_id) {
    const long long now = now_sec();
    std::string csv;
    for (const auto& entry : g_peers) {
        const PeerState& peer = entry.second;
        if (peer.id == except_id) continue;
        if (!csv.empty()) csv += ";";
        csv += peer.id + "|" + peer.ip + "|" + std::to_string(peer.data_port) + "|" +
               peer.prefix + "|" + (peer.primary ? "primary" : "replica") + "|" +
               std::to_string(peer.last_seen > 0 && now >= peer.last_seen ? now - peer.last_seen
                                                                        : -1);
    }
    return csv;
}

std::string locations_csv_locked(const std::string& except_id) {
    std::string csv;
    for (const auto& entry : g_locations) {
        if (entry.second == except_id) continue;
        if (!csv.empty()) csv += ";";
        csv += entry.first + "|" + entry.second;
    }
    return csv;
}

std::string names_csv() {
    std::string csv;
    for (const auto& record : arpa_list(500)) {
        if (!csv.empty()) csv += ";";
        csv += record.name + "|" + record.ip + "|" + std::to_string(record.ttl) + "|" +
               record.identity + "|" + record.info;
    }
    return csv;
}

std::string tld_csv() {
    std::string csv;
    for (const auto& suffix : arpa_tld_list()) {
        if (suffix.empty()) continue;
        if (!csv.empty()) csv += ",";
        csv += suffix;
    }
    return csv;
}

// Applies a synced name record to the local name database. A record already
// owned by someone else is reported as a conflict, never overwritten.
void apply_synced_name(const std::string& name, const std::string& ip, int ttl,
                       const std::string& owner, const std::string& info) {
    if (name.empty() || ip.empty()) return;
    const std::string identity = owner.empty() ? "federation.primary" : owner;
    std::string canonical;
    const std::string result = arpa_set(name, identity, ip, ttl, info, &canonical);
    if (result != "ok") {
        if (result == "taken") {
            log_line("name conflict for " + name + ", the local record was kept");
        }
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    NameSlot slot;
    slot.ip = ip;
    slot.owner = identity;
    slot.expires = now_sec() + 300;
    g_names[canonical.empty() ? name : canonical] = slot;
}

// ------------------------------------------------------------ primary side

bool handle_hello(const std::shared_ptr<ConnState>& conn, const std::string& line) {
    const std::string command = line.substr(0, line.find(' '));
    if (command != "HELLO") {
        send_to_conn(conn, "HELLO_ERR CODE:expected_hello");
        return false;
    }

    const std::string id = sanitize_id(token_value(line, "ID"));
    if (id.empty() || id == fed::link_id) {
        send_to_conn(conn, "HELLO_ERR CODE:bad_id");
        return false;
    }

    if (!fed::link_secret.empty()) {
        const std::string nonce = token_value(line, "NONCE");
        const std::string proof = token_value(line, "PROOF");
        if (nonce.empty() || proof != hmac_hex(fed::link_secret, nonce)) {
            log_line("link from " + conn->ip + " rejected: authentication failed");
            send_to_conn(conn, "HELLO_ERR CODE:auth");
            return false;
        }
    }

    const std::string prefix_text = token_value(line, "PREFIX");
    const Prefix prefix = parse_prefix(prefix_text);
    if (!prefix.valid) {
        send_to_conn(conn, "HELLO_ERR CODE:bad_prefix");
        return false;
    }
    if (prefix_overlap(prefix, own_prefix_parsed())) {
        log_line("link from " + conn->ip + " rejected: prefix " + prefix_text +
                 " overlaps this server's own address space");
        send_to_conn(conn, "HELLO_ERR CODE:prefix_conflict");
        return false;
    }
    warn_if_outside_segment(id, prefix_text);

    int data_port = token_int(line, "DATA", 0);
    if (data_port < 1 || data_port > 65535) data_port = fed::link_data_port;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& other : g_conns) {
            if (!other || other->id == id) continue;
            if (other->prefix == prefix_text || prefix_overlap(prefix, parse_prefix(other->prefix))) {
                send_to_conn(conn, "HELLO_ERR CODE:prefix_conflict");
                return false;
            }
        }
    }

    conn->id = id;
    conn->prefix = prefix_text;
    conn->data_port = data_port;

    PeerState peer;
    peer.id = id;
    peer.ip = conn->ip;
    peer.data_port = data_port;
    peer.prefix = prefix_text;
    peer.primary = false;
    peer.last_seen = now_sec();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_conns.push_back(conn);
        fill_peer_locked(peer);
    }

    send_to_conn(conn, "HELLO_OK ID:" + fed::link_id +
                           " EPOCH:" + std::to_string(g_epoch.load()) +
                           " DATA:" + std::to_string(fed::link_data_port) +
                           " PREFIX:" + fed::own_prefix() + " ROLE:primary");

    // Full state for the new replica.
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        send_to_conn(conn, "SYNC_PEERS " + peers_csv_locked(conn->id));
        send_to_conn(conn, "SYNC_LOC " + locations_csv_locked(""));
    }
    send_to_conn(conn, "SYNC_NAMES " + names_csv());
    send_to_conn(conn, "SYNC_TLD " + tld_csv());

    broadcast_replicas("PEER_ADD ID:" + peer.id + " IP:" + peer.ip +
                           " DATA:" + std::to_string(peer.data_port) + " PREFIX:" + peer.prefix +
                           " ROLE:replica",
                       id);

    log_line("replica " + id + " linked from " + conn->ip + " owning " + prefix_text);
    return true;
}

// Returns false when the connection must be closed.
bool handle_primary_message(const std::shared_ptr<ConnState>& conn, const std::string& line) {
    // Request/reply commands carry a "RID:<n> " prefix; the command word is the
    // first token after it.
    std::string body = line;
    const std::string rid = token_value(line, "RID");
    if (!rid.empty()) {
        const std::string prefix = "RID:" + rid;
        if (body.rfind(prefix, 0) == 0) body = trim(body.substr(prefix.size()));
    }
    const std::string command = body.substr(0, body.find(' '));

    if (command == "PING") {
        send_to_conn(conn, "PONG");
        return true;
    }
    log_line("control " + command + " from " + (conn->id.empty() ? conn->ip : conn->id));
    if (command == "LINK_CLOSE") {
        log_line("replica " + conn->id + " closed the link");
        return false;
    }
    if (command == "REGISTER") {
        const std::string ip = token_value(line, "IP");
        uint32_t address = 0;
        const Prefix prefix = parse_prefix(conn->prefix);
        if (!parse_ipv4_text(ip, address) || !prefix.valid || (address & prefix.mask) != prefix.net) {
            log_line("registration refused from " + conn->id + ": " + ip +
                     " is outside its announced prefix");
            return true;
        }
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_locations[ip] = conn->id;
        }
        broadcast_replicas("LOC_ADD IP:" + ip + " ID:" + conn->id, conn->id);
        return true;
    }
    if (command == "UNREGISTER") {
        const std::string ip = token_value(line, "IP");
        if (ip.empty()) return true;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_locations.erase(ip);
        }
        broadcast_replicas("LOC_DEL IP:" + ip, conn->id);
        return true;
    }
    if (command == "LOOKUP_NAME") {
        const std::string name = token_value(line, "NAME");
        const std::string rid = token_value(line, "RID");
        std::string owner;
        std::string ip = arpa_get(name, &owner, NULL);
        const std::string prefix = rid.empty() ? "" : "RID:" + rid + " ";
        if (ip.empty()) {
            send_to_conn(conn, prefix + "NAME NONE");
        } else {
            send_to_conn(conn, prefix + "NAME IP:" + ip + " OWNER:" + owner);
        }
        return true;
    }
    if (command == "NAME_ADD") {
        const std::string name = token_value(line, "NAME");
        const std::string ip = token_value(line, "IP");
        const std::string owner = token_value(line, "OWNER");
        const int ttl = token_int(line, "TTL", 60);
        const int days = ttl < 1 || ttl > 86400 ? 60 : ttl;
        const std::string info = token_value(line, "INFO");
        const std::string rid = token_value(line, "RID");
        const std::string rid_prefix = rid.empty() ? "" : "RID:" + rid + " ";

        std::string canonical;
        const std::string result =
            arpa_set(name, owner.empty() ? "federation.replica" : owner, ip, days, info,
                     &canonical);
        if (result != "ok") {
            send_to_conn(conn, rid_prefix + "NAME_ERR CODE:" + result);
            return true;
        }
        send_to_conn(conn, rid_prefix + "NAME_OK NAME:" + canonical + " IP:" + ip +
                               " TTL:" + std::to_string(days));
        std::string announce = "NAME_SET NAME:" + canonical + " IP:" + ip +
                               " TTL:" + std::to_string(days) + " OWNER:" +
                               (owner.empty() ? std::string("federation.replica") : owner);
        if (!info.empty()) announce += " INFO:" + info;
        broadcast_replicas(announce, conn->id);
        return true;
    }
    if (command == "NAME_DEL") {
        const std::string name = token_value(line, "NAME");
        const std::string rid = token_value(line, "RID");
        const std::string rid_prefix = rid.empty() ? "" : "RID:" + rid + " ";
        if (!arpa_delete(name)) {
            send_to_conn(conn, rid_prefix + "NAME_ERR CODE:not_found");
            return true;
        }
        send_to_conn(conn, rid_prefix + "NAME_OK NAME:" + name);
        broadcast_replicas("NAME_DEL NAME:" + name, conn->id);
        return true;
    }
    return true;
}

void drop_conn(std::shared_ptr<ConnState> conn) {
    if (!conn) return;
    std::vector<std::string> removed_ips;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto it = g_conns.begin(); it != g_conns.end(); ++it) {
            if (*it == conn) {
                g_conns.erase(it);
                break;
            }
        }
        g_peers.erase(conn->id);
        for (auto it = g_locations.begin(); it != g_locations.end();) {
            if (it->second == conn->id) {
                removed_ips.push_back(it->first);
                it = g_locations.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (conn->sock != INVALID_SOCKET) closesocket(conn->sock);
    conn->sock = INVALID_SOCKET;
    if (!conn->id.empty()) {
        broadcast_replicas("PEER_DEL ID:" + conn->id, conn->id);
        for (const auto& ip : removed_ips) {
            broadcast_replicas("LOC_DEL IP:" + ip, conn->id);
        }
        log_line("replica " + conn->id + " unlinked");
    }
}

void serve_conn(std::shared_ptr<ConnState> conn) {
    if (!conn) return;
    DWORD timeout = 30000;  // a replica heartbeats every 5s
    setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    std::string buffer;
    bool hello_done = false;
    char chunk[4096];

    while (g_running.load()) {
        const int n = recv(conn->sock, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        buffer.append(chunk, (size_t)n);
        size_t position = 0;
        while ((position = buffer.find('\n')) != std::string::npos) {
            std::string line = trim(buffer.substr(0, position));
            buffer.erase(0, position + 1);
            if (line.empty()) continue;
            if (!hello_done) {
                if (!handle_hello(conn, line)) {
                    if (conn->sock != INVALID_SOCKET) closesocket(conn->sock);
                    conn->sock = INVALID_SOCKET;
                    return;
                }
                hello_done = true;
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                auto it = g_peers.find(conn->id);
                if (it != g_peers.end()) it->second.last_seen = now_sec();
            }
            if (!handle_primary_message(conn, line)) {
                if (conn->sock != INVALID_SOCKET) closesocket(conn->sock);
                conn->sock = INVALID_SOCKET;
                return;
            }
        }
        if (buffer.size() > kMaxLine) break;
    }
    drop_conn(conn);
}

void accept_thread() {
    while (g_running.load()) {
        sockaddr_in peer;
        int peer_len = sizeof(peer);
        SOCKET sock = accept(g_listen_sock, (sockaddr*)&peer, &peer_len);
        if (sock == INVALID_SOCKET) {
            if (!g_running.load()) break;
            Sleep(50);
            continue;
        }
        if ((int)conns_snapshot().size() >= kMaxConnections) {
            send_text(sock, "HELLO_ERR CODE:busy");
            closesocket(sock);
            continue;
        }
        auto conn = std::make_shared<ConnState>();
        conn->sock = sock;
        conn->ip = inet_ntoa(peer.sin_addr);
        std::thread(serve_conn, conn).detach();
    }
}

// ------------------------------------------------------------ replica side

void process_pending(const std::string& line) {
    const std::string rid_text = token_value(line, "RID");
    if (rid_text.empty()) return;
    const long long rid = atoll(rid_text.c_str());
    if (rid <= 0) return;
    std::lock_guard<std::mutex> lock(g_req_mutex);
    auto it = g_pending.find(rid);
    if (it != g_pending.end()) {
        it->second = line;
        g_req_cv.notify_all();
    }
}

void handle_replica_line(const std::string& line) {
    process_pending(line);

    const std::string command = line.substr(0, line.find(' '));
    const size_t space = line.find(' ');
    const std::string rest = space == std::string::npos ? "" : trim(line.substr(space + 1));

    if (command == "PONG") {
        g_last_pong.store(now_sec());
        return;
    }
    if (command == "PEER_ADD") {
        PeerState peer;
        peer.id = sanitize_id(token_value(line, "ID"));
        peer.ip = token_value(line, "IP");
        peer.data_port = token_int(line, "DATA", 0);
        peer.prefix = token_value(line, "PREFIX");
        peer.primary = token_value(line, "ROLE") == "primary";
        peer.last_seen = now_sec();
        if (peer.id.empty()) return;
        std::lock_guard<std::mutex> lock(g_mutex);
        fill_peer_locked(peer);
        return;
    }
    if (command == "PEER_DEL") {
        const std::string id = token_value(line, "ID");
        if (id.empty()) return;
        std::lock_guard<std::mutex> lock(g_mutex);
        g_peers.erase(id);
        for (auto it = g_locations.begin(); it != g_locations.end();) {
            if (it->second == id) {
                it = g_locations.erase(it);
            } else {
                ++it;
            }
        }
        return;
    }
    if (command == "LOC_ADD") {
        const std::string ip = token_value(line, "IP");
        const std::string id = token_value(line, "ID");
        if (ip.empty() || id.empty()) return;
        std::lock_guard<std::mutex> lock(g_mutex);
        g_locations[ip] = id;
        return;
    }
    if (command == "LOC_DEL") {
        const std::string ip = token_value(line, "IP");
        if (ip.empty()) return;
        std::lock_guard<std::mutex> lock(g_mutex);
        g_locations.erase(ip);
        return;
    }
    if (command == "SYNC_LOC") {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_locations.clear();
        if (!rest.empty()) {
            for (const auto& record : split_char(rest, ';')) {
                const auto fields = split_char(record, '|');
                if (fields.size() >= 2 && !fields[0].empty() && !fields[1].empty()) {
                    g_locations[fields[0]] = fields[1];
                }
            }
        }
        return;
    }
    if (command == "SYNC_PEERS") {
        std::lock_guard<std::mutex> lock(g_mutex);
        // The primary itself is not part of the replica list; keep the entry
        // that HELLO_OK created so the data plane still knows where it lives.
        std::map<std::string, PeerState> kept;
        for (const auto& entry : g_peers) {
            if (entry.second.primary) kept[entry.first] = entry.second;
        }
        g_peers.swap(kept);
        if (!rest.empty()) {
            for (const auto& record : split_char(rest, ';')) {
                const auto fields = split_char(record, '|');
                if (fields.size() < 4 || fields[0].empty()) continue;
                PeerState peer;
                peer.id = fields[0];
                peer.ip = fields[1];
                peer.data_port = std::atoi(fields[2].c_str());
                peer.prefix = fields[3];
                peer.primary = fields.size() > 4 && fields[4] == "primary";
                peer.last_seen = now_sec();
                fill_peer_locked(peer);
            }
        }
        return;
    }
    if (command == "SYNC_TLD") {
        for (const auto& suffix : split_char(rest, ',')) {
            if (!suffix.empty()) arpa_tld_add(suffix, NULL);
        }
        return;
    }
    if (command == "SYNC_NAMES") {
        if (rest.empty()) return;
        for (const auto& record : split_char(rest, ';')) {
            const auto fields = split_char(record, '|');
            if (fields.size() < 3 || fields[0].empty() || fields[1].empty()) continue;
            apply_synced_name(fields[0], fields[1], std::atoi(fields[2].c_str()),
                              fields.size() > 3 ? fields[3] : std::string(),
                              fields.size() > 4 ? fields[4] : std::string());
        }
        return;
    }
    if (command == "NAME_SET") {
        apply_synced_name(token_value(line, "NAME"), token_value(line, "IP"),
                          token_int(line, "TTL", 60), token_value(line, "OWNER"),
                          token_value(line, "INFO"));
        return;
    }
    if (command == "NAME_DEL") {
        const std::string name = token_value(line, "NAME");
        if (!name.empty()) arpa_delete(name);
        std::lock_guard<std::mutex> lock(g_mutex);
        g_names.erase(name);
        return;
    }
}

// Reads one line for the handshake and keeps whatever followed it in `carry`:
// the primary pushes the peer/location/name tables right behind HELLO_OK, so
// anything read past the first newline must reach the steady-state parser.
bool read_handshake_line(SOCKET sock, std::string& out, std::string& carry) {
    char chunk[512];
    for (int attempt = 0; attempt < 64; ++attempt) {
        const size_t position = carry.find('\n');
        if (position != std::string::npos) {
            out = trim(carry.substr(0, position));
            carry.erase(0, position + 1);
            return true;
        }
        const int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) return false;
        carry.append(chunk, (size_t)n);
        if (carry.size() > kMaxLine) return false;
    }
    return false;
}

SOCKET connect_to_primary() {
    uint32_t address = 0;
    if (!parse_ipv4_text(fed::link_target, address)) {
        log_line("link target " + fed::link_target + " is not an IPv4 address");
        return INVALID_SOCKET;
    }
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)fed::link_primary_port);
    addr.sin_addr.s_addr = htonl(address);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    return sock;
}

std::vector<std::pair<std::string, std::string>> online_clients() {
    std::vector<std::pair<std::string, std::string>> clients;
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (const auto& session : online) {
        if (!session || session->retired || session->virtual_ip.empty()) continue;
        clients.emplace_back(session->virtual_ip, client_db_key(session->hw_id, session->identity));
    }
    return clients;
}

void connector_thread() {
    while (g_running.load()) {
        if (fed::link_target.empty()) {
            Sleep(300);
            continue;
        }

        SOCKET sock = connect_to_primary();
        if (sock == INVALID_SOCKET) {
            if (fed::mode() != fed::Mode::Degraded) {
                set_mode(fed::Mode::Degraded, "primary " + fed::link_target + " unreachable");
            }
            Sleep(3000);
            continue;
        }

        // ---- handshake ---------------------------------------------------
        std::string nonce = random_hex(16);
        std::string hello = "HELLO ID:" + fed::link_id +
                            " DATA:" + std::to_string(fed::link_data_port) +
                            " PREFIX:" + fed::own_prefix() + " ROLE:replica";
        if (!fed::link_secret.empty()) {
            hello += " NONCE:" + nonce + " PROOF:" + hmac_hex(fed::link_secret, nonce);
        }
        {
            std::lock_guard<std::mutex> lock(g_write_mutex);
            g_link_sock.store(sock);
        }
        if (!send_to_primary(hello)) {
            std::lock_guard<std::mutex> lock(g_write_mutex);
            g_link_sock.store(INVALID_SOCKET);
            closesocket(sock);
            Sleep(3000);
            continue;
        }

        std::string buffer;
        std::string reply;
        if (!read_handshake_line(sock, reply, buffer) || reply.rfind("HELLO_OK", 0) != 0) {
            const std::string code = reply.empty() ? "no_answer" : token_value(reply, "CODE");
            log_line("handshake with " + fed::link_target + " failed: " +
                     (code.empty() ? reply : code));
            std::lock_guard<std::mutex> lock(g_write_mutex);
            g_link_sock.store(INVALID_SOCKET);
            closesocket(sock);
            set_mode(fed::Mode::Degraded, "primary refused the link");
            Sleep(5000);
            continue;
        }

        const std::string primary_id = sanitize_id(token_value(reply, "ID"));
        const long long epoch = atoll(token_value(reply, "EPOCH").c_str());
        const int primary_data = token_int(reply, "DATA", fed::link_data_port);
        const std::string primary_prefix = token_value(reply, "PREFIX");
        warn_if_outside_segment(primary_id, primary_prefix);

        g_epoch.store(epoch);
        g_last_pong.store(now_sec());
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_peers.clear();
            PeerState primary;
            primary.id = primary_id.empty() ? fed::link_target : primary_id;
            primary.ip = fed::link_target;
            primary.data_port = primary_data;
            primary.prefix = primary_prefix;
            primary.primary = true;
            primary.last_seen = now_sec();
            fill_peer_locked(primary);
        }

        // Announce the clients that are already connected; the primary answers
        // with the full location table after HELLO, this closes the gap for
        // clients that joined while the link was down.
        for (const auto& client : online_clients()) {
            send_to_primary("REGISTER IP:" + client.first + " KEY:" + client.second);
        }

        set_mode(fed::Mode::Linked, "primary " + fed::link_target + " epoch " +
                                       std::to_string(epoch));

        // ---- steady state ------------------------------------------------
        DWORD timeout = 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        long long last_ping = now_sec();
        char chunk[4096];
        while (g_running.load() && !fed::link_target.empty()) {
            const int n = recv(sock, chunk, sizeof(chunk), 0);
            if (n == 0) break;
            if (n < 0) {
                if (WSAGetLastError() != WSAETIMEDOUT) break;
            } else {
                buffer.append(chunk, (size_t)n);
                size_t position = 0;
                while ((position = buffer.find('\n')) != std::string::npos) {
                    std::string line = trim(buffer.substr(0, position));
                    buffer.erase(0, position + 1);
                    if (!line.empty()) handle_replica_line(line);
                }
                if (buffer.size() > kMaxLine) break;
            }

            const long long now = now_sec();
            if (now - g_last_pong.load() > kHeartbeatTimeoutSec) {
                log_line("heartbeat lost, primary did not answer for " +
                         std::to_string(kHeartbeatTimeoutSec) + "s");
                break;
            }
            if (now - last_ping >= kHeartbeatSec) {
                send_to_primary("PING");
                last_ping = now;
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_write_mutex);
            if (g_link_sock.load() == sock) g_link_sock.store(INVALID_SOCKET);
        }
        closesocket(sock);

        if (g_running.load() && !fed::link_target.empty()) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_peers.clear();
                g_locations.clear();
            }
            set_mode(fed::Mode::Degraded,
                     "link to " + fed::link_target + " lost, writes disabled");
            Sleep(3000);
        }
    }
}

// ------------------------------------------------------------- data plane

void data_thread() {
    char buffer[65535];
    while (g_running.load()) {
        sockaddr_in sender;
        int sender_len = sizeof(sender);
        const int len = recvfrom(g_data_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender,
                                 &sender_len);
        if (len <= 0) {
            if (!g_running.load()) break;
            Sleep(1);
            continue;
        }
        if (len < kEnvelopeSize) continue;

        Envelope envelope;
        memcpy(&envelope, buffer, kEnvelopeSize);
        if (ntohl(envelope.magic) != kEnvelopeMagic) continue;
        if (envelope.version != 1) continue;
        if (envelope.ttl != 1) continue;  // one hop only: no loops
        if (ntohs(envelope.payload_len) != (uint16_t)(len - kEnvelopeSize)) continue;

        const uint64_t dst_id = ntoh64(envelope.dst_id);
        if (dst_id != hash64(fed::link_id)) continue;

        const uint32_t src_ip = ntohl(envelope.src_ip);
        const uint32_t dst_ip = ntohl(envelope.dst_ip);

        // The sending server must be known and must own the source address.
        std::string peer_prefix;
        {
            const uint64_t src_id = ntoh64(envelope.src_id);
            std::lock_guard<std::mutex> lock(g_mutex);
            for (const auto& entry : g_peers) {
                if (hash64(entry.second.id) == src_id) {
                    peer_prefix = entry.second.prefix;
                    break;
                }
            }
        }
        if (peer_prefix.empty()) continue;
        const Prefix prefix = parse_prefix(peer_prefix);
        if (!prefix.valid || (src_ip & prefix.mask) != prefix.net) {
            log_line("dropped a spoofed packet claiming " + ip_to_string(src_ip));
            continue;
        }
        if (!in_own_space(dst_ip)) continue;

        const char* payload = buffer + kEnvelopeSize;
        const int payload_len = len - kEnvelopeSize;
        bool delivered = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            auto hit = sessions_by_ip.find(ip_to_string(dst_ip));
            if (hit != sessions_by_ip.end() && hit->second && hit->second->endpoint_known &&
                hit->second->download.allow((size_t)payload_len)) {
                sendto(relay_sock, payload, payload_len, 0, (sockaddr*)&hit->second->endpoint,
                       sizeof(hit->second->endpoint));
                delivered = true;
            }
        }
        if (!delivered && gateway_active.load() && dst_ip == virtual_ip_server) {
            queue_tap_frame(payload, payload_len);
        }
    }
}

// Peering needs TCP link_port and UDP link_data_port inbound on every server.
// The gateway rule only covers the adapter, so these are added by name; the
// rule is rebuilt on each start so a changed port does not leave a stale one.
void open_firewall_ports() {
    if (!is_admin_server()) {
        log_line("not elevated: open TCP " + std::to_string(fed::link_port) + " and UDP " +
                 std::to_string(fed::link_data_port) +
                 " in Windows Firewall, otherwise peering and federated traffic are blocked");
        return;
    }

    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    const std::string netsh = std::string(system_dir) + "\\netsh.exe";
    const std::string tcp_rule = "RootLayer Federation TCP";
    const std::string udp_rule = "RootLayer Federation UDP";

    long long code = 0;
    run_hidden_command("\"" + netsh + "\" advfirewall firewall delete rule name=\"" +
                           tcp_rule + "\"",
                       &code);
    run_hidden_command("\"" + netsh + "\" advfirewall firewall delete rule name=\"" +
                           udp_rule + "\"",
                       &code);

    const bool tcp_ok =
        run_hidden_command("\"" + netsh + "\" advfirewall firewall add rule name=\"" +
                               tcp_rule + "\" dir=in action=allow protocol=TCP localport=" +
                               std::to_string(fed::link_port),
                           &code) && code == 0;
    const bool udp_ok =
        run_hidden_command("\"" + netsh + "\" advfirewall firewall add rule name=\"" +
                               udp_rule + "\" dir=in action=allow protocol=UDP localport=" +
                               std::to_string(fed::link_data_port),
                           &code) && code == 0;

    if (tcp_ok && udp_ok) {
        log_line("firewall: TCP " + std::to_string(fed::link_port) + " and UDP " +
                 std::to_string(fed::link_data_port) + " open for peering");
    } else {
        log_line("firewall rules could not be created; open TCP " +
                 std::to_string(fed::link_port) + " and UDP " +
                 std::to_string(fed::link_data_port) + " manually on this server");
    }
}

bool request_primary(const std::string& body, int timeout_ms, std::string& response) {
    if (g_mode.load() != (int)fed::Mode::Linked) return false;
    const long long rid = ++g_next_rid;
    {
        std::lock_guard<std::mutex> lock(g_req_mutex);
        g_pending[rid] = "";
    }
    if (!send_to_primary("RID:" + std::to_string(rid) + " " + body)) {
        std::lock_guard<std::mutex> lock(g_req_mutex);
        g_pending.erase(rid);
        return false;
    }
    std::unique_lock<std::mutex> lock(g_req_mutex);
    const bool ready = g_req_cv.wait_for(
        lock, std::chrono::milliseconds(timeout_ms), [&] {
            auto it = g_pending.find(rid);
            return it != g_pending.end() && !it->second.empty();
        });
    if (!ready) {
        g_pending.erase(rid);
        log_line("no answer from the primary for: " + body);
        return false;
    }
    response = g_pending[rid];
    g_pending.erase(rid);
    return true;
}

}  // namespace

// ------------------------------------------------------------------- config

void fed::load_settings(const std::string& ini_path) {
    char buffer[256] = {0};

    if (GetPrivateProfileStringA("Settings", "link", "", buffer, sizeof(buffer),
                                 ini_path.c_str()) != 0) {
        const std::string value = trim(std::string(buffer));
        uint32_t address = 0;
        if (parse_bool_off(value)) {
            fed::link_target.clear();
        } else if (parse_ipv4_text(value, address)) {
            fed::link_target = value;
        } else {
            std::cerr << "link=\"" << value
                      << "\" is neither an IPv4 address nor false; federation stays single."
                      << std::endl;
            fed::link_target.clear();
        }
    }

    const unsigned long port = GetPrivateProfileIntA("Settings", "link_port", 40002,
                                                     ini_path.c_str());
    if (port > 0 && port <= 65535) fed::link_port = (int)port;

    // Port on the primary: defaults to link_port, so two servers on different
    // hosts need nothing extra, while a NAT/port-forward setup can differ.
    fed::link_primary_port = fed::link_port;
    const unsigned long primary_port =
        GetPrivateProfileIntA("Settings", "link_primary_port", fed::link_port,
                             ini_path.c_str());
    if (primary_port > 0 && primary_port <= 65535) {
        fed::link_primary_port = (int)primary_port;
    }

    const unsigned long data_port = GetPrivateProfileIntA("Settings", "link_data_port", 40003,
                                                          ini_path.c_str());
    if (data_port > 0 && data_port <= 65535) fed::link_data_port = (int)data_port;

    {
        char id_buffer[128] = {0};
        GetPrivateProfileStringA("Settings", "link_id", "", id_buffer, sizeof(id_buffer),
                                 ini_path.c_str());
        std::string id = sanitize_id(trim(std::string(id_buffer)));
        if (id.empty()) {
            id = "srv-" + ip_to_string(virtual_ip_server);
            for (char& c : id) {
                if (c == '.') c = '-';
            }
        }
        fed::link_id = id;
    }

    {
        char secret_buffer[256] = {0};
        GetPrivateProfileStringA("Settings", "link_secret", "", secret_buffer,
                                 sizeof(secret_buffer), ini_path.c_str());
        fed::link_secret = trim(std::string(secret_buffer));
    }

    const unsigned long ttl = GetPrivateProfileIntA("Settings", "link_cache_ttl_sec", 60,
                                                    ini_path.c_str());
    if (ttl > 0 && ttl <= 3600) fed::cache_ttl_sec = (int)ttl;
}

// -------------------------------------------------------------------- mode

bool fed::is_primary() { return fed::link_target.empty(); }

fed::Mode fed::mode() { return (fed::Mode)g_mode.load(); }

std::string fed::mode_name() { return mode_label(fed::mode()); }

std::string fed::own_prefix() {
    const Prefix own = own_prefix_parsed();
    if (!own.valid) return "";
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "/%d", own.len);
    return ip_to_string(own.net) + buffer;
}

// --------------------------------------------------------------- lifecycle

bool fed::start() {
    if (g_running.exchange(true)) return true;
    g_epoch.store(now_sec());

    // Data plane socket. A failure is not fatal: the server still works as a
    // single server, only remote client traffic cannot be carried.
    g_data_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_data_sock == INVALID_SOCKET) {
        log_line("UDP data socket could not be created");
    } else {
        int buffer_size = 2 * 1024 * 1024;
        setsockopt(g_data_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&buffer_size,
                   sizeof(buffer_size));
        setsockopt(g_data_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&buffer_size,
                   sizeof(buffer_size));
        sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)fed::link_data_port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(g_data_sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            log_line("UDP " + std::to_string(fed::link_data_port) +
                     " could not be bound, federation data disabled");
            closesocket(g_data_sock);
            g_data_sock = INVALID_SOCKET;
        } else {
            std::thread(data_thread).detach();
        }
    }

    // Peering listener: always up, so a SINGLE server can be a primary.
    g_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen_sock == INVALID_SOCKET) {
        log_line("peering listener socket could not be created");
    } else {
        BOOL reuse = TRUE;
        setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)fed::link_port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(g_listen_sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
            listen(g_listen_sock, 8) == SOCKET_ERROR) {
            log_line("TCP " + std::to_string(fed::link_port) +
                     " could not be bound, replicas cannot link to this server");
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
        } else {
            std::thread(accept_thread).detach();
        }
    }

    open_firewall_ports();

    if (!fed::link_target.empty()) {
        set_mode(fed::Mode::Linking, "connecting to primary " + fed::link_target);
        if (!g_connector_running.exchange(true)) {
            std::thread(connector_thread).detach();
        }
    }

    if (fed::link_secret.empty()) {
        log_line("link_secret is empty; the peering handshake is not authenticated");
    }
    log_line(std::string("role ") + (fed::is_primary() ? "PRIMARY" : "REPLICA") + ", mode " +
             fed::mode_name() + ", own prefix " + fed::own_prefix() + ", control TCP " +
             std::to_string(fed::link_port) + ", data UDP " +
             std::to_string(fed::link_data_port));
    return true;
}

void fed::stop() {
    if (!g_running.exchange(false)) return;
    SOCKET link = g_link_sock.exchange(INVALID_SOCKET);
    if (link != INVALID_SOCKET) closesocket(link);
    if (g_listen_sock != INVALID_SOCKET) {
        closesocket(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
    }
    if (g_data_sock != INVALID_SOCKET) {
        closesocket(g_data_sock);
        g_data_sock = INVALID_SOCKET;
    }
}

// ------------------------------------------------------------- diagnostics

std::string fed::status_tokens() {
    size_t peer_count = 0;
    size_t location_count = 0;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        peer_count = g_peers.size();
        location_count = g_locations.size();
    }
    const long long seen = g_last_pong.load();
    const long long age = seen > 0 ? now_sec() - seen : -1;
    std::string out = "MODE:" + fed::mode_name();
    out += " ROLE:" + std::string(fed::is_primary() ? "PRIMARY" : "REPLICA");
    out += " LINK:" + (fed::link_target.empty() ? std::string("-") : fed::link_target) + ":" +
           std::to_string(fed::link_primary_port);
    out += " PREFIX:" + fed::own_prefix();
    out += " EPOCH:" + std::to_string(g_epoch.load());
    out += " PEERS:" + std::to_string(peer_count);
    out += " LOCATIONS:" + std::to_string(location_count);
    out += " AGE:" + std::to_string(age);

    // route:ok  - every peer block is on-link for clients (shared /16 segment)
    // route:client - peer blocks are outside the client's mask and are pushed
    //                as ROUTES entries so clients route them into the tunnel.
    bool route_ok = true;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& entry : g_peers) {
            const Prefix prefix = parse_prefix(entry.second.prefix);
            if (prefix.valid && !prefix_inside_segment(prefix)) {
                route_ok = false;
                break;
            }
        }
    }
    out += std::string(" ROUTE:") + (route_ok ? "ok" : "client");
    return out;
}

std::vector<fed::PeerInfo> fed::peers() {
    std::vector<fed::PeerInfo> out;
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& entry : g_peers) {
        fed::PeerInfo info;
        info.id = entry.second.id;
        info.ip = entry.second.ip;
        info.data_port = entry.second.data_port;
        info.prefix = entry.second.prefix;
        info.primary = entry.second.primary;
        info.last_seen = entry.second.last_seen;
        out.push_back(info);
    }
    return out;
}

std::string fed::peers_csv() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return peers_csv_locked("");
}

// -------------------------------------------------------------- data plane

bool fed::forward_packet(const char* packet, int len) {
    if (len < 20 || (((unsigned char)packet[0]) >> 4) != 4) return false;
    if (!g_running.load() || g_data_sock == INVALID_SOCKET) return false;

    uint32_t dst_network = 0;
    memcpy(&dst_network, packet + 16, sizeof(dst_network));
    const uint32_t dst = ntohl(dst_network);
    if (in_own_space(dst)) return false;  // local traffic never leaves the server

    std::string target_ip;
    int target_port = 0;
    std::string target_id;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const std::string ip_text = ip_to_string(dst);
        auto location = g_locations.find(ip_text);
        if (location != g_locations.end()) {
            auto peer = g_peers.find(location->second);
            if (peer != g_peers.end()) {
                target_ip = peer->second.ip;
                target_port = peer->second.data_port;
                target_id = peer->second.id;
            }
        }
        if (target_ip.empty()) {
            for (const auto& entry : g_peers) {
                const Prefix prefix = parse_prefix(entry.second.prefix);
                if (prefix.valid && (dst & prefix.mask) == prefix.net) {
                    target_ip = entry.second.ip;
                    target_port = entry.second.data_port;
                    target_id = entry.second.id;
                    break;
                }
            }
        }
    }
    if (target_ip.empty() || target_port <= 0) return false;

    uint32_t src = 0;
    memcpy(&src, packet + 12, sizeof(src));
    src = ntohl(src);

    Envelope envelope;
    envelope.magic = htonl(kEnvelopeMagic);
    envelope.version = 1;
    envelope.ttl = 1;
    envelope.payload_len = htons((uint16_t)len);
    envelope.src_ip = htonl(src);
    envelope.dst_ip = htonl(dst);
    envelope.src_id = hton64(hash64(fed::link_id));
    envelope.dst_id = hton64(hash64(target_id));

    char framed[65535 + kEnvelopeSize];
    memcpy(framed, &envelope, kEnvelopeSize);
    memcpy(framed + kEnvelopeSize, packet, (size_t)len);

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)target_port);
    addr.sin_addr.s_addr = inet_addr(target_ip.c_str());

    const int sent = sendto(g_data_sock, framed, kEnvelopeSize + len, 0, (sockaddr*)&addr,
                            sizeof(addr));
    return sent > 0;
}

// --------------------------------------------------- client registration

void fed::note_client_online(const std::string& virtual_ip, const std::string& client_key) {
    if (virtual_ip.empty()) return;
    if (fed::link_target.empty()) {
        bool has_replicas = false;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_locations[virtual_ip] = fed::link_id;
            has_replicas = !g_conns.empty();
        }
        if (has_replicas) {
            broadcast_replicas("LOC_ADD IP:" + virtual_ip + " ID:" + fed::link_id, "");
        }
        return;
    }
    send_to_primary("REGISTER IP:" + virtual_ip + " KEY:" + client_key);
}

void fed::note_client_offline(const std::string& virtual_ip) {
    if (virtual_ip.empty()) return;
    if (fed::link_target.empty()) {
        bool removed = false;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            removed = g_locations.erase(virtual_ip) > 0;
        }
        if (removed) {
            broadcast_replicas("LOC_DEL IP:" + virtual_ip, "");
        }
        return;
    }
    send_to_primary("UNREGISTER IP:" + virtual_ip);
}

// -------------------------------------------------------------- names

bool fed::lookup_name(const std::string& name, std::string& ip, std::string* owner) {
    ip.clear();
    if (owner) owner->clear();
    if (name.empty() || fed::link_target.empty()) return false;

    const long long now = now_sec();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto hit = g_names.find(name);
        if (hit != g_names.end() && hit->second.expires > now) {
            ip = hit->second.ip;
            if (owner) *owner = hit->second.owner;
            return !ip.empty();
        }
    }

    std::string response;
    if (!request_primary("LOOKUP_NAME NAME:" + name, 2500, response)) return false;

    const std::string resolved_ip = token_value(response, "IP");
    const std::string resolved_owner = token_value(response, "OWNER");
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        NameSlot slot;
        slot.ip = resolved_ip;
        slot.owner = resolved_owner;
        slot.expires = now + (resolved_ip.empty() ? 15 : (fed::cache_ttl_sec > 0
                                                             ? fed::cache_ttl_sec
                                                             : 60));
        g_names[name] = slot;
    }
    ip = resolved_ip;
    if (owner) *owner = resolved_owner;
    return !ip.empty();
}

bool fed::name_add(const std::string& name, const std::string& ip, int ttl,
                   const std::string& owner, std::string& error,
                   std::string* canonical, const std::string& info) {
    if (fed::link_target.empty()) {
        error = "not_replica";
        return false;
    }
    std::string response;
    std::string line = "NAME_ADD NAME:" + name + " IP:" + ip +
                       " TTL:" + std::to_string(ttl) + " OWNER:" + owner;
    if (!info.empty()) line += " INFO:" + info;
    if (!request_primary(line, 3000, response)) {
        error = "primary_unavailable";
        return false;
    }
    if (response.find("NAME_OK") == std::string::npos) {
        error = token_value(response, "CODE");
        if (error.empty()) error = "rejected";
        return false;
    }
    if (canonical) *canonical = token_value(response, "NAME");
    return true;
}

bool fed::name_del(const std::string& name, std::string& error) {
    if (fed::link_target.empty()) {
        error = "not_replica";
        return false;
    }
    std::string response;
    if (!request_primary("NAME_DEL NAME:" + name, 3000, response)) {
        error = "primary_unavailable";
        return false;
    }
    if (response.find("NAME_OK") == std::string::npos) {
        error = token_value(response, "CODE");
        if (error.empty()) error = "rejected";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    g_names.erase(name);
    return true;
}

// -------------------------------------------------- single trust root

bool fed::certificate_proxy(const std::string& request, std::string& response) {
    response.clear();
    if (fed::link_target.empty() || request.empty()) return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)signaling_port);
    addr.sin_addr.s_addr = inet_addr(fed::link_target.c_str());
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    send_text(sock, request);

    // The primary answers with one or more CERT/CACERT lines and closes.
    char chunk[4096];
    for (;;) {
        const int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        response.append(chunk, (size_t)n);
    }
    closesocket(sock);
    response = trim(response);
    return !response.empty();
}

// ------------------------------------------------------- name announces

void fed::announce_name(const std::string& name, const std::string& ip, int ttl,
                        const std::string& owner, const std::string& info) {
    if (name.empty() || ip.empty() || !fed::link_target.empty()) return;
    std::string line = "NAME_SET NAME:" + name + " IP:" + ip +
                       " TTL:" + std::to_string(ttl) + " OWNER:" + owner;
    if (!info.empty()) line += " INFO:" + info;
    broadcast_replicas(line, "");
}

void fed::announce_name_delete(const std::string& name) {
    if (name.empty() || !fed::link_target.empty()) return;
    broadcast_replicas("NAME_DEL NAME:" + name, "");
}

// --------------------------------------------------------- link control

bool fed::link_connect(const std::string& ip, int port, std::string& error) {
    uint32_t address = 0;
    if (!parse_ipv4_text(ip, address)) {
        error = "bad_ip";
        return false;
    }
    if (port < 1 || port > 65535) {
        error = "bad_port";
        return false;
    }
    if (ip == server_virtual_ip()) {
        error = "cannot_link_to_self";
        return false;
    }

    const bool was_linked = !fed::link_target.empty();
    fed::link_target = ip;
    fed::link_primary_port = port;

    if (!server_ini_path().empty()) {
        WritePrivateProfileStringA("Settings", "link", ip.c_str(), server_ini_path().c_str());
        WritePrivateProfileStringA("Settings", "link_primary_port",
                                   std::to_string(port).c_str(),
                                   server_ini_path().c_str());
    }

    if (!g_running.load()) {
        error = "federation_not_running";
        return false;
    }
    if (!g_connector_running.exchange(true)) {
        std::thread(connector_thread).detach();
    }
    if (!was_linked) {
        set_mode(fed::Mode::Linking, "operator linked this server to " + ip);
    }
    return true;
}

bool fed::link_disconnect(std::string& error) {
    if (fed::link_target.empty()) {
        error = "not_linked";
        return false;
    }
    set_mode(fed::Mode::Unlinking, "operator closed the link");
    send_to_primary("LINK_CLOSE");

    {
        std::lock_guard<std::mutex> lock(g_write_mutex);
        SOCKET sock = g_link_sock.exchange(INVALID_SOCKET);
        if (sock != INVALID_SOCKET) closesocket(sock);
    }

    fed::link_target.clear();
    if (!server_ini_path().empty()) {
        WritePrivateProfileStringA("Settings", "link", "", server_ini_path().c_str());
    }
    clear_remote_state();
    set_mode(fed::Mode::Single, "back to the local database");
    return true;
}
