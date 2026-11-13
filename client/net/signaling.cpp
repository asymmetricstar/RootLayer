// client/net/signaling.cpp - control channel, relay address, UDP bind.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "net/signaling.h"
#include "net/auto_secure.h"
#include "tap/tap.h"

// Read one '\n' terminated line. Partial data is kept in `line` when the read
// times out, so a timeout in the middle of a line does not lose bytes.
ReadResult read_line_socket(SOCKET sock, std::string& line) {
    char ch;
    for (;;) {
        int len = recv(sock, &ch, 1, 0);
        if (len == 1) {
            if (ch == '\n') {
                return READ_OK;
            }
            line.push_back(ch);
            continue;
        }
        if (len == 0) {
            return READ_FAILED;
        }
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT) {
            return READ_TIMEOUT;
        }
        return READ_FAILED;
    }
}

// Every frame travels through the server relay, so the tunnel destination is
// the signaling server itself on the relay port. The server floods the frame to
// all other members, which makes 10.0.0.0/24 one shared segment.

// Random 16-hex id generated once per process. Sent with every CLIENT_REQ so
// the server can recognize a reconnect of this very process and refuse a
// different process that claims the same identity.
static std::string process_instance_id() {
    static const std::string id = [] {
        unsigned long long mix = (unsigned long long)GetTickCount64() ^
                                 ((unsigned long long)(uintptr_t)&mix << 32) ^
                                 ((unsigned long long)GetCurrentProcessId() << 16);
        // xorshift so the two halves are not trivially predictable.
        mix ^= mix >> 33; mix *= 0xff51afd7ed558ccdULL;
        mix ^= mix >> 29; mix *= 0xc4ceb9fe1a85ec53ULL;
        mix ^= mix >> 32;
        char buf[17];
        snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)mix);
        return std::string(buf, 16);
    }();
    return id;
}

bool update_relay_address() {
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* resolved = NULL;
    int rc = getaddrinfo(signaling_server_ip.c_str(), std::to_string(relay_port).c_str(), &hints, &resolved);
    if (rc != 0 || resolved == NULL) {
        json_event("error", json_string_field("code", "relay_address_invalid"));
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(tunnel_mutex);
        peer_addr = *(sockaddr_in*)resolved->ai_addr;
        peer_valid = true;
        // Keep the fallback in sync: after a disconnect peer_valid is cleared
        // and tap_to_udp falls back to this address; it must be the relay
        // port learned from the server, not the initial default.
        fallback_target = peer_addr;
        fallback_target_valid = true;
    }

    // The relay only forwards to members whose UDP endpoint it knows. This
    // probe registers us right away instead of waiting for the first real
    // frame, so the other side is reachable immediately after connecting.
    // The last octet of our virtual IP is appended so the server can match
    // the packet to us even when NAT rewrites the UDP port.
    char registration[7] = "\x01HELLO";
    int reg_len = 6;
    size_t last_dot = virtual_ip.find_last_of('.');
    if (last_dot != std::string::npos) {
        int octet = std::atoi(virtual_ip.c_str() + last_dot + 1);
        if (octet >= 0 && octet <= 255) {
            registration[6] = (char)octet;
            reg_len = 7;
        }
    }
    sendto(udp_sock, registration, reg_len, 0,
           (sockaddr*)&peer_addr, sizeof(peer_addr));

    freeaddrinfo(resolved);

    return true;
}

// One signaling attempt. The connection is kept open as the control channel
// when a peer is found.
// Splits the comma separated TLD list the server reports and hands it to the
// resolver rule set. An empty list means "no tunnel TLDs": every rule is
// removed, so nothing from an earlier connection can survive.
static void apply_tld_list(const std::string& tlds) {
    std::vector<std::string> suffixes;
    size_t start = 0;
    while (start <= tlds.size()) {
        size_t comma = tlds.find(',', start);
        if (comma == std::string::npos) comma = tlds.size();
        std::string suffix = trim(tlds.substr(start, comma - start));
        if (!suffix.empty()) suffixes.push_back(suffix);
        if (comma >= tlds.size()) break;
        start = comma + 1;
    }
    set_tunnel_dns_namespaces(suffixes);
}

// Applies a "STATE GATEWAY:.. MASK:.. TLD:.." line the server pushes on the
// control channel. The server is authoritative: a missing GATEWAY means it has
// no tunnel gateway right now, which drops the client's resolver rules.
static void apply_control_state(const std::string& line) {
    gateway_ip = token_value(line, "GATEWAY");
    const std::string mask = token_value(line, "MASK");
    if (!mask.empty()) {
        tap_mask = mask;
    }
    apply_tld_list(token_value(line, "TLD"));
}

bool request_peer() {
    if (g_shutdown) {
        return false;
    }

    std::string port_str = std::to_string(signaling_server_port);

    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = NULL;
    int rc = getaddrinfo(signaling_server_ip.c_str(), port_str.c_str(), &hints, &resolved);
    if (rc != 0 || resolved == NULL) {
        return false;
    }

    SOCKET sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(resolved);
        return false;
    }

    // Short timeout so the client stays responsive to the tray menu while it
    // waits for a peer.
    DWORD timeout_ms = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    if (connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(resolved);
        return false;
    }
    freeaddrinfo(resolved);

    // The address is assigned by the server; nothing is taken from a
    // configuration file. On the first connect it is still empty, which is
    // fine: the token is only a hint for the server's endpoint learning.
    std::string request = "CLIENT_REQ:" + virtual_ip + " UDP_PORT:" + std::to_string(udp_tunnel_port);
    if (static_enabled && !client_identity.empty()) {
        request += " IDENTITY:" + client_identity;
    }
    // Random id for this process: lets the server tell "the same client
    // reconnecting" (takeover) apart from "a second client.exe with the same
    // identity" (refused).
    request += " INSTANCE:" + process_instance_id();
    request += "\n";
    if (send(sock, request.c_str(), (int)request.size(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    std::string response;
    for (;;) {
        ReadResult result = read_line_socket(sock, response);
        if (result == READ_TIMEOUT) {
            if (g_shutdown) {
                closesocket(sock);
                return false;
            }
            continue;
        }
        if (result == READ_FAILED) {
            closesocket(sock);
            return false;
        }
        break;
    }

    response = trim(response);

    // Another live client process already holds this identity on the server
    // (double launch that slipped past the local mutex, or a second machine
    // using the same identity). Do not take the session over - log it and
    // keep retrying; the server releases the slot when the other one leaves.
    if (response == "ALREADY_CONNECTED") {
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::cerr << "This identity is already connected from another client instance "
                      << "(ALREADY_CONNECTED); waiting for it to disconnect."
                      << std::endl;
        }
        closesocket(sock);
        json_event("error", "\"code\":\"already_connected\"");
        return false;
    }

    std::string assigned_ip = token_value(response, "YOUR_IP");
    int relay = token_int(response, "RELAY_PORT", 0);
    gateway_ip = token_value(response, "GATEWAY");
    tap_mask = token_value(response, "MASK");

    // Virtual TLDs this server is authoritative for (TLD:p2p,abc). The list is
    // never assumed: it is taken from the server, and an empty answer means the
    // client must not keep any tunnel DNS rule.
    apply_tld_list(token_value(response, "TLD"));

    // CA fingerprint of the server we are talking to. When it differs from the
    // CA we enrolled against (server restarted, new in-memory CA), the cached
    // certificate material is dropped and the next bootstrap re-enrolls.
    std::string server_ca = token_value(response, "CAFP");
    if (!server_ca.empty()) {
        auto_secure_on_server_ca(server_ca);
    }
    {
        int members = token_int(response, "MEMBERS", 0);
        if (members > 0) {
            peer_count.store(members);
        }
    }
    if (tap_mask.empty()) tap_mask = "255.255.255.0";

    if (assigned_ip.empty()) {
        closesocket(sock);
        return false;
    }
    if (relay > 0 && relay <= 65535) {
        relay_port = (uint16_t)relay;
    }

    virtual_ip = assigned_ip;

    // The control channel is kept alive with a PING every few seconds, which
    // also lets the server notice a silently vanished peer.
    DWORD control_timeout_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&control_timeout_ms, sizeof(control_timeout_ms));

    control_sock = sock;
    return true;
}

// Keeps the control channel alive with PING messages and reports when the
// server tells us the peer is gone.
void control_thread_fn() {
    for (;;) {
        std::string line;
        ReadResult result = read_line_socket(control_sock, line);

        if (result == READ_TIMEOUT) {
            // "PING STATE" keeps the session alive and asks for the server's
            // current gateway/TLD state in the same request. A server that does
            // not know the extra word answers nothing, which is the old
            // behavior.
            if (send(control_sock, "PING STATE\n", 11, 0) == SOCKET_ERROR) {
                break;
            }
            continue;
        }

        if (result == READ_FAILED) {
            break;
        }

        line = trim(line);
        if (line.rfind("STATE", 0) == 0) {
            // The server reports its network state: let the tunnel loop apply
            // it (adapter settings and resolver rules) without reconnecting.
            apply_control_state(line);
            {
                std::lock_guard<std::mutex> lock(control_mutex);
                server_config_dirty = true;
            }
            control_cv.notify_all();
            continue;
        }

        // Any other line means the server is tearing the control channel down.
        if (!line.empty()) {
            break;
        }
    }

    std::lock_guard<std::mutex> lock(control_mutex);
    peer_lost = true;
    control_cv.notify_all();
}

bool bind_udp_socket() {
    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        json_event("error", "\"code\":\"udp_socket_failed\",\"win_error\":" + std::to_string(WSAGetLastError()));
        return false;
    }

    sockaddr_in local_addr;
    ZeroMemory(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(udp_tunnel_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    // Allow rebinding quickly after a previous instance exits (SO_REUSEADDR).
    BOOL reuse = TRUE;
    setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    if (bind(udp_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        json_event("error", "\"code\":\"udp_bind_failed\",\"port\":" + std::to_string(udp_tunnel_port) + ",\"win_error\":" + std::to_string(WSAGetLastError()));
        closesocket(udp_sock);
        udp_sock = INVALID_SOCKET;
        return false;
    }

    return true;
}
