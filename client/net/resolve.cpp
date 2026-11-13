// client/net/resolve.cpp - one-shot ARPA resolution (--resolve) and the zone
// health probe behind the panel's "Zone Network" pill.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "net/signaling.h"
#include "net/resolve.h"
#include "ui/shared_state.h"

// One-shot ARPA resolution: connect to the root (gateway, 10.0.0.1), ask for a
// name, print a single JSON line and exit. Works in headless mode.
int run_arpa_resolve(const std::string& name) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        json_event("error", "\"code\":\"winsock_init_failed\"");
        return 1;
    }

    // The root server address comes from the signaling response; nothing is
    // assumed when it is missing.
    std::string resolver = gateway_ip;
    if (resolver.empty()) {
        json_event("arpa_resolve", json_string_field("name", name) +
                                        ",\"ok\":false,\"code\":\"gateway_unknown\"");
        WSACleanup();
        return 1;
    }

    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = NULL;
    int rc = getaddrinfo(resolver.c_str(), std::to_string(signaling_server_port).c_str(), &hints, &resolved);
    if (rc != 0 || resolved == NULL) {
        json_event("arpa_resolve", json_string_field("name", name) + ",\"ok\":false,\"code\":\"resolver_unreachable\"");
        WSACleanup();
        return 1;
    }

    SOCKET sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(resolved);
        json_event("arpa_resolve", json_string_field("name", name) + ",\"ok\":false,\"code\":\"socket_failed\"");
        WSACleanup();
        return 1;
    }

    DWORD timeout_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    if (connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(resolved);
        json_event("arpa_resolve", json_string_field("name", name) + ",\"ok\":false,\"code\":\"connect_failed\"");
        WSACleanup();
        return 1;
    }
    freeaddrinfo(resolved);

    std::string request = "ARPA_QUERY:" + name + "\n";
    if (send(sock, request.c_str(), (int)request.size(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        json_event("arpa_resolve", json_string_field("name", name) + ",\"ok\":false,\"code\":\"send_failed\"");
        WSACleanup();
        return 1;
    }

    std::string response;
    for (int attempt = 0; attempt < 5; ++attempt) {
        ReadResult result = read_line_socket(sock, response);
        if (result == READ_TIMEOUT) {
            if (g_shutdown) break;
            continue;
        }
        if (result == READ_FAILED) break;
        break;
    }
    closesocket(sock);

    response = trim(response);
    std::string ip = token_value(response, "ADDR");
    if (!ip.empty()) {
        std::string resolved_name = token_value(response, "ARPA_IP");
        if (resolved_name.empty()) resolved_name = name;
        json_event("arpa_resolve", json_string_field("name", resolved_name) + "," +
                   json_string_field("ip", ip) + ",\"ok\":true");
        WSACleanup();
        return 0;
    }

    std::string code = token_value(response, "CODE");
    if (code.empty()) code = "no_response";
    json_event("arpa_resolve", json_string_field("name", name) + ",\"ok\":false," +
               json_string_field("code", code));
    WSACleanup();
    return 1;
}

// ------------------------------------------------------------ zone probe
//
// The root server answers "ARPA_QUERY:root" with "ARPA_IP:... ADDR:<ip>"
// when its domain zone system (root reservation + name service) is healthy.
// Anything else - unreachable, still starting, NXDOMAIN - counts as down.
// The probe talks to the signaling address directly, so it reports on the
// server's zone system rather than on this client's tunnel state.
static bool zone_probe_once() {
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = NULL;
    if (getaddrinfo(signaling_server_ip.c_str(),
                    std::to_string(signaling_server_port).c_str(),
                    &hints, &resolved) != 0 || resolved == NULL) {
        return false;
    }

    SOCKET sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(resolved);
        return false;
    }

    DWORD timeout_ms = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    bool ok = false;
    if (connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen) != SOCKET_ERROR) {
        std::string request = "ARPA_QUERY:root\n";
        if (send(sock, request.c_str(), (int)request.size(), 0) != SOCKET_ERROR) {
            std::string response;
            for (int attempt = 0; attempt < 2 && !g_shutdown; ++attempt) {
                ReadResult result = read_line_socket(sock, response);
                if (result == READ_TIMEOUT) continue;  // partial line is kept
                break;
            }
            ok = !token_value(trim(response), "ADDR").empty();
        }
    }

    closesocket(sock);
    freeaddrinfo(resolved);
    return ok;
}

void zone_worker_thread() {
    panel_zone_status.store(0);  // gray: checking
    for (;;) {
        if (g_shutdown) break;
        panel_zone_status.store(zone_probe_once() ? 1 : 2);
        sleep_or_shutdown(15000);
    }
}
