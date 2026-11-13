// console/net/admin_client.cpp
#include "net/admin_client.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>

#include "core/text.h"

namespace {

// Winsock is process wide; the console makes one request per run, so starting
// it on first use keeps main() free of plumbing.
bool ensure_winsock() {
    static const bool started = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return started;
}

}  // namespace

AdminClient::AdminClient(const ConsoleConfig& config) : config_(config) {}

AdminResult AdminClient::request(const std::string& line) {
    AdminResult result;

    if (!ensure_winsock()) {
        result.transport_failed = true;
        result.error = "Winsock could not be initialised";
        return result;
    }

    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = NULL;
    const std::string port = std::to_string(config_.port);
    if (getaddrinfo(config_.server.c_str(), port.c_str(), &hints, &resolved) != 0 || resolved == NULL) {
        result.transport_failed = true;
        result.error = "cannot resolve " + config_.server;
        return result;
    }

    SOCKET sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(resolved);
        result.transport_failed = true;
        result.error = "socket() failed";
        return result;
    }

    const DWORD timeout = (DWORD)config_.timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(resolved);
        closesocket(sock);
        result.transport_failed = true;
        result.error = "cannot connect to " + config_.server + ":" + port +
                       " (is the server running?)";
        return result;
    }
    freeaddrinfo(resolved);

    std::string payload = line;
    if (payload.empty() || payload.back() != '\n') {
        payload.push_back('\n');
    }
    if (send(sock, payload.c_str(), (int)payload.size(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        result.transport_failed = true;
        result.error = "the request could not be sent";
        return result;
    }

    char buffer[4096];
    for (;;) {
        const int received = recv(sock, buffer, (int)sizeof(buffer), 0);
        if (received > 0) {
            result.response.append(buffer, (size_t)received);
            if (result.response.size() > (1u << 20)) break;
            continue;
        }
        break;
    }
    closesocket(sock);

    if (result.response.empty()) {
        result.transport_failed = true;
        result.error = "the server closed the connection without an answer";
        return result;
    }
    return result;
}

AdminResult AdminClient::call(const std::string& line) {
    AdminResult result = request(line);
    if (result.transport_failed) {
        return result;
    }

    if (result.response.rfind("ADMIN_ERR:", 0) == 0) {
        result.ok = false;
        result.error = trim(result.response.substr(10));
        return result;
    }

    result.ok = result.response.rfind("ADMIN_OK", 0) == 0;
    if (!result.ok) {
        result.error = "unexpected answer: " + trim(result.response);
    }
    return result;
}
