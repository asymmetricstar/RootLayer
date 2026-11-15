// server/net/signaling.cpp - non-blocking control plane.
//
// One thread, one WSAPoll() set: accept, read, write and timeouts for every
// signaling connection. The request itself is processed by handle_request()
// (net/control.cpp), which never touches a socket, so a slow or half-open peer
// can only ever stall its own connection - never the accept loop.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/utils.h"
#include "session/session.h"
#include "net/net.h"
#include "net/signaling.h"
#include "core/guard.h"

#include <algorithm>
#include <unordered_map>

namespace {

// A request without a newline is treated as complete once the client has been
// silent for this long (certificate payloads are not line-terminated).
const unsigned long long kRequestSettleMs = 250;
const unsigned long long kRequestTimeoutMs = 10000;
const unsigned long long kSessionTimeoutMs = 60000;  // keepalive every 5 s
const size_t kMaxRequestBytes = 1u << 20;
const size_t kReadChunk = 8192;

struct Conn {
    SOCKET sock = INVALID_SOCKET;
    sockaddr_in peer;
    std::string in;
    std::string out;
    size_t sent = 0;                  // bytes of `out` already written
    unsigned long long deadline = 0;  // absolute GetTickCount64 deadline
    unsigned long long last_rx = 0;
    bool settle_pending = false;      // request waiting for the settle timer
    bool closing = false;             // close once `out` drains
    bool session_phase = false;
    std::shared_ptr<Session> session;
};

void set_nonblocking(SOCKET sock) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
}

// Idempotent: releases the guard slot, the session and the socket exactly once.
void close_conn(const std::shared_ptr<Conn>& conn) {
    if (!conn || conn->sock == INVALID_SOCKET) {
        return;
    }
    closesocket(conn->sock);
    conn->sock = INVALID_SOCKET;
    if (conn->session) {
        release_session(conn->session);
        conn->session.reset();
    }
    guard::leave_connection();
    conn->in.clear();
    conn->out.clear();
    conn->sent = 0;
    conn->closing = true;
}

void queue_line(const std::shared_ptr<Conn>& conn, const std::string& line) {
    conn->out += line;
    conn->out += "\n";
}

// Runs the finished request through the pure handler and decides what the
// connection does next: answer and close, or answer and keep the session.
void process_request(const std::shared_ptr<Conn>& conn) {
    conn->settle_pending = false;

    std::string request = conn->in;
    conn->in.clear();
    const size_t newline = request.find('\n');
    if (newline != std::string::npos) {
        request.resize(newline);
    }
    if (!request.empty() && request.back() == '\r') {
        request.pop_back();
    }

    bool closes = true;
    std::shared_ptr<Session> session;
    const std::string response = handle_request(request, conn->peer, closes, session);
    if (!response.empty()) {
        queue_line(conn, response);
    }

    if (!closes && session) {
        conn->session = session;
        conn->session_phase = true;
        // The takeover path closes stale sessions through this handle.
        session->sock = conn->sock;
        conn->deadline = GetTickCount64() + kSessionTimeoutMs;
        return;
    }
    conn->closing = true;
}

void on_readable(const std::shared_ptr<Conn>& conn, unsigned long long now) {
    char buffer[kReadChunk];
    for (;;) {
        const int received = recv(conn->sock, buffer, (int)sizeof(buffer), 0);
        if (received > 0) {
            conn->last_rx = now;
            if (conn->session_phase) {
                // Keepalive. "PING STATE" asks for the current gateway/TLD
                // state, so a client can follow a moved gateway without
                // dropping the session; a plain "PING" only refreshes the timer.
                std::string text(buffer, (size_t)received);
                if (text.find("STATE") != std::string::npos) {
                    queue_line(conn, "STATE" +
                                         server_network_state_tokens(conn->session.get()));
                }
                conn->deadline = now + kSessionTimeoutMs;
                if (received < (int)sizeof(buffer)) {
                    return;
                }
                continue;
            }

            conn->in.append(buffer, (size_t)received);
            if (conn->in.size() > kMaxRequestBytes ||
                conn->in.find('\n') != std::string::npos) {
                process_request(conn);
                return;
            }
            conn->settle_pending = true;
            if (received < (int)sizeof(buffer)) {
                return;  // wait for the settle timer or the rest of the payload
            }
            continue;
        }
        if (received == 0) {
            close_conn(conn);  // peer closed
            return;
        }
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            return;
        }
        if (error == WSAEINTR) {
            continue;
        }
        close_conn(conn);
        return;
    }
}

void on_writable(const std::shared_ptr<Conn>& conn) {
    while (conn->sent < conn->out.size()) {
        const int chunk =
            send(conn->sock, conn->out.data() + conn->sent,
                 (int)std::min<size_t>(conn->out.size() - conn->sent, 16384), 0);
        if (chunk > 0) {
            conn->sent += (size_t)chunk;
            continue;
        }
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            return;
        }
        if (error == WSAEINTR) {
            continue;
        }
        close_conn(conn);
        return;
    }
    conn->out.clear();
    conn->sent = 0;
    if (conn->closing) {
        close_conn(conn);
    }
}

void accept_pending(SOCKET listen_sock, std::vector<std::shared_ptr<Conn>>& connections,
                    unsigned long long now) {
    for (;;) {
        sockaddr_in address;
        int length = sizeof(address);
        const SOCKET sock = accept(listen_sock, (sockaddr*)&address, &length);
        if (sock == INVALID_SOCKET) {
            return;  // drained (WSAEWOULDBLOCK) or a transient accept error
        }

        // Shield: a connection flood must not spawn unlimited work. Refused
        // peers get a BUSY line and retry like any other failed attempt.
        if (!guard::enter_connection((uint32_t)ntohl(address.sin_addr.s_addr))) {
            const char busy[] = "BUSY\n";
            send(sock, busy, (int)strlen(busy), 0);
            // Half-close before closesocket: a plain close with data still in
            // flight sends RST, which can discard the BUSY line.
            shutdown(sock, SD_SEND);
            closesocket(sock);
            continue;
        }

        set_nonblocking(sock);
        auto conn = std::make_shared<Conn>();
        conn->sock = sock;
        conn->peer = address;
        conn->deadline = now + kRequestTimeoutMs;
        conn->last_rx = now;
        connections.push_back(conn);
    }
}

}  // namespace

void signaling_run(SOCKET listen_sock) {
    set_nonblocking(listen_sock);

    std::vector<std::shared_ptr<Conn>> connections;
    std::vector<WSAPOLLFD> poll_set;

    while (relay_running) {
        poll_set.clear();
        WSAPOLLFD listener;
        listener.fd = listen_sock;
        listener.events = POLLRDNORM;
        listener.revents = 0;
        poll_set.push_back(listener);

        for (const auto& conn : connections) {
            WSAPOLLFD entry;
            entry.fd = conn->sock;
            entry.events = POLLRDNORM;
            if (conn->sent < conn->out.size()) {
                entry.events |= POLLWRNORM;
            }
            entry.revents = 0;
            poll_set.push_back(entry);
        }

        const int ready = WSAPoll(poll_set.data(), (ULONG)poll_set.size(), 500);
        if (ready < 0) {
            Sleep(20);
            continue;
        }

        const unsigned long long now = GetTickCount64();

        if (poll_set[0].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
            // Appends only, so the indices below stay valid for this pass.
            accept_pending(listen_sock, connections, now);
        }

        const size_t watched = poll_set.size();
        for (size_t i = 1; i < watched; ++i) {
            const std::shared_ptr<Conn>& conn = connections[i - 1];
            if (!conn || conn->sock == INVALID_SOCKET) {
                continue;
            }
            const short events = poll_set[i].revents;
            if (events & (POLLRDNORM | POLLIN)) {
                on_readable(conn, now);
            }
            if (conn->sock == INVALID_SOCKET) {
                continue;
            }
            if ((events & (POLLWRNORM | POLLOUT)) && conn->sent < conn->out.size()) {
                on_writable(conn);
            }
            if (conn->sock == INVALID_SOCKET) {
                continue;
            }
            if (events & (POLLERR | POLLHUP | POLLNVAL)) {
                close_conn(conn);
                continue;
            }
            if (now >= conn->deadline) {
                close_conn(conn);  // request or session timed out
                continue;
            }
            if (conn->settle_pending && now - conn->last_rx >= kRequestSettleMs) {
                process_request(conn);
            }
        }

        // Drain the finished connections between passes.
        connections.erase(std::remove_if(connections.begin(), connections.end(),
                                         [](const std::shared_ptr<Conn>& conn) {
                                             return conn->sock == INVALID_SOCKET;
                                         }),
                          connections.end());
    }

    for (const auto& conn : connections) {
        close_conn(conn);
    }
}
