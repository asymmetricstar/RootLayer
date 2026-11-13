// server/main.cpp - entry point: numbered startup sequence + accept loop.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "db/store.h"
#include "db/write_queue.h"
#include "arpa/arpa.h"
#include "dns/dns.h"
#include "session/session.h"
#include "gateway/gateway.h"
#include "net/net.h"
#include "ca/ca.h"

const int kStartupSteps = 8;

void startup_begin(int step, const std::string& label) {
    std::cout << "[" << step << "/" << kStartupSteps << "] " << label << " ... " << std::flush;
}

void startup_ok() { std::cout << "OK" << std::endl; }

int startup_fail(const std::string& label, const std::string& reason) {
    std::cout << "FAILED" << std::endl;
    std::cerr << "\xE2\x9D\x8C Server not ready: " << label << " - " << reason << std::endl;
    return 1;
}

// Ctrl+C / console close / logoff: push the write-behind buffers to disk
// before the process goes away. The default handler terminates afterwards.
static BOOL WINAPI on_console_control(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT ||
        type == CTRL_SHUTDOWN_EVENT) {
        flush_all_databases();
    }
    return FALSE;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "RootLayer Server" << std::endl;
    SetConsoleCtrlHandler(on_console_control, TRUE);
    // Set console window title for Windows
    ::SetConsoleTitleA("Gateway Server");
    // Configuration first, then the numbered sequence: the printed settings
    // above stay readable instead of being squeezed between step markers.
    load_server_config_from_ini("server.ini");

    startup_begin(1, "Identity database");
    if (!db_open(get_exe_dir_server())) {
        return startup_fail("Identity database", "could not be opened");
    }
    db_prune_stale_rows();
    db_start_write_buffer();
    startup_ok();

    startup_begin(2, "TLD Name Server");
    bool name_service = arpa_open(get_exe_dir_server());
    if (name_service) {
        arpa_reserve_root(server_virtual_ip(), 60);
        arpa_start_write_buffer();
        // The records are never enumerated: a deployment can hold hundreds of
        // thousands of domains and one line each would flood the console.
        std::cout << "\n      " << arpa_domain_count() << " domain registered  " << std::flush;
    }
    std::cout << (name_service ? "OK" : "OK (name service disabled)") << std::endl;

    // Certificate Authority: generated once, kept in process memory only.
    startup_begin(3, "Certificate Authority");
    if (!ca::ensure_ca(get_exe_dir_server())) {
        return startup_fail("Certificate Authority", "could not create the certificate authority");
    }
    startup_ok();

    startup_begin(4, "Network stack (Winsock)");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return startup_fail("Winsock", "WSAStartup failed");
    }
    startup_ok();

    // Network first: adapter, gateway address, MTU, firewall and NAT.
    startup_begin(5, "TAP adapter, gateway " + server_virtual_ip() + ", firewall and NAT");
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

    startup_begin(6, "Relay socket (UDP " + std::to_string(relay_port) + ")");
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
    startup_begin(7, "Signaling listener (TCP " + std::to_string(signaling_port) + ")");
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

    startup_begin(8, "Starting relay, DNS and session workers");
    std::thread(relay_thread).detach();
    // DNS name server for *.p2p (UDP + TCP 53) - answers from domain.db.
    // TCP is what a resolver falls back to when a UDP answer is truncated.
    if (name_service) {
        std::thread(dns_thread).detach();
        std::thread(dns_tcp_thread).detach();
    }
    server_ready = true;
    startup_ok();

    std::cout << "      Signaling: TCP " << signaling_port << "   Relay: UDP " << relay_port << std::endl;
    if (name_service) {
        std::cout << "      DNS: UDP+TCP 53 (*.";
        for (const auto& suf : arpa_suffixes) std::cout << " " << suf;
        std::cout << ")" << std::endl;
    }
    std::cout << "      Gateway " << server_virtual_ip() << "   Pool from "
              << virtual_ip_prefix << (virtual_ip_start_octet + 1) << std::endl;
    std::cout << "      Certificate: " << ca::status() << std::endl;
    std::cout << "      Write buffer: " << db_write_stats() << " | " << arpa_write_stats() << std::endl;
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
