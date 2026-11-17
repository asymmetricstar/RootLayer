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
#include "net/signaling.h"
#include "ca/ca.h"
#include "core/log.h"
#include "core/guard.h"
#include "core/limits.h"
#include "federation/federation.h"
#include "service/winservice.h"

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

static int run_server() {
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
    startup_begin(5, "Tunnel adapter (Wintun), gateway " + server_virtual_ip() +
                         ", firewall and NAT");
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

    startup_begin(8, "Starting relay, DNS, federation and session workers");
    // Federation: peering listener + data socket, and the link to the primary
    // when server.ini carries `link=<ip>`. A failure here only disables the
    // server-to-server paths; the local network keeps working.
    fed::start();
    std::thread(relay_thread).detach();
    // DNS name server for *.p2p (UDP + TCP 53) - answers from domain.db.
    // TCP is what a resolver falls back to when a UDP answer is truncated.
    if (name_service) {
        std::thread(dns_thread).detach();
        std::thread(dns_tcp_thread).detach();
    }
    // Shield housekeeping: rolls the load window, adapts the packet budget and
    // writes the periodic GUARD line for as long as the server runs.
    std::thread([] {
        while (relay_running) {
            guard::tick();
            Sleep(1000);
        }
    }).detach();
    server_ready = true;
    startup_ok();

    srvlog::section("Server ready");
    {
        double up = 0.0;
        double down = 0.0;
        limits::defaults(up, down);
        auto kbps = [](double bytes_per_sec) {
            return bytes_per_sec > 0.0
                       ? std::to_string((long long)(bytes_per_sec * 8.0 / 1000.0)) + " kbit/s"
                       : std::string("unlimited");
        };
        srvlog::item("Client band", "up " + kbps(up) + ", down " + kbps(down));
    }
    srvlog::item("Signaling", "TCP " + std::to_string(signaling_port));
    srvlog::item("Relay", "UDP " + std::to_string(relay_port));
    srvlog::item("Network", ip_to_string(virtual_ip_network) + "/" +
                                 std::to_string(virtual_ip_prefix_len) + " (" +
                                 ip_to_string(virtual_ip_mask) + ")");
    srvlog::item("Gateway", server_virtual_ip());
    if (virtual_ip_first_client <= virtual_ip_last) {
        srvlog::item("Client pool", ip_to_string(virtual_ip_first_client) + " - " +
                                        ip_to_string(virtual_ip_last) + " (" +
                                        std::to_string(virtual_ip_last -
                                                       virtual_ip_first_client + 1) +
                                        " addresses)");
    } else {
        srvlog::item("Client pool", "empty");
    }
    if (name_service) {
        std::string dns = "UDP+TCP 53";
        for (const auto& suffix : arpa_suffixes) {
            dns += "  *." + suffix;
        }
        srvlog::item("DNS", dns);
    } else {
        srvlog::item("DNS", "disabled");
    }
    srvlog::item("Federation", fed::status_tokens());
    srvlog::item("Certificate", ca::status());
    srvlog::item("Write buffer", db_write_stats() + " | " + arpa_write_stats());
    srvlog::item("Shield", guard::stats());
    {
        const guard::Settings limits = guard::settings();
        srvlog::item("Shield limits",
                     "budget " + std::to_string(limits.min_pps) + "-" +
                         std::to_string(limits.max_budget_pps) + " pps, per sender " +
                         std::to_string(limits.per_ip_pps) + " pps, " +
                         std::to_string(limits.connect_limit) + " connects/" +
                         std::to_string(limits.connect_window_sec) + "s, " +
                         std::to_string(limits.source_table) + " sources kept " +
                         std::to_string(limits.source_idle_sec) + "s");
    }

    if (gateway_ready) {
        std::cout << "\n\xE2\x9C\x85 Ready Server" << std::endl;
    } else {
        std::cout << "\n\xE2\x9A\xA0\xEF\xB8\x8F Ready Server (relay only): " << gateway_note
                  << std::endl;
    }

    srvlog::section("Client events");
    srvlog::events_header();
    std::cout << std::flush;

    // Control plane: one poll loop owns every connection, so each client costs
    // a buffer plus a poll entry instead of a thread. A slow or half-open peer
    // can only stall its own connection. Returns when the server stops.
    signaling_run(listen_sock);

    fed::stop();
    relay_running = false;
    closesocket(listen_sock);
    closesocket(relay_sock);
    WSACleanup();
    return 0;
}

// --- Windows service ---------------------------------------------------------
// "server.exe --service start|stop|status" installs/removes the automatic-start
// service; the SCM itself starts the program with "--service run" and runs the
// normal body below as LocalSystem.
static void service_on_stop() {
    // The signaling loop is inside WSAPoll(), so a stop cannot unwind it from
    // here. The pending writes are flushed synchronously and the handler ends
    // the process right after.
    flush_all_databases();
}

static winservice::Config service_config() {
    winservice::Config config;
    config.name = "RootLayerServer";
    config.display_name = "RootLayer Server";
    config.description =
        "RootLayer virtual LAN gateway, relay, DNS name server and certificate authority.";
    config.run_app = run_server;
    config.on_stop = service_on_stop;
    return config;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    if (winservice::requested()) {
        return winservice::handle(service_config());
    }
    return run_server();
}
