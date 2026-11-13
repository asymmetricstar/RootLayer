// client/client.cpp - entry point (main/WinMain) and the tunnel loop.
// Everything else lives in core/, tap/, net/ and ui/ subfolders.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "tap/tap.h"
#include "net/signaling.h"
#include "net/tunnel.h"
#include "net/resolve.h"
#include "net/auto_secure.h"
#include "ui/tray.h"
#include "ui/panel.h"
#include "ui/ui_qt.h"
#include "ui/shared_state.h"

// Libraries linked via command line: -lws2_32 -liphlpapi -lsetupapi
// -lnetapi32 -lshell32 -ladvapi32 -lgdiplus -lgdi32 -lole32

// The tunnel: TAP setup, relay threads and the reconnect loop. Runs in the
// main thread for headless/managed mode and in a worker thread when the Qt
// panel owns the GUI.
static int run_tunnel();

// Single-instance guard. A second client process would open a second TAP
// session and connect to the server a second time with the same identity, so
// only one client.exe may exist per machine. The mutex is acquired without
// the "already exists" ownership flag and kept open for the whole process
// lifetime - the kernel drops it automatically on exit, which is what makes
// "closed the first one, launch again" work without any cleanup code.
// --resolve is exempt (checked by the caller) so diagnose tools keep working
// while a client is running.
static HANDLE g_single_instance_mutex = NULL;

static bool acquire_single_instance() {
    // Global\ so the guard covers every session on the machine; fall back to
    // Local\ when the Global namespace cannot be created (no privilege).
    g_single_instance_mutex = CreateMutexA(NULL, FALSE, "Global\\RootLayer.Client.SingleInstance");
    if (g_single_instance_mutex == NULL) {
        g_single_instance_mutex = CreateMutexA(NULL, FALSE, "Local\\RootLayer.Client.SingleInstance");
    }
    if (g_single_instance_mutex == NULL) {
        // Cannot enforce the guard - better to run than to refuse startup.
        return true;
    }
    return GetLastError() != ERROR_ALREADY_EXISTS;
}

int main() {
    headless_mode = has_headless_argument();
    if (headless_mode) {
        attach_parent_console();
    }

    load_config_from_ini("client.ini");
    ensure_client_identity(get_exe_dir() + "\\client.ini");

    if (!resolve_name.empty()) {
        if (headless_mode) {
            attach_parent_console();
        }
        return run_arpa_resolve(resolve_name);
    }

    // One client per machine: a second launch would open a second TAP
    // session and connect to the server twice with the same identity.
    // --resolve above is exempt so diagnose tools work while a client runs.
    if (!acquire_single_instance()) {
        if (headless_mode) {
            json_event("error", "\"code\":\"already_running\"");
        } else {
            MessageBoxA(NULL,
                        "RootLayer is already running.\n"
                        "Use the tray icon or the panel of the running instance.",
                        "RootLayer", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        }
        return 1;
    }

    json_event("start", json_string_field("signaling", signaling_server_ip + ":" + std::to_string(signaling_server_port)) + "," +
                        json_number_field("udp_port", udp_tunnel_port) + "," +
                        json_string_field("mode", headless_mode ? "headless" : "gui"));

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        json_event("error", "\"code\":\"winsock_init_failed\"");
        return 1;
    }

    // Fully automatic, headless PKI bootstrap: fetch/trust CA and enroll a
    // client certificate (no user interaction). Best-effort if server not ready.
    ensure_client_auto_security();

    if (!headless_mode) {
        // Qt requires the GUI on the main thread, so the tunnel gets a worker.
        g_qt_ui = true;
        std::thread tunnel_thread(run_tunnel);
        tunnel_thread.detach();
        return run_qt_ui();
    }

    return run_tunnel();
}

static int run_tunnel() {
    // GUI mode only: the tunnel thread measures the ping shown in the panel.
    // The Win32 tray window is only created when the Qt panel is not in charge.
    if (!headless_mode) {
        if (!g_qt_ui) {
            Gdiplus::GdiplusStartupInput gdiplus_input;
            if (Gdiplus::GdiplusStartup(&gdiplus_token, &gdiplus_input, NULL) != Gdiplus::Ok) {
                std::cerr << "GDI+ initialization failed; using default tray icons." << std::endl;
            }
            tray_set_state_utf8(false, "RootLayer - starting...");
            std::thread tray_thread(tray_thread_fn);
            tray_thread.detach();
        }
        std::thread(panel_worker_thread).detach();
        // Zone Network pill: probes the root server's domain zone system.
        std::thread(zone_worker_thread).detach();
    }

    // virtual_ip stays empty until the signaling server assigns one: no
    // address is assumed from a configuration file.

    // TAP adapter identification is the highest priority: the tunnel must not
    // start until one healthy adapter is guaranteed. This resets stale
    // detection, restarts an unhealthy node, or removes and reinstalls when
    // no usable adapter exists.
    if (!ensure_tap_adapter()) {
        WSACleanup();
        return 1;
    }

    std::string tap_name = get_tap_device_name();
    if (tap_name.empty()) {
        json_event("error", "\"code\":\"tap_missing\"");
        WSACleanup();
        return 1;
    }

    if (!open_tap_device(tap_name)) {
        // Open failed (stale GUID / ghost node): reset and re-ensure once.
        reset_tap_detection();
        if (!ensure_tap_adapter()) {
            WSACleanup();
            return 1;
        }
        tap_name = get_tap_device_name();
        if (tap_name.empty() || !open_tap_device(tap_name)) {
            WSACleanup();
            return 1;
        }
    }

    set_tap_media_status(true);

    if (!bind_udp_socket()) {
        CloseHandle(tap_device);
        WSACleanup();
        return 1;
    }

    // Fallback target: until the first peer packet arrives, send outbound TAP
    // frames to the relay (signaling IP : relay port) so the server learns this
    // client's UDP endpoint. THIS MUST BE relay_port (40001), not the local
    // tunnel port (50000) — the server never listens for relay frames on 50000.
    fallback_target.sin_family = AF_INET;
    fallback_target.sin_port = htons(relay_port);
    fallback_target.sin_addr.s_addr = inet_addr(signaling_server_ip.c_str());
    fallback_target_valid = true;

    std::thread tap_to_udp(tap_to_udp_thread);
    std::thread udp_to_tap(udp_to_tap_thread);

    // Traffic counters make a silent tunnel visible: frames leaving the adapter
    // and frames handed to it by the relay.
    std::thread([] {
        for (;;) {
            Sleep(5000);
            if (g_shutdown) {
                break;
            }
            json_event("stats", "\"from_tap\":" + std::to_string(frames_from_tap.load()) +
                                ",\"to_tap\":" + std::to_string(frames_to_tap.load()));
        }
    }).detach();

    // Reconnect loop: the tray icon follows the signaling connection, not a
    // peer. It turns online while the control channel to the server is open
    // and offline again as soon as that channel drops.
    for (;;) {
        if (g_shutdown) {
            break;
        }

        // Retry automatic enrollment/trust if it was not completed earlier.
        ensure_client_auto_security();

        tray_set_state_utf8(false, "Connecting to server... " + signaling_server_ip + ":" + std::to_string(signaling_server_port));
        json_event("waiting_server");
        while (!request_peer()) {
            if (g_shutdown) {
                break;
            }
            sleep_or_shutdown(3000);
        }
        if (g_shutdown) {
            break;
        }

        if (!update_relay_address()) {
            {
                std::lock_guard<std::mutex> lock(tunnel_mutex);
                peer_valid = false;
            }
            if (control_sock != INVALID_SOCKET) {
                closesocket(control_sock);
                control_sock = INVALID_SOCKET;
            }
            if (g_shutdown) {
                break;
            }
            sleep_or_shutdown(3000);
            continue;
        }

        // Ensure CA trust is applied once connectivity is available (headless).
        ensure_client_auto_security();

        // Applies what the server currently reports: TAP address/gateway and the
        // resolver rules. Called again when the server pushes a change over the
        // control channel, so neither of them needs a reconnect.
        auto apply_server_network_config = [&]() {
            if (virtual_ip != configured_ip || gateway_ip != configured_gateway || tap_mask != configured_mask) {
                if (is_admin()) {
                    // The gateway comes from the server only; without one the TAP
                    // gets its address but no gateway route.
                    std::string tap_gateway = gateway_ip;
                    if (configure_tap_adapter(virtual_ip, tap_gateway, tap_mask, tap_gateway)) {
                        configured_ip = virtual_ip;
                        configured_gateway = gateway_ip;
                        configured_mask = tap_mask;
                        ip_applied = true;
                        prepare_tap_adapter(get_tap_adapter_name());
                        // Bind the server's virtual TLDs to the server's gateway so
                        // the resolver asks the tunnel DNS server directly instead
                        // of timing out on the physical NIC's DNS server first.
                        apply_tunnel_dns_rules(gateway_ip);
                        if (!gateway_ip.empty()) {
                            json_event("gateway_set", json_string_field("gateway", gateway_ip));
                        }
                    } else {
                        ip_applied = false;
                    }
                } else {
                    // Without elevation netsh cannot touch the adapter: the address
                    // stays 169.254.x.x and every 10.0.0.x packet leaves through the
                    // physical NIC instead of the tunnel.
                    json_event("error", std::string("\"code\":\"admin_required\",") + json_string_field("ip", virtual_ip));
                    configured_ip = virtual_ip;
                    ip_applied = false;
                }
            }

            // A TLD list changed on the server has to reach the resolver even
            // when the assigned address and the gateway stayed the same.
            if (!tunnel_dns_rules_current(gateway_ip)) {
                apply_tunnel_dns_rules(gateway_ip);
            }
        };

        apply_server_network_config();

        {
            std::lock_guard<std::mutex> lock(control_mutex);
            peer_lost = false;
        }

        std::thread control(control_thread_fn);

        // The control channel is open, so the client is online from here on.
        // The TAP/IP configuration below does not change that state.
        tray_set_state_utf8(true, "Connected | IP: " + virtual_ip);
        panel_set_connected(true, virtual_ip);
        json_event("connected",
                   json_string_field("server", signaling_server_ip + ":" + std::to_string(signaling_server_port)) + "," +
                   json_string_field("local_ip", virtual_ip) + "," +
                   json_number_field("static", static_enabled));

        if (!ip_applied) {
            tray_set_state_utf8(true, "Connected | IP not applied (" + virtual_ip + ")");
            json_event("error", std::string("\"code\":\"ip_not_applied\",") + json_string_field("ip", virtual_ip));
        }

        for (;;) {
            std::unique_lock<std::mutex> lock(control_mutex);
            control_cv.wait(lock, [] { return peer_lost || server_config_dirty; });
            const bool lost = peer_lost;
            const bool dirty = server_config_dirty;
            server_config_dirty = false;
            lock.unlock();
            if (lost) {
                break;
            }
            if (dirty) {
                // Gateway or TLD list changed on the server: re-apply without
                // dropping the session.
                apply_server_network_config();
            }
        }
        control.join();

        {
            std::lock_guard<std::mutex> lock(tunnel_mutex);
            peer_valid = false;
        }

        if (control_sock != INVALID_SOCKET) {
            closesocket(control_sock);
            control_sock = INVALID_SOCKET;
        }

        if (g_shutdown) {
            break;
        }

        tray_set_state_utf8(false, "Server connection lost - reconnecting...");
        panel_set_connected(false, "");
        json_event("server_lost");
    }

    // Exit requested from the tray menu: close the devices so the tunnel
    // threads stop, then leave.
    clear_tunnel_dns_rules();
    set_tap_media_status(false);

    HANDLE tap_handle = tap_device;
    tap_device = INVALID_HANDLE_VALUE;
    if (tap_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(tap_handle);
    }

    SOCKET udp_socket = udp_sock;
    udp_sock = INVALID_SOCKET;
    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
    }

    // Detach instead of joining: a driver call may not return immediately and
    // Exit must stay responsive.
    tap_to_udp.detach();
    udp_to_tap.detach();

    // Wait briefly until the tray thread has removed the icon.
    for (int i = 0; i < 20 && tray_hwnd != NULL; ++i) {
        Sleep(50);
    }

    WSACleanup();
    return 0;
}

// The executable is linked as a GUI program (-mwindows), so double clicking
// it never opens a console window. WinMain is only the entry point; the real
// work happens in main().
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous_instance, LPSTR command_line, int show_cmd) {
    (void)instance;
    (void)previous_instance;
    (void)command_line;
    (void)show_cmd;
    return main();
}
