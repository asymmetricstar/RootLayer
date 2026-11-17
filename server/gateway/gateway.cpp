// server/gateway/gateway.cpp - the server's own member of the virtual segment.
//
// The gateway is a Wintun (layer 3) adapter: it carries bare IP packets, so the
// address, MTU, firewall rule and NAT below are all that is needed. There is no
// TAP driver to install, no device node to enumerate and no MAC layer: frames
// arrive from the relay as IP packets and are written straight into the adapter.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "session/session.h"
#include "gateway/gateway.h"
#include "federation/federation.h"
#include "netdev/wintun.h"

namespace {

// Stable alias: netsh and PowerShell address the adapter by this name.
const char* kGatewayAdapter = "RootLayer Gateway";

// Fixed adapter GUID: the same PnP device on every start, so Windows keeps the
// gateway adapter's network profile instead of making a new one each time.
// (A Wintun adapter is IP-only and has no MAC address.)
const GUID kGatewayAdapterGuid = {0x7d3e1c42, 0x6a55, 0x4f0b,
                                  {0x9c, 0x21, 0x5a, 0x8e, 0x3c, 0x9b, 0x1d, 0x12}};

}  // namespace

// The packet queue itself (tap_tx_* in core/globals.cpp) is shared with the
// relay: the relay must never block on a device write, and a full queue drops
// the oldest packet so latency stays bounded instead of growing.

bool run_hidden_command(const std::string& command_line, long long* exit_code) {
    STARTUPINFOA startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);

    PROCESS_INFORMATION process;
    ZeroMemory(&process, sizeof(process));

    std::string mutable_cmd = command_line;
    if (!CreateProcessA(NULL, &mutable_cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                        &startup, &process)) {
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

bool is_admin_server() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY SIdAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup = NULL;
    if (AllocateAndInitializeSid(&SIdAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &pAdministratorsGroup)) {
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

void queue_tap_frame(const char* data, int len) {
    if (len <= 0) return;
    {
        std::lock_guard<std::mutex> lock(tap_tx_mutex);
        if (tap_tx_queue.size() >= tap_tx_max_frames) {
            tap_tx_queue.pop_front();  // keep latency bounded: drop the oldest
            tap_tx_dropped++;
            if (tap_tx_dropped % 1000 == 1) {
                std::cerr << "Gateway write queue full, dropped " << tap_tx_dropped
                          << " packet(s)." << std::endl;
            }
        }
        tap_tx_queue.emplace_back(data, data + len);
    }
    tap_tx_cv.notify_one();
}

void tap_writer_thread() {
    for (;;) {
        std::vector<char> packet;
        {
            std::unique_lock<std::mutex> lock(tap_tx_mutex);
            tap_tx_cv.wait(lock, [] { return tap_tx_stop || !tap_tx_queue.empty(); });
            if (tap_tx_queue.empty()) break;  // stop only after draining
            packet = std::move(tap_tx_queue.front());
            tap_tx_queue.pop_front();
        }
        if (!gateway_active.load()) continue;

        if (!netdev::write_packet(packet.data(), (int)packet.size())) {
            std::cerr << "Gateway packet write failed: " << netdev::error_text() << std::endl;
            Sleep(10);
        }
    }
}

void gateway_to_relay_thread() {
    char buffer[65535];

    while (relay_running) {
        int bytes_read = netdev::read_packet(buffer, sizeof(buffer), 500);
        if (bytes_read < 0) {
            if (!relay_running) break;
            std::cerr << "Gateway packet read failed: " << netdev::error_text() << std::endl;
            break;
        }
        if (bytes_read == 0) {
            continue;  // idle timeout
        }
        // A packet routing through the gateway belongs to the whole segment,
        // unless its destination is another server's address block: then it
        // takes the federation link instead of being flooded only here. This
        // is what lets the server host itself reach a remote client (for
        // example `ping 10.0.0.19` from the B machine).
        if (fed::forward_packet(buffer, bytes_read)) {
            continue;
        }
        flood_to_sessions(buffer, bytes_read, nullptr);
    }
}

// Brings the gateway adapter up: create it, give it the virtual gateway address,
// shrink the MTU, allow inbound traffic and enable NAT. Returns false when the
// gateway could not be configured; the relay keeps running in that case.
bool setup_gateway() {
    if (!netdev::available()) {
        std::cerr << "Gateway: wintun.dll could not be loaded (" << netdev::error_text()
                  << "); gateway stays offline." << std::endl;
        return false;
    }

    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh = std::string(system_dir) + "\\netsh.exe";

    if (!netdev::create_adapter(kGatewayAdapter, "RootLayer", &kGatewayAdapterGuid)) {
        std::cerr << "Gateway: " << netdev::error_text() << std::endl;
        return false;
    }

    // The driver creates the interface asynchronously; netsh only accepts an
    // adapter that the network stack already lists.
    for (int i = 0; i < 50 && !adapter_connection_exists_server(kGatewayAdapter); ++i) {
        Sleep(200);
    }
    if (!adapter_connection_exists_server(kGatewayAdapter)) {
        std::cerr << "Gateway: adapter \"" << kGatewayAdapter
                  << "\" did not appear in the network stack." << std::endl;
        netdev::close();
        return false;
    }
    const std::string adapter = kGatewayAdapter;

    long long exit_code = 0;

    // A disabled adapter rejects the address; enabling first is harmless.
    (void)run_hidden_command("\"" + netsh + "\" interface set interface name=\"" + adapter +
                                 "\" admin=enabled", &exit_code);

    std::string address_cmd = "\"" + netsh + "\" interface ipv4 set address name=\"" + adapter +
                              "\" static " + server_virtual_ip() + " " +
                              ip_to_string(virtual_ip_mask);
    if (!run_hidden_command(address_cmd, &exit_code) || exit_code != 0) {
        std::cerr << "Gateway: could not assign " << server_virtual_ip() << " to \"" << adapter
                  << "\" (exit " << exit_code << ")." << std::endl;
        netdev::close();
        return false;
    }

    // Layer 3: a packet for another address has to be forwarded by this host.
    // With a layer-2 bridge that happened implicitly, a TUN interface needs the
    // interface forwarding flag (New-NetNat also installs its own forwarding).
    (void)run_hidden_command("\"" + netsh + "\" interface ipv4 set interface \"" + adapter +
                                 "\" forwarding=enabled", &exit_code);

    // The packet travels inside UDP, so the segment MTU has to shrink.
    bool mtu_ran = run_hidden_command("\"" + netsh + "\" interface ipv4 set subinterface \"" +
                                          adapter + "\" mtu=1400 store=persistent",
                                      &exit_code);
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
    //
    // The rules are rebuilt every start instead of only when the display name
    // is missing: a rule left behind by an earlier adapter (named the same, but
    // bound to an interface that no longer exists) would otherwise survive and
    // the new gateway adapter would never get its ICMP allowance, leaving
    // 10.0.0.1 unpingable while TCP/UDP still work.
    std::string fw_script = "Remove-NetFirewallRule -DisplayName '" + rule_name + "','" +
        icmp_rule_name + "' -ErrorAction SilentlyContinue; "
        "New-NetFirewallRule -DisplayName '" + rule_name +
        "' -Direction Inbound -Action Allow -InterfaceAlias '" + adapter +
        "' -Profile Any | Out-Null; "
        "New-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias '" + adapter +
        "' -Profile Any | Out-Null";

    bool fw_ok = run_hidden_command("\"" + powershell + "\" -NoProfile -NonInteractive -Command \"" +
                                    fw_script + "\"", &exit_code) && exit_code == 0;
    if (!fw_ok) {
        std::cerr << "Firewall rule could not be created (exit " << exit_code << ")." << std::endl;
    } else {
        std::cout << "Firewall rule \"" << rule_name << "\" ready for \"" << adapter << "\"" << std::endl;
    }

    if (nat_enabled) {
        // The NAT prefix follows the configured subnet, so a /16 or /22 network
        // is translated as a whole instead of only its first /24.
        const std::string nat_prefix =
            ip_to_string(virtual_ip_network) + "/" + std::to_string(virtual_ip_prefix_len);
        std::string nat_cmd = "\"" + powershell + "\" -NoProfile -Command \"if (-not (Get-NetNat -Name P2PVPN -ErrorAction SilentlyContinue)) "
                              "{ New-NetNat -Name P2PVPN -InternalIPInterfaceAddressPrefix " +
                              nat_prefix + " | Out-Null }\"";
        if (!run_hidden_command(nat_cmd, &exit_code) || exit_code != 0) {
            std::cerr << "NAT could not be enabled (WinNat service / administrator rights)." << std::endl;
        } else {
            std::cout << "NAT enabled: " << nat_prefix << " -> internet" << std::endl;
        }
    }

    if (!netdev::start_session()) {
        std::cerr << "Gateway: " << netdev::error_text() << std::endl;
        netdev::close();
        return false;
    }

    gateway_active = true;
    gateway_adapter_name = adapter;

    std::cout << "Gateway active: " << server_virtual_ip() << " on \"" << adapter << "\""
              << std::endl;

    std::thread(gateway_to_relay_thread).detach();
    std::thread(tap_writer_thread).detach();
    return true;
}
