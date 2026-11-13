// client/tap/tap_config.cpp - IP/DNS/firewall/MTU setup, open + media status.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "tap/tap.h"

// True when the named adapter currently owns the given IPv4 address.
bool adapter_has_ipv4(const std::string& adapter_name, const std::string& ip) {
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }

    std::vector<unsigned char> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) {
        return false;
    }

    std::wstring wanted;
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, adapter_name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, adapter_name.c_str(), -1, &wanted[0], wide_len);
    }

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted != adapter->FriendlyName) {
            continue;
        }
        for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress; unicast != NULL; unicast = unicast->Next) {
            sockaddr_in* address = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
            if (address != NULL && address->sin_family == AF_INET) {
                if (ip == std::string(inet_ntoa(address->sin_addr))) {
                    return true;
                }
            }
        }
    }

    return false;
}

// Give the TAP adapter its virtual IP and bring the link up. When the server
// offers a gateway (10.0.0.1) it is written with a high metric so the physical
// NIC keeps the default route.
bool configure_tap_adapter(const std::string& ip, const std::string& gateway, const std::string& mask, const std::string& gateway2) {
    (void)gateway2;  // reserved; kept so callers can pass a second gateway value later
    std::string adapter = get_tap_adapter_name();
    if (adapter.empty()) {
        json_event("error", "\"code\":\"tap_adapter_name_missing\"");
        return false;
    }

    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh_path = std::string(system_dir) + "\\netsh.exe";

    // The chosen TAP adapter may be disabled (a spare adapter). Enable it
    // first so netsh can configure its address.
    std::string enable_cmd = "interface set interface name=\"" + adapter + "\" admin=enabled";
    std::string enable_output;
    run_program_captured(netsh_path, enable_cmd, enable_output, 10000);

    std::string address_cmd = "interface ipv4 set address name=\"" + adapter + "\" static " + ip + " " + mask;
    if (!gateway.empty()) {
        address_cmd += " " + gateway + " gwmetric=50";
    }

    std::string output;
    long long exitCode = run_program_captured(netsh_path, address_cmd, output, 30000);

    std::string detail = trim(output);

    if (exitCode != 0) {
        json_event("error", std::string("\"code\":\"tap_configure_failed\",") +
            json_number_field("exit", exitCode) + "," +
            json_string_field("detail", detail));
        return false;
    }

    // Tell the TAP adapter to use the gateway as its DNS server so names like
    // root.p2p resolve through the ARPA/DNS server on the other side of the
    // tunnel (10.0.0.1:53). Without this, Windows has no idea where to send
    // .p2p queries and ping root.p2p fails with "could not find host".
    if (!gateway.empty()) {
        std::string dns_cmd = "interface ipv4 set dns name=\"" + adapter + "\" static " + gateway;
        std::string dns_output;
        run_program_captured(netsh_path, dns_cmd, dns_output, 10000);
    }

    // netsh can return before the address is actually active.
    for (int i = 0; i < 10; ++i) {
        if (adapter_has_ipv4(adapter, ip)) {
            json_event("tap_configured", json_string_field("ip", ip));
            return true;
        }
        Sleep(300);
    }

    json_event("error", std::string("\"code\":\"tap_ip_missing\",") +
        json_string_field("ip", ip) + "," +
        json_string_field("adapter", adapter) + "," +
        json_string_field("detail", detail));
    return false;
}

// The TAP adapter is treated as a new, unidentified network, so Windows applies
// the Public firewall profile and drops inbound traffic. One allow rule bound to
// the interface fixes HTTP/SMB/FTP/ICMP without touching the physical adapters.
// The MTU also has to shrink because the frame is wrapped in UDP/IP.
void prepare_tap_adapter(const std::string& adapter) {
    if (adapter.empty()) {
        return;
    }

    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh_path = std::string(system_dir) + "\\netsh.exe";

    // "netsh advfirewall firewall add rule" has no interface= parameter (only
    // interfacetype=), so a rule bound to one adapter needs New-NetFirewallRule.
    std::string powershell_path = std::string(system_dir) + "\\WindowsPowerShell\\v1.0\\powershell.exe";

    const std::string rule_name = "P2P VPN TAP";
    // Interface-specific: the server running on the same machine adds a rule too.
    const std::string icmp_rule_name = "P2P VPN TAP ICMP";
    // Interface rules do not cover ICMP: without this, an inbound echo request
    // on the tunnel adapter is dropped and peers cannot ping each other.
    std::string fw_script = "if (-not (Get-NetFirewallRule -DisplayName '" + rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + rule_name +
        "' -Direction Inbound -Action Allow -InterfaceAlias '" + adapter + "' -Profile Any | Out-Null }; "
        "if (-not (Get-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias '" + adapter +
        "' -Profile Any | Out-Null }";

    std::string fw_output;
    long long fw_exit = run_program_captured(powershell_path,
        "-NoProfile -NonInteractive -Command \"" + fw_script + "\"", fw_output, 20000);

    if (fw_exit == 0) {
        json_event("tap_prepared", std::string("\"firewall_rule\":\"ready\",") + json_string_field("interface", adapter));
    } else {
        json_event("warning", std::string("\"code\":\"firewall_rule_failed\",") +
            json_number_field("exit", fw_exit) + "," + json_string_field("detail", trim(fw_output)));
    }

    // A 1500 byte frame plus the outer UDP/IP headers no longer fits a normal
    // 1500 byte path, which makes large transfers stall after the handshake.
    std::string mtu_output;
    long long mtu_exit = run_program_captured(netsh_path,
        "interface ipv4 set subinterface \"" + adapter + "\" mtu=1400 store=persistent", mtu_output, 15000);
    if (mtu_exit != 0) {
        json_event("warning", std::string("\"code\":\"mtu_set_failed\",") +
            json_number_field("exit", mtu_exit) + "," + json_string_field("detail", trim(mtu_output)));
    }
}

bool open_tap_device(const std::string& tap_name) {
    // FILE_FLAG_OVERLAPPED: with synchronous I/O a pending ReadFile makes every
    // concurrent WriteFile on the same TAP handle wait (measured 0.4-2.8 s per
    // frame), so incoming tunnel traffic crawled and the queue backed up.
    tap_device = CreateFileA(
        tap_name.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (tap_device == INVALID_HANDLE_VALUE) {
        json_event("error", "\"code\":\"tap_open_failed\",\"win_error\":" + std::to_string(GetLastError()));
        return false;
    }

    return true;
}

// A freshly opened TAP adapter starts in the "disconnected" state and would
// drop every packet until the media status is set to connected.
bool set_tap_media_status(bool connected) {
    if (tap_device == INVALID_HANDLE_VALUE) {
        return false;
    }

    ULONG status = connected ? 1 : 0;
    DWORD returned = 0;
    if (!DeviceIoControl(tap_device, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status),
                         &returned, NULL)) {
        json_event("error", "\"code\":\"tap_media_status_failed\",\"win_error\":" + std::to_string(GetLastError()));
        return false;
    }
    return true;
}

// --- Virtual TLD resolution (NRPT) -----------------------------------------
//
// A lookup is sent to the DNS server of the interface that owns the default
// route, so names under the server's virtual TLDs are answered "not found"
// there and only reach the tunnel after the resolver has retried for several
// seconds. An NRPT rule points exactly those name spaces at the tunnel DNS
// server and leaves the internet resolver untouched.
//
// Neither the gateway address nor the TLD list is built into the client: both
// arrive with every registration response (GATEWAY and TLD tokens), so the
// administrator can move the network (10.0.0.x, 100.0.0.x, ...) or change the
// TLD set and the installed clients follow on their next registration.

static std::vector<std::string> g_tunnel_namespaces;  // server-provided, may be empty
// Rules from an earlier run are assumed to exist until they have been
// reconciled once, so a leftover rule can never survive a restart.
static bool g_dns_rules_may_exist = true;
static std::string g_applied_gateway;
static std::vector<std::string> g_applied_namespaces;

static bool valid_namespace_label(const std::string& label);

// The server suffixes reduced to the plain labels that may go into a rule.
static std::vector<std::string> validated_namespaces() {
    std::vector<std::string> accepted;
    for (const auto& suffix : g_tunnel_namespaces) {
        std::string label = suffix;
        if (!label.empty() && label.front() == '.') label.erase(0, 1);
        if (valid_namespace_label(label)) accepted.push_back(label);
    }
    return accepted;
}

static std::string powershell_path() {
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    return std::string(system_dir) + "\\WindowsPowerShell\\v1.0\\powershell.exe";
}

// Only a plain DNS label may reach the rule: anything else is dropped instead
// of being handed to the shell.
static bool valid_namespace_label(const std::string& label) {
    if (label.empty() || label.size() > 63) return false;
    if (label.front() == '-' || label.back() == '-') return false;
    for (char c : label) {
        if (!(isalnum((unsigned char)c) || c == '-')) return false;
    }
    return true;
}

static bool run_powershell(const std::string& script) {
    std::string output;
    long long exit_code = run_program_captured(
        powershell_path(),
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"",
        output, 20000);
    return exit_code == 0;
}

// Only the rules this client created are touched, so a rule left over from an
// earlier gateway address or TLD set can never survive.
static const char* kRemoveDnsRules =
    "Get-DnsClientNrptRule | Where-Object { $_.Name -like 'RootLayerTunnel:*' } | "
    "Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;";

void set_tunnel_dns_namespaces(const std::vector<std::string>& namespaces) {
    // Stored exactly as the server sent them; validated_namespaces() filters
    // them when the rules are written.
    g_tunnel_namespaces = namespaces;
}

void apply_tunnel_dns_rules(const std::string& gateway) {
    // Remove first: a changed gateway or TLD list must not leave the previous
    // rules in place.
    const std::vector<std::string> namespaces = validated_namespaces();
    const bool usable = !gateway.empty() && inet_addr(gateway.c_str()) != INADDR_NONE &&
                        !namespaces.empty();

    std::string script = kRemoveDnsRules;
    if (usable) {
        for (const auto& suffix : namespaces) {
            script += " Add-DnsClientNrptRule -Name 'RootLayerTunnel:" + suffix +
                      "' -Namespace '." + suffix + "' -NameServers " + gateway +
                      " -ErrorAction SilentlyContinue;";
        }
    }

    if (!run_powershell(script)) {
        json_event("error", "\"code\":\"dns_rules_failed\"");
        return;
    }

    g_dns_rules_may_exist = usable;
    g_applied_gateway = usable ? gateway : "";
    g_applied_namespaces = usable ? namespaces : std::vector<std::string>();
    if (usable) {
        json_event("dns_rules_set", json_string_field("gateway", gateway) + "," +
                                        json_number_field("count", (long long)namespaces.size()));
    }
}

void clear_tunnel_dns_rules() {
    if (!g_dns_rules_may_exist) return;
    if (run_powershell(kRemoveDnsRules)) {
        g_dns_rules_may_exist = false;
        g_applied_gateway.clear();
        g_applied_namespaces.clear();
    }
}

// True when the installed rules already match what the server reports, so a
// reconnect that only changed the TLD list still refreshes them.
bool tunnel_dns_rules_current(const std::string& gateway) {
    const std::vector<std::string> wanted = validated_namespaces();
    const bool should_have_rules = !gateway.empty() &&
                                   inet_addr(gateway.c_str()) != INADDR_NONE &&
                                   !wanted.empty();
    if (!should_have_rules) {
        return !g_dns_rules_may_exist;
    }
    return g_dns_rules_may_exist && g_applied_gateway == gateway &&
           g_applied_namespaces == wanted;
}
