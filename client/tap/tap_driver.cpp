// client/tap/tap_driver.cpp - Wintun adapter creation for the client tunnel.
//
// Wintun is a layer-3 TUN driver: packets carry no Ethernet header, there is no
// ARP and no link-layer broadcast. It ships as a single wintun.dll (embedded
// driver, no INF/devcon/pnputil step) and the adapter is a normal Windows
// interface that netsh can address by its alias.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/json.h"
#include "core/utils.h"
#include "tap/tap.h"
#include "netdev/wintun.h"

namespace {

// Stable alias: the address, DNS and firewall setup all address the adapter by
// this name, and a change here would leave the old configuration behind.
const char* kAdapterName = "RootLayer";

// Fixed adapter GUID: Wintun then creates the same PnP device on every run, so
// Windows keeps one "RootLayer" network profile instead of creating a new one
// (and a new firewall category) on every start. A Wintun adapter is IP-only
// (NdisMediumIP) and exposes no MAC address at all, which is why the client's
// permanent identity is the 02:xx:... hardware id in client.ini.
const GUID kAdapterGuid = {0x7d3e1c42, 0x6a55, 0x4f0b,
                           {0x9c, 0x21, 0x5a, 0x8e, 0x3c, 0x9b, 0x1d, 0x11}};

// The adapter this process talks to. Empty until ensure_tap_adapter() ran.
std::string g_adapter_name;

bool adapter_listed(const std::string& name) {
    if (name.empty()) {
        return false;
    }
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
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wanted[0], wide_len);
    }

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted == adapter->FriendlyName) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool adapter_connection_exists(const std::string& adapter_name) {
    return adapter_listed(adapter_name);
}

void reset_tap_detection() {
    g_adapter_name.clear();
}

std::string get_tap_adapter_name() {
    return g_adapter_name.empty() ? std::string(kAdapterName) : g_adapter_name;
}

// In the tunnel the Windows interface alias and the netsh name are the same:
// Wintun has no separate user-mode device path.
std::string get_tap_device_name() {
    return get_tap_adapter_name();
}

// Kept for the startup sequence: wintun.dll carries the signed driver and
// installs it on the first adapter creation, so there is nothing to add to the
// driver store here.
bool install_tap_driver() {
    if (!netdev::available()) {
        json_event("error", std::string("\"code\":\"wintun_missing\",") +
                                json_string_field("detail", netdev::error_text()));
        return false;
    }
    json_event("info", "\"code\":\"wintun_ready\"");
    return true;
}

bool find_available_tap_adapter(std::string& instance_guid, std::string& connection_name) {
    instance_guid.clear();
    connection_name = kAdapterName;
    return netdev::available();
}

// Creates the adapter (the driver is installed by Wintun itself the first time)
// and waits until Windows lists the interface, because netsh can only configure
// an adapter that the network stack already knows.
bool ensure_tap_adapter() {
    if (!netdev::available()) {
        json_event("error", std::string("\"code\":\"wintun_missing\",") +
                                json_string_field("detail", netdev::error_text()));
        return false;
    }

    if (!netdev::create_adapter(kAdapterName, "RootLayer", &kAdapterGuid)) {
        json_event("error", std::string("\"code\":\"wintun_adapter_failed\",") +
                                json_string_field("detail", netdev::error_text()));
        return false;
    }
    g_adapter_name = kAdapterName;

    for (int i = 0; i < 50; ++i) {
        if (adapter_listed(g_adapter_name)) {
            json_event("info", std::string("\"code\":\"wintun_adapter_ready\",") +
                                   json_string_field("adapter", g_adapter_name));
            return true;
        }
        Sleep(200);
    }

    json_event("error", std::string("\"code\":\"wintun_adapter_missing\",") +
                            json_string_field("adapter", g_adapter_name));
    netdev::close();
    g_adapter_name.clear();
    return false;
}
