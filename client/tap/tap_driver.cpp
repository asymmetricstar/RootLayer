// client/tap/tap_driver.cpp - driver package install and adapter discovery.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "tap/tap.h"

// Install the driver package and create the TAP device node. pnputil only
// registers the package, the adapter itself is created by
// "devcon install <inf> tap0901" (the INF is root enumerated).

bool install_tap_driver() {
    std::string exe_dir = get_exe_dir();
    std::string inf_path = exe_dir + "\\resources\\tap\\OemVista.inf";
    std::string sys_path = exe_dir + "\\resources\\tap\\tap0901.sys";
    std::string cat_path = exe_dir + "\\resources\\tap\\tap0901.cat";
    std::string devcon_path = exe_dir + "\\resources\\tap\\devcon.exe";

    if (GetFileAttributesA(inf_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(sys_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(cat_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(devcon_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        json_event("error", "\"code\":\"tap_files_missing\"");
        return false;
    }

    reset_tap_detection();

    // Stage the driver in the driver store.
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string pnputil = std::string(system_dir) + "\\pnputil.exe";
    std::string output;
    (void)run_program_captured(pnputil, "/add-driver \"" + inf_path + "\"", output, 30000);

    // Reuse an existing TAP adapter if one exists.
    std::string instance_guid;
    std::string connection_name;
    if (find_available_tap_adapter(instance_guid, connection_name)) {
        return true;
    }
    reset_tap_detection();

    // No TAP adapter present at all: auto-create one with devcon so the client
    // can self-heal after the adapter was deleted. We do this only once per
    // start (not repeatedly), so Device Manager stays clean.
    json_event("info", "\"code\":\"tap_creating_adapter\"");
    std::string devcon_output;
    (void)run_program_captured(devcon_path, "install \"" + inf_path + "\" tap0901", devcon_output, 60000);

    // Give Windows a moment to enumerate the new device, then look again.
    Sleep(3000);
    reset_tap_detection();
    if (find_available_tap_adapter(instance_guid, connection_name)) {
        json_event("info", "\"code\":\"tap_adapter_created\"");
        return true;
    }

    json_event("error", "\"code\":\"tap_device_missing\"");
    return false;
}

// True when the given device instance (e.g. ROOT\\NET\\0000) uses a TAP
// driver. devcon installs the adapter as a root enumerated device, so its
// instance id does not contain "tap0901"; the hardware id does.
bool device_instance_is_tap(const std::string& instance_id) {
    if (instance_id.empty()) {
        return false;
    }

    std::string key = std::string("SYSTEM\\CurrentControlSet\\Enum") + instance_id;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    char buffer[512];
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    bool is_tap = false;

    if (RegQueryValueExA(hKey, "HardwareID", NULL, &type, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
        std::string hardware_ids(buffer, size);
        for (char& c : hardware_ids) {
            if (c == '\0') {
                c = ' ';
            }
        }
        is_tap = hardware_ids.find("tap0901") != std::string::npos ||
                 hardware_ids.find("tap0801") != std::string::npos ||
                 hardware_ids.find("tap1000") != std::string::npos;
    }

    RegCloseKey(hKey);
    return is_tap;
}

// Finds the TAP adapter Windows knows about. tap-windows6 exposes it as
// \\.\\Global\\{adapter-guid}.tap, the component id name only exists on older
// installations.
bool find_tap_adapter(std::string& instance_guid, std::string& connection_name) {
    instance_guid.clear();
    connection_name.clear();

    HKEY hNet;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &hNet) != ERROR_SUCCESS) {
        return false;
    }

    char guid[256];
    DWORD index = 0;

    for (;;) {
        DWORD guid_len = sizeof(guid);
        if (RegEnumKeyExA(hNet, index++, guid, &guid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }

        std::string conn_key = std::string(NETWORK_CONNECTIONS_KEY) + "\\" + std::string(guid) + "\\Connection";
        HKEY hConn;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key.c_str(), 0, KEY_READ, &hConn) != ERROR_SUCCESS) {
            continue;
        }

        char pnp_id[512];
        DWORD pnp_len = sizeof(pnp_id);
        DWORD type = 0;
        bool is_tap = false;
        std::string name;

        if (RegQueryValueExA(hConn, "PnpInstanceID", NULL, &type, (LPBYTE)pnp_id, &pnp_len) == ERROR_SUCCESS) {
            std::string pnp(pnp_id);
            is_tap = pnp.find("tap0901") != std::string::npos ||
                     pnp.find("tap0801") != std::string::npos ||
                     pnp.find("tap1000") != std::string::npos ||
                     device_instance_is_tap(pnp);
        }

        if (is_tap) {
            char name_buf[256];
            DWORD name_len = sizeof(name_buf);
            if (RegQueryValueExA(hConn, "Name", NULL, &type, (LPBYTE)name_buf, &name_len) == ERROR_SUCCESS) {
                name = std::string(name_buf);
            }
        }

        RegCloseKey(hConn);

        if (is_tap) {
            instance_guid = std::string(guid);
            connection_name = name;
            break;
        }
    }

    RegCloseKey(hNet);
    return !instance_guid.empty();
}

// Cached choice so get_tap_device_name() and get_tap_adapter_name() agree on
// the same physical adapter (important when several TAP adapters exist).
std::string chosen_tap_guid;
std::string chosen_tap_name;

// Clears the cached TAP choice. Call this whenever the adapter was deleted,
// disabled, or re-created, otherwise get_tap_adapter_name() keeps returning a
// stale name and netsh fails silently.
void reset_tap_detection() {
    chosen_tap_guid.clear();
    chosen_tap_name.clear();
}

// True when a Windows connection with this friendly name still exists.
bool adapter_connection_exists(const std::string& adapter_name) {
    if (adapter_name.empty()) {
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
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, adapter_name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, adapter_name.c_str(), -1, &wanted[0], wide_len);
    }
    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted == adapter->FriendlyName) {
            return true;
        }
    }
    return false;
}

// Collect every TAP adapter and return the first one that can actually be
// opened (not already in use by the server or another process).
bool find_available_tap_adapter(std::string& instance_guid, std::string& connection_name) {
    instance_guid.clear();
    connection_name.clear();

    HKEY hNet;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &hNet) != ERROR_SUCCESS) {
        return false;
    }

    std::vector<std::pair<std::string, std::string>> taps;
    std::vector<std::pair<std::string, std::string>> hardware_taps;
    char guid[256];
    DWORD index = 0;
    for (;;) {
        DWORD guid_len = sizeof(guid);
        if (RegEnumKeyExA(hNet, index++, guid, &guid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }

        std::string conn_key = std::string(NETWORK_CONNECTIONS_KEY) + "\\" + std::string(guid) + "\\Connection";
        HKEY hConn;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key.c_str(), 0, KEY_READ, &hConn) != ERROR_SUCCESS) {
            continue;
        }

        DWORD type = 0;
        std::string name;
        char pnp_id[512] = {0};
        DWORD pnp_len = sizeof(pnp_id);
        bool has_pnp = false;

        // Read the connection name for every adapter.
        char name_buf[256];
        DWORD name_len = sizeof(name_buf);
        if (RegQueryValueExA(hConn, "Name", NULL, &type, (LPBYTE)name_buf, &name_len) == ERROR_SUCCESS) {
            name = std::string(name_buf);
        }

        // Read the PnP instance so we can identify true TAP adapters by hardware
        // id (works for root-enumerated installs where PnpInstanceID does not
        // contain "tap0901" literally).
        if (RegQueryValueExA(hConn, "PnpInstanceID", NULL, &type, (LPBYTE)pnp_id, &pnp_len) == ERROR_SUCCESS) {
            has_pnp = true;
        }

        RegCloseKey(hConn);

        if (name.empty()) {
            continue;
        }

        bool is_tap = false;
        if (has_pnp) {
            std::string pnp(pnp_id);
            is_tap = pnp.find("tap0901") != std::string::npos ||
                     pnp.find("tap0801") != std::string::npos ||
                     pnp.find("tap1000") != std::string::npos ||
                     device_instance_is_tap(pnp);
        }

        if (is_tap) {
            hardware_taps.push_back(std::make_pair(std::string(guid), name));
        }
        taps.push_back(std::make_pair(std::string(guid), name));
    }

    RegCloseKey(hNet);

    // Prefer hardware-identified TAP adapters. The old code tried every
    // adapter (physical Ethernet, WAN Miniports, ...), which pollutes the
    // debug count and enables unrelated interfaces via netsh below.
    if (!hardware_taps.empty()) {
        taps = hardware_taps;
    }

    auto try_open = [&]() -> bool {
        for (size_t i = 0; i < taps.size(); ++i) {
            std::string dev = std::string(USERMODEDEVICEDIR) + taps[i].first + ".tap";
            HANDLE handle = CreateFileA(
                dev.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
                NULL
            );
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                instance_guid = taps[i].first;
                connection_name = taps[i].second;
                return true;
            }
        }
        return false;
    };

    if (try_open()) {
        return true;
    }

    // If nothing could be opened, try enabling disabled adapters via netsh.
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh = std::string(system_dir) + "\\netsh.exe";
    for (size_t i = 0; i < taps.size(); ++i) {
        std::string enable_cmd = "interface set interface name=\"" + taps[i].second + "\" admin=enabled";
        std::string enable_output;
        run_program_captured(netsh, enable_cmd, enable_output, 10000);
    }

    if (try_open()) {
        return true;
    }

    // Legacy device paths.
    const char* legacy[] = { USERMODEDEVICEDIR "tap0901.tap", USERMODEDEVICEDIR "tap0801.tap", USERMODEDEVICEDIR "tap1000.tap" };
    for (int i = 0; i < 3; ++i) {
        HANDLE handle = CreateFileA(legacy[i], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, NULL);
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
            instance_guid.clear();
            connection_name.clear();
            return true;
        }
    }

    json_event("debug", "\"code\":\"tap_debug\"," +
        json_number_field("tap_count", taps.size()) +
        json_string_field("detail", "no_tap_available"));
    return false;
}


std::string get_tap_device_name() {
    std::string instance_guid;
    std::string connection_name;

    if (find_available_tap_adapter(instance_guid, connection_name)) {
        chosen_tap_guid = instance_guid;
        chosen_tap_name = connection_name;
        return std::string(USERMODEDEVICEDIR) + instance_guid + ".tap";
    }
    // No usable adapter right now: drop any stale cache so the next lookup
    // forces a fresh registry scan instead of returning a deleted name.
    reset_tap_detection();
    return "";
}

// Find the Windows connection name (e.g. "Ethernet 2") of the TAP adapter.
// netsh needs that name, the user mode device path does not contain it.
std::string get_tap_adapter_name() {
    if (!chosen_tap_name.empty()) {
        if (adapter_connection_exists(chosen_tap_name)) {
            return chosen_tap_name;
        }
        // Cached name is stale (adapter was deleted/disabled): reset and rescan.
        reset_tap_detection();
    }
    std::string instance_guid;
    std::string connection_name;
    if (find_available_tap_adapter(instance_guid, connection_name)) {
        chosen_tap_guid = instance_guid;
        chosen_tap_name = connection_name;
        return connection_name;
    }
    return "";
}

// Priority startup guarantee: the client MUST have one healthy TAP adapter
// before the tunnel starts. Health means: the adapter exists in the network
// connections, its connection name is still present, and its user-mode device
// can actually be opened. If it is missing or unhealthy, reset detection,
// try a device restart, then remove the node and reinstall from scratch.
// After a TAP adapter is created/found, give it a predictable name
// ("Client Adaptor") so the gateway / firewall rules and tests can rely on it.
// Renaming is best-effort: if "Client Adaptor" is already taken (e.g. by a
// second TAP adapter) the current name is kept and no error is reported.
void maybe_rename_tap_to_ethernet2(const std::string& current_name) {
    const std::string wanted = "Client Adaptor";
    if (current_name.empty() || current_name == wanted) {
        return;
    }
    if (adapter_connection_exists(wanted)) {
        return;  // name taken, keep current
    }
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh = std::string(system_dir) + "\\netsh.exe";
    std::string rename_cmd = "interface set interface name=\"" + current_name + "\" newname=\"" + wanted + "\"";
    std::string rename_output;
    long long rc = run_program_captured(netsh, rename_cmd, rename_output, 10000);
    if (rc == 0 && adapter_connection_exists(wanted)) {
        chosen_tap_name = wanted;
        json_event("info", "\"code\":\"tap_adapter_renamed\"," + json_string_field("adapter", wanted));
    } else {
        json_event("warning", "\"code\":\"tap_rename_failed\",\"exit\":" + std::to_string(rc) +
                              "," + json_string_field("from", current_name));
    }
}

bool ensure_tap_adapter() {
    reset_tap_detection();

    std::string guid;
    std::string name;
    if (find_available_tap_adapter(guid, name) && adapter_connection_exists(name)) {
        chosen_tap_guid = guid;
        chosen_tap_name = name;
        maybe_rename_tap_to_ethernet2(name);
        json_event("info", "\"code\":\"tap_adapter_found\"," + json_string_field("adapter", chosen_tap_name));
        return true;
    }
    reset_tap_detection();

    if (!is_admin()) {
        json_event("error", "\"code\":\"tap_missing_admin\"");
        return false;
    }

    std::string exe_dir = get_exe_dir();
    std::string inf_path = exe_dir + "\\resources\\tap\\OemVista.inf";
    std::string devcon_path = exe_dir + "\\resources\\tap\\devcon.exe";

    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string pnputil = std::string(system_dir) + "\\pnputil.exe";

    // Stage the driver package (idempotent).
    std::string output;
    (void)run_program_captured(pnputil, "/add-driver \"" + inf_path + "\"", output, 30000);

    // Do NOT "remove *tap0901*" or "restart *tap0901*": on a host where the
    // server gateway and a client run together, "*tap0901*" also hits the
    // other process's adapter and destroys it (Server Adaptor disappears,
    // Client Adaptor loses its IP). Instead only ADD one adapter. If the
    // existing TAPs are all busy on this same host, install creates a second
    // one without touching the first. Disabled adapters are already enabled
    // inside find_available_tap_adapter via netsh.
    json_event("info", "\"code\":\"tap_adapter_install_attempt\"");
    (void)run_program_captured(devcon_path, "install \"" + inf_path + "\" tap0901", output, 60000);
    Sleep(3000);
    reset_tap_detection();
    if (find_available_tap_adapter(guid, name) && adapter_connection_exists(name)) {
        chosen_tap_guid = guid;
        chosen_tap_name = name;
        maybe_rename_tap_to_ethernet2(name);
        json_event("info", "\"code\":\"tap_adapter_created\"," + json_string_field("adapter", chosen_tap_name));
        return true;
    }

    json_event("error", "\"code\":\"tap_device_missing\"");
    return false;
}
