// server/gateway/gateway.cpp - TAP gateway setup + adapter threads.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "gateway/gateway.h"
#include "session/session.h"

// TAP IOCTL
#define TAP_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
std::vector<std::string> tap_instance_ids_by_registry() {
    std::vector<std::string> found;

    HKEY root = NULL;
    const char* class_key = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, class_key, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        return found;
    }

    for (DWORD index = 0; index < 256; ++index) {
        char subkey[16];
        sprintf(subkey, "%04lu", index);

        HKEY device = NULL;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &device) != ERROR_SUCCESS) {
            continue;
        }

        char component[128] = {0};
        DWORD size = sizeof(component);
        DWORD type = 0;
        bool is_tap = false;
        if (RegQueryValueExA(device, "ComponentId", NULL, &type, (BYTE*)component, &size) == ERROR_SUCCESS) {
            is_tap = std::string(component).find("tap") != std::string::npos;
        }

        if (is_tap) {
            char guid[128] = {0};
            size = sizeof(guid);
            if (RegQueryValueExA(device, "NetCfgInstanceId", NULL, &type, (BYTE*)guid, &size) == ERROR_SUCCESS) {
                // The registry value already carries braces; the device path and
                // the adapter name expect them in different places, so keep the
                // bare GUID only.
                std::string raw = guid;
                std::string bare;
                for (char c : raw) {
                    if (c != '{' && c != '}') {
                        bare.push_back(c);
                    }
                }
                if (!bare.empty()) {
                    found.push_back(bare);
                }
            }
        }

        RegCloseKey(device);
    }

    RegCloseKey(root);
    return found;
}
std::string adapter_friendly_name(const std::string& guid) {
    if (guid.empty()) {
        return "";
    }
    // Try the registry first: the authoritative netsh name for that GUID.
    {
        HKEY hNet;
        const char* net_key = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4d36e972-e325-11ce-bfc1-08002be10318}";
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, net_key, 0, KEY_READ, &hNet) == ERROR_SUCCESS) {
            char enum_guid[256];
            DWORD index = 0;
            for (;;) {
                DWORD guid_len = sizeof(enum_guid);
                if (RegEnumKeyExA(hNet, index++, enum_guid, &guid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                    break;
                }
                std::string enum_str(enum_guid);
                // Compare ignoring braces and case.
                std::string enum_norm = enum_str;
                std::string want_norm = guid;
                for (char& c : enum_norm) {
                    if (c == '{' || c == '}') c = ' ';
                    else c = (char)tolower((unsigned char)c);
                }
                for (char& c : want_norm) {
                    if (c == '{' || c == '}') c = ' ';
                    else c = (char)tolower((unsigned char)c);
                }
                if (enum_norm.find(want_norm) != std::string::npos) {
                    std::string conn_key = std::string(net_key) + "\\" + enum_str + "\\Connection";
                    HKEY hConn;
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key.c_str(), 0, KEY_READ, &hConn) == ERROR_SUCCESS) {
                        char name_buf[256] = {0};
                        DWORD name_len = sizeof(name_buf);
                        DWORD type = 0;
                        std::string result;
                        if (RegQueryValueExA(hConn, "Name", NULL, &type, (LPBYTE)name_buf, &name_len) == ERROR_SUCCESS) {
                            result = std::string(name_buf);
                        }
                        RegCloseKey(hConn);
                        RegCloseKey(hNet);
                        if (!result.empty()) {
                            return result;
                        }
                    }
                    break;
                }
            }
            RegCloseKey(hNet);
        }
    }

    // Fallback: case-insensitive match through GetAdaptersAddresses.
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        return "";
    }

    std::vector<unsigned char> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) {
        return "";
    }

    std::string guid_lower = guid;
    for (char& c : guid_lower) c = (char)tolower((unsigned char)c);

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        std::string name_lower(adapter->AdapterName);
        for (char& c : name_lower) c = (char)tolower((unsigned char)c);
        if (name_lower.find(guid_lower) != std::string::npos) {
            return narrow(std::wstring(adapter->FriendlyName));
        }
    }
    return "";
}
bool is_tap_friendly_name(const std::string& friendly_name) {
    if (friendly_name.empty()) {
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
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, friendly_name.c_str(), -1, NULL, 0);
    if (wide_len > 1) {
        wanted.resize((size_t)wide_len - 1);
        MultiByteToWideChar(CP_UTF8, 0, friendly_name.c_str(), -1, &wanted[0], wide_len);
    }
    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (wanted == adapter->FriendlyName) {
            std::string desc = narrow(std::wstring(adapter->Description));
            for (char& c : desc) c = (char)tolower((unsigned char)c);
            return desc.find("tap") != std::string::npos;
        }
    }
    return false;
}
bool run_hidden_command(const std::string& command_line, long long* exit_code) {
    STARTUPINFOA startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION process;
    ZeroMemory(&process, sizeof(process));

    std::string mutable_cmd = command_line;
    if (!CreateProcessA(NULL, &mutable_cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
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
void queue_tap_frame(const char* data, int len) {
    if (len <= 0) return;
    {
        std::lock_guard<std::mutex> lock(tap_tx_mutex);
        if (tap_tx_queue.size() >= tap_tx_max_frames) {
            tap_tx_queue.pop_front();  // keep latency bounded: drop the oldest
            tap_tx_dropped++;
            if (tap_tx_dropped % 1000 == 1) {
                std::cerr << "Gateway TAP write queue full, dropped " << tap_tx_dropped
                          << " frame(s)." << std::endl;
            }
        }
        tap_tx_queue.emplace_back(data, data + len);
    }
    tap_tx_cv.notify_one();
}
void tap_writer_thread() {
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        std::cerr << "Gateway TAP write event could not be created." << std::endl;
        return;
    }

    for (;;) {
        std::vector<char> frame;
        {
            std::unique_lock<std::mutex> lock(tap_tx_mutex);
            tap_tx_cv.wait(lock, [] { return tap_tx_stop || !tap_tx_queue.empty(); });
            if (tap_tx_queue.empty()) break;  // stop only after draining
            frame = std::move(tap_tx_queue.front());
            tap_tx_queue.pop_front();
        }
        if (gateway_tap == INVALID_HANDLE_VALUE) continue;

        ResetEvent(ov.hEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        DWORD written = 0;
        if (!WriteFile(gateway_tap, frame.data(), (DWORD)frame.size(), &written, &ov)) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                std::cerr << "Gateway TAP write failed: " << error << std::endl;
                Sleep(10);
                continue;
            }
            if (WaitForSingleObject(ov.hEvent, 5000) != WAIT_OBJECT_0 ||
                !GetOverlappedResult(gateway_tap, &ov, &written, FALSE)) {
                std::cerr << "Gateway TAP write did not complete." << std::endl;
                CancelIo(gateway_tap);
            }
        }
    }
    CloseHandle(ov.hEvent);
}
void gateway_to_relay_thread() {
    char buffer[65535];
    DWORD bytes_read = 0;
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        std::cerr << "Gateway TAP read event could not be created." << std::endl;
        return;
    }

    while (gateway_tap != INVALID_HANDLE_VALUE && relay_running) {
        ResetEvent(ov.hEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        bytes_read = 0;

        if (!ReadFile(gateway_tap, buffer, sizeof(buffer), &bytes_read, &ov)) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                if (!relay_running || gateway_tap == INVALID_HANDLE_VALUE) {
                    break;
                }
                if (error == ERROR_OPERATION_ABORTED || error == ERROR_NOT_READY) {
                    Sleep(100);
                    continue;
                }
                std::cerr << "Gateway TAP read failed: " << error << std::endl;
                break;
            }

            // Wait in slices so a shutdown is noticed even mid-read.
            for (;;) {
                if (WaitForSingleObject(ov.hEvent, 500) == WAIT_OBJECT_0) {
                    break;
                }
                if (!relay_running || gateway_tap == INVALID_HANDLE_VALUE) {
                    CancelIo(gateway_tap);
                    CloseHandle(ov.hEvent);
                    return;
                }
            }

            if (!GetOverlappedResult(gateway_tap, &ov, &bytes_read, FALSE)) {
                DWORD done_error = GetLastError();
                if (done_error == ERROR_OPERATION_ABORTED || done_error == ERROR_NOT_READY) {
                    Sleep(10);
                    continue;
                }
                std::cerr << "Gateway TAP read completion failed: " << done_error << std::endl;
                break;
            }
        }

        if (bytes_read > 0) {
            flood_to_sessions(buffer, (int)bytes_read, nullptr);
        }
    }
    CloseHandle(ov.hEvent);
}
bool is_admin_server() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY SIdAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup = NULL;
    if (AllocateAndInitializeSid(&SIdAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
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
void maybe_rename_gateway_adapter(std::string& adapter, const std::string& netsh) {
    const std::string wanted = "Server Adaptor";
    if (adapter == wanted) return;
    if (adapter_connection_exists_server(wanted)) {
        std::cout << "Gateway adapter keeps name \"" << adapter << "\" (\"" << wanted << "\" already in use)." << std::endl;
        return;
    }
    std::string cmd = "\"" + netsh + "\" interface set interface name=\"" + adapter + "\" newname=\"" + wanted + "\"";
    long long exit_code = 0;
    if (run_hidden_command(cmd, &exit_code) && exit_code == 0 && adapter_connection_exists_server(wanted)) {
        std::cout << "Gateway adapter renamed to \"" << wanted << "\"" << std::endl;
        adapter = wanted;
    } else {
        std::cerr << "Could not rename gateway adapter \"" << adapter << "\" to \"" << wanted << "\" (exit " << exit_code << ")." << std::endl;
    }
}
bool setup_gateway() {
    HANDLE tap = INVALID_HANDLE_VALUE;
    std::string guid;
    std::string adapter;
    // Adapters that failed to take the gateway address are never retried.
    std::set<std::string> rejected_adapters;
    char system_dir[MAX_PATH] = {0};
    GetSystemDirectoryA(system_dir, MAX_PATH);
    std::string netsh = std::string(system_dir) + "\\netsh.exe";

    auto try_find_gateway_tap = [&]() -> bool {
        if (tap != INVALID_HANDLE_VALUE) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; }
        std::vector<std::string> candidates = tap_instance_ids_by_registry();
        if (candidates.empty()) return false;

        // The server must claim its own TAP adapter. When a client runs on this
        // same host it renames its adapter to "Client Adaptor". Taking that one
        // leaves the virtual gateway address unassigned, so remote clients can
        // connect and get an IP but never reach 10.0.0.1 or the tunnel
        // ("Gateway disabled: clients will only reach each other").
        std::vector<std::string> ordered;
        for (const auto& candidate : candidates) {
            std::string name = adapter_friendly_name(candidate);
            if (name.empty()) continue;
            if (!is_tap_friendly_name(name)) continue;
            if (!adapter_connection_exists_server(name)) continue;
            if (rejected_adapters.find(name) != rejected_adapters.end()) continue;
            ordered.push_back(candidate);
        }
        std::stable_sort(ordered.begin(), ordered.end(),
                         [](const std::string& a, const std::string& b) {
                             auto rank = [](const std::string& guid) -> int {
                                 std::string name = adapter_friendly_name(guid);
                                 for (char& c : name) c = (char)tolower((unsigned char)c);
                                 if (name == "server adaptor") return 0;
                                 if (name == "client adaptor") return 2;
                                 return 1;
                             };
                             return rank(a) < rank(b);
                         });
        candidates.swap(ordered);
        if (candidates.empty()) return false;
        DWORD last_error = 0;
        for (const auto& candidate : candidates) {
            std::string device_path = "\\\\.\\Global\\{" + candidate + "}.tap";
            // FILE_FLAG_OVERLAPPED: synchronous TAP I/O serialises reads and
            // writes on the same handle, which blocks the relay thread.
            HANDLE h = CreateFileA(device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                tap = h;
                guid = candidate;
                break;
            }
            last_error = GetLastError();
        }
        (void)last_error;
        if (tap == INVALID_HANDLE_VALUE) return false;
        DWORD returned = 0;
        unsigned long media_status = 1;
        DeviceIoControl(tap, TAP_IOCTL_SET_MEDIA_STATUS, &media_status, sizeof(media_status),
                        &media_status, sizeof(media_status), &returned, NULL);
        adapter = adapter_friendly_name(guid);
        if (adapter.empty()) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        if (!is_tap_friendly_name(adapter)) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        if (!adapter_connection_exists_server(adapter)) { CloseHandle(tap); tap = INVALID_HANDLE_VALUE; return false; }
        return true;
    };

    if (!try_find_gateway_tap()) {
        if (!is_admin_server()) {
            std::cerr << "No TAP adapter found: gateway address " << server_virtual_ip() << " is not available (run the server as administrator)." << std::endl;
            return false;
        }
        std::string exe_dir = get_exe_dir_server();
        std::string inf_path = exe_dir + "\\resources\\tap\\OemVista.inf";
        std::string devcon_path = exe_dir + "\\resources\\tap\\devcon.exe";
        std::string pnputil = std::string(system_dir) + "\\pnputil.exe";
        long long exit_code = 0;
        (void)run_hidden_command("\"" + pnputil + "\" /add-driver \"" + inf_path + "\"", &exit_code);
        // Do NOT "remove/restart *tap0901*": when a client runs on this same
        // host, "*tap0901*" also hits its "Client Adaptor" and destroys it
        // (ipconfig then shows Client Adaptor without an IP and no
        // Server Adaptor at all). Only ADD one adapter — if the existing
        // TAPs are busy, install creates a second one without touching the
        // first. Disabled adapters are already enabled inside the health
        // check via netsh.
        std::cout << "TAP adapter not found: installing one for gateway..." << std::endl;
        (void)run_hidden_command("\"" + devcon_path + "\" install \"" + inf_path + "\" tap0901", &exit_code);
        Sleep(3000);
        if (!try_find_gateway_tap()) {
            std::cerr << "No TAP adapter found: gateway address " << server_virtual_ip() << " is not available." << std::endl;
            return false;
        }
        std::cout << "TAP adapter recovered for gateway." << std::endl;
    }

    long long exit_code = 0;

    // Bring the adapter up and give it the gateway address. A disabled or stale
    // TAP node accepts CreateFile but rejects the address, so a failed adapter
    // must not disable the gateway while a usable TAP still exists.
    for (;;) {
        std::string original_name = adapter;

        std::string enable_cmd = "\"" + netsh + "\" interface set interface name=\"" + adapter + "\" admin=enabled";
        (void)run_hidden_command(enable_cmd, &exit_code);

        maybe_rename_gateway_adapter(adapter, netsh);

        bool assigned = false;
        if (is_tap_friendly_name(adapter) && adapter_connection_exists_server(adapter)) {
            std::string address_cmd = "\"" + netsh + "\" interface ipv4 set address name=\"" + adapter +
                                      "\" static " + server_virtual_ip() + " " + ip_to_string(virtual_ip_mask);
            if (run_hidden_command(address_cmd, &exit_code) && exit_code == 0) {
                assigned = true;
            } else {
                std::cerr << "Could not assign " << server_virtual_ip() << " to \"" << adapter
                          << "\" (exit " << exit_code << ")." << std::endl;
            }
        } else {
            std::cerr << "Gateway adapter \"" << adapter << "\" did not pass TAP health check." << std::endl;
        }

        if (assigned) {
            break;
        }

        // Try the next TAP instead of leaving the gateway offline.
        rejected_adapters.insert(original_name);
        rejected_adapters.insert(adapter);
        if (tap != INVALID_HANDLE_VALUE) {
            CloseHandle(tap);
            tap = INVALID_HANDLE_VALUE;
        }
        if (!try_find_gateway_tap()) {
            std::cerr << "No further TAP adapter available for " << server_virtual_ip()
                      << "; gateway stays offline." << std::endl;
            return false;
        }
    }

    // The frame travels inside UDP, so the segment MTU has to shrink.
    bool mtu_ran = run_hidden_command("\"" + netsh + "\" interface ipv4 set subinterface \"" + adapter +
                                      "\" mtu=1400 store=persistent", &exit_code);
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
    std::string fw_script = "if (-not (Get-NetFirewallRule -DisplayName '" + rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + rule_name +
        "' -Direction Inbound -Action Allow -InterfaceAlias '" + adapter + "' -Profile Any | Out-Null }; "
        "if (-not (Get-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '" + icmp_rule_name +
        "' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias '" + adapter +
        "' -Profile Any | Out-Null }";

    bool fw_ok = run_hidden_command("\"" + powershell + "\" -NoProfile -NonInteractive -Command \"" +
                                    fw_script + "\"", &exit_code) && exit_code == 0;
    if (!fw_ok) {
        std::cerr << "Firewall rule could not be created (exit " << exit_code << ")." << std::endl;
    } else {
        std::cout << "Firewall rule \"" << rule_name << "\" ready for \"" << adapter << "\"" << std::endl;
    }

    if (nat_enabled) {
        std::string powershell = std::string(system_dir) + "\\WindowsPowerShell\\v1.0\\powershell.exe";
        std::string nat_cmd = "\"" + powershell + "\" -NoProfile -Command \"if (-not (Get-NetNat -Name P2PVPN -ErrorAction SilentlyContinue)) "
                              "{ New-NetNat -Name P2PVPN -InternalIPInterfaceAddressPrefix " +
                              virtual_ip_prefix + "0/24 | Out-Null }\"";
        if (!run_hidden_command(nat_cmd, &exit_code) || exit_code != 0) {
            std::cerr << "NAT could not be enabled (WinNat service / administrator rights)." << std::endl;
        } else {
            std::cout << "NAT enabled: " << virtual_ip_prefix << "0/24 -> internet" << std::endl;
        }
    }

    gateway_tap = tap;
    gateway_adapter_name = adapter;

    std::cout << "Gateway active: " << server_virtual_ip() << " on \"" << adapter << "\"" << std::endl;

    std::thread(gateway_to_relay_thread).detach();
    std::thread(tap_writer_thread).detach();
    return true;
}
