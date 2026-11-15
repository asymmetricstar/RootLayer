// netdev/wintun.cpp
//
// wintun.dll is loaded dynamically (LoadLibraryEx + GetProcAddress), so the
// executables still start, and report a clear error, when the DLL is missing.
// The function signatures below match include/wintun.h of the Wintun package;
// declaring them here keeps the driver header out of the build.
#include "netdev/wintun.h"

#include <cstring>
#include <vector>

namespace netdev {
namespace {

typedef void* WintunAdapter;
typedef void* WintunSession;

typedef WintunAdapter(WINAPI* CreateAdapterFn)(LPCWSTR, LPCWSTR, const GUID*);
typedef WintunAdapter(WINAPI* OpenAdapterFn)(LPCWSTR);
typedef void(WINAPI* CloseAdapterFn)(WintunAdapter);
typedef WintunSession(WINAPI* StartSessionFn)(WintunAdapter, DWORD);
typedef void(WINAPI* EndSessionFn)(WintunSession);
typedef HANDLE(WINAPI* GetReadWaitEventFn)(WintunSession);
typedef BYTE*(WINAPI* ReceivePacketFn)(WintunSession, DWORD*);
typedef void(WINAPI* ReleaseReceivePacketFn)(WintunSession, const BYTE*);
typedef BYTE*(WINAPI* AllocateSendPacketFn)(WintunSession, DWORD);
typedef void(WINAPI* SendPacketFn)(WintunSession, const BYTE*);

HMODULE g_module = NULL;
CreateAdapterFn g_create_adapter = NULL;
OpenAdapterFn g_open_adapter = NULL;
CloseAdapterFn g_close_adapter = NULL;
StartSessionFn g_start_session = NULL;
EndSessionFn g_end_session = NULL;
GetReadWaitEventFn g_read_wait_event = NULL;
ReceivePacketFn g_receive_packet = NULL;
ReleaseReceivePacketFn g_release_receive_packet = NULL;
AllocateSendPacketFn g_allocate_send_packet = NULL;
SendPacketFn g_send_packet = NULL;

WintunAdapter g_adapter = NULL;
WintunSession g_session = NULL;
std::string g_error;

// Wintun's ring must be a power of two between 128 KiB and 64 MiB. 4 MiB holds
// a few hundred full-size packets, enough for a burst without starving reads.
const DWORD kRingCapacity = 0x400000;

std::string exe_dir() {
    char buffer[MAX_PATH * 4];
    DWORD length = GetModuleFileNameA(NULL, buffer, sizeof(buffer));
    if (length == 0 || length == sizeof(buffer)) {
        return std::string();
    }
    std::string path(buffer, length);
    size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? std::string() : path.substr(0, pos);
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, NULL, 0);
    if (needed <= 1) {
        return std::wstring();
    }
    std::wstring wide((size_t)needed - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wide[0], needed);
    return wide;
}

// GetProcAddress returns FARPROC; going through void* keeps the per-export
// function-type casts warning-free.
#define ROOTLAYER_RESOLVE(target, type, name) \
    target = reinterpret_cast<type>(reinterpret_cast<void*>(GetProcAddress(g_module, name)))

bool resolve() {
    ROOTLAYER_RESOLVE(g_create_adapter, CreateAdapterFn, "WintunCreateAdapter");
    ROOTLAYER_RESOLVE(g_open_adapter, OpenAdapterFn, "WintunOpenAdapter");
    ROOTLAYER_RESOLVE(g_close_adapter, CloseAdapterFn, "WintunCloseAdapter");
    ROOTLAYER_RESOLVE(g_start_session, StartSessionFn, "WintunStartSession");
    ROOTLAYER_RESOLVE(g_end_session, EndSessionFn, "WintunEndSession");
    ROOTLAYER_RESOLVE(g_read_wait_event, GetReadWaitEventFn, "WintunGetReadWaitEvent");
    ROOTLAYER_RESOLVE(g_receive_packet, ReceivePacketFn, "WintunReceivePacket");
    ROOTLAYER_RESOLVE(g_release_receive_packet, ReleaseReceivePacketFn,
                      "WintunReleaseReceivePacket");
    ROOTLAYER_RESOLVE(g_allocate_send_packet, AllocateSendPacketFn, "WintunAllocateSendPacket");
    ROOTLAYER_RESOLVE(g_send_packet, SendPacketFn, "WintunSendPacket");

    return g_create_adapter != NULL && g_open_adapter != NULL && g_close_adapter != NULL &&
           g_start_session != NULL && g_end_session != NULL && g_read_wait_event != NULL &&
           g_receive_packet != NULL && g_release_receive_packet != NULL &&
           g_allocate_send_packet != NULL && g_send_packet != NULL;
}

#undef ROOTLAYER_RESOLVE

}  // namespace

std::string error_text() {
    if (!g_error.empty()) {
        return g_error;
    }
    DWORD code = GetLastError();
    char buffer[512];
    DWORD length = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), NULL);
    std::string text = length > 0 ? std::string(buffer, length) : std::string();
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
        text.pop_back();
    }
    return std::to_string((unsigned long)code) + (text.empty() ? "" : " " + text);
}

bool available() {
    if (g_module != NULL) {
        return true;
    }

    // Side-by-side deployment: build/bin/<Client|Server>/wintun.dll.
    std::string directory = exe_dir();
    if (!directory.empty()) {
        std::string path = directory + "\\wintun.dll";
        g_module = LoadLibraryExA(path.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (g_module == NULL) {
        g_module = LoadLibraryA("wintun.dll");
    }
    if (g_module == NULL) {
        g_error = "wintun.dll could not be loaded: " + error_text();
        return false;
    }
    if (!resolve()) {
        FreeLibrary(g_module);
        g_module = NULL;
        g_error = "wintun.dll does not export the expected functions";
        return false;
    }
    return true;
}

bool create_adapter(const std::string& name, const std::string& tunnel_type,
                    const GUID* requested_guid) {
    if (!available()) {
        return false;
    }
    if (g_adapter != NULL) {
        return true;
    }

    std::wstring wide_name = widen(name);
    std::wstring wide_type = widen(tunnel_type);
    if (wide_name.empty() || wide_type.empty()) {
        g_error = "adapter name could not be converted";
        return false;
    }

    // Create first: an adapter created here is removed again by close(), so a
    // stopped tunnel leaves no disabled adapter behind.
    g_adapter = g_create_adapter(wide_name.c_str(), wide_type.c_str(), requested_guid);
    if (g_adapter == NULL) {
        // A previous process may have left one behind (crash): reuse it.
        g_adapter = g_open_adapter(wide_name.c_str());
    }
    if (g_adapter == NULL) {
        g_error = "adapter \"" + name + "\" could not be created: " + error_text();
        return false;
    }
    return true;
}

bool start_session() {
    if (g_adapter == NULL) {
        g_error = "session requested before the adapter exists";
        return false;
    }
    if (g_session != NULL) {
        return true;
    }
    g_session = g_start_session(g_adapter, kRingCapacity);
    if (g_session == NULL) {
        g_error = "packet session could not be started: " + error_text();
        return false;
    }
    return true;
}

bool is_open() {
    return g_session != NULL;
}

int read_packet(char* buffer, int max_size, int timeout_ms) {
    if (g_session == NULL || buffer == NULL || max_size <= 0) {
        return -1;
    }

    DWORD size = 0;
    BYTE* packet = g_receive_packet(g_session, &size);
    if (packet == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_NO_MORE_ITEMS) {
            // The ring is empty: sleep on the session's event instead of
            // spinning. A timeout lets the caller notice a shutdown.
            if (WaitForSingleObject(g_read_wait_event(g_session), (DWORD)timeout_ms) !=
                WAIT_OBJECT_0) {
                return 0;
            }
            packet = g_receive_packet(g_session, &size);
            if (packet == NULL) {
                DWORD retry_error = GetLastError();
                if (retry_error == ERROR_NO_MORE_ITEMS) {
                    return 0;
                }
                g_error = "packet read failed: " + error_text();
                return -1;
            }
        } else {
            // ERROR_HANDLE_EOF: the adapter is terminating.
            g_error = "packet read failed: " + error_text();
            return -1;
        }
    }

    int copied = (int)size;
    if (copied > max_size) {
        copied = max_size;
    }
    memcpy(buffer, packet, (size_t)copied);
    g_release_receive_packet(g_session, packet);
    return copied;
}

bool write_packet(const char* data, int len) {
    if (g_session == NULL || data == NULL || len <= 0) {
        return false;
    }

    BYTE* packet = g_allocate_send_packet(g_session, (DWORD)len);
    if (packet == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_BUFFER_OVERFLOW) {
            // Ring full: drop like a congested interface instead of failing.
            return true;
        }
        g_error = "packet write failed: " + error_text();
        return false;
    }
    memcpy(packet, data, (size_t)len);
    g_send_packet(g_session, packet);
    return true;
}

void close() {
    if (g_session != NULL) {
        g_end_session(g_session);
        g_session = NULL;
    }
    if (g_adapter != NULL) {
        // Removes the adapter when it was created by this process.
        g_close_adapter(g_adapter);
        g_adapter = NULL;
    }
}

}  // namespace netdev
