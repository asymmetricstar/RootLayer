// client/ui/tray.cpp - notification area icon + its message window.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "shared_state.h"
#include "ui/tray.h"
#include "ui/panel.h"

// ---------------------------------------------------------------- Tray icon

#define WM_TRAY_UPDATE   (WM_APP + 1)
#define WM_TRAY_CALLBACK (WM_APP + 2)
#define WM_TRAY_EXIT     (WM_APP + 3)
#define TRAY_ICON_ID 1
#define IDM_TRAY_EXIT 1001

// Resource ids from client.rc (tray icons are embedded in the executable).
#define IDR_TRAY_ONLINE  201
#define IDR_TRAY_OFFLINE 202

HWND tray_hwnd = NULL;
NOTIFYICONDATAW tray_data;
HICON tray_icon_online = NULL;
HICON tray_icon_offline = NULL;
HICON tray_icon_fallback = NULL;
bool tray_connected = false;
std::wstring tray_tooltip = L"RootLayer";
std::mutex tray_mutex;
ULONG_PTR gdiplus_token = 0;
UINT taskbar_created_message = 0;

// The shipped icons are large PNG files, so they are scaled down to the system
// tray icon size and turned into HICONs with GDI+.
HICON bitmap_to_tray_icon(Gdiplus::Bitmap* source) {
    if (source == NULL || source->GetLastStatus() != Gdiplus::Ok) {
        delete source;
        return NULL;
    }

    int size = GetSystemMetrics(SM_CXSMICON);
    if (size <= 0) {
        size = 16;
    }

    Gdiplus::Bitmap scaled(size, size, PixelFormat32bppARGB);
    Gdiplus::Graphics graphics(&scaled);
    graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    graphics.SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);
    graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
    graphics.DrawImage(source, 0, 0, size, size);

    HICON icon = NULL;
    if (scaled.GetHICON(&icon) != Gdiplus::Ok) {
        icon = NULL;
    }

    delete source;
    return icon;
}

HICON load_png_icon(const std::wstring& path) {
    return bitmap_to_tray_icon(Gdiplus::Bitmap::FromFile(path.c_str()));
}

// Icons embedded in the executable (client.rc): the tray works even when the
// program is started from a folder without the resources/ directory.
HICON load_png_icon_resource(UINT resource_id) {
    HMODULE module = GetModuleHandleW(NULL);
    HRSRC resource = FindResourceA(module, MAKEINTRESOURCE(resource_id), RT_RCDATA);
    if (resource == NULL) {
        return NULL;
    }

    DWORD size = SizeofResource(module, resource);
    const void* data = LockResource(LoadResource(module, resource));
    if (data == NULL || size == 0) {
        return NULL;
    }

    HGLOBAL global = GlobalAlloc(GMEM_MOVEABLE, size);
    if (global == NULL) {
        return NULL;
    }
    memcpy(GlobalLock(global), data, size);
    GlobalUnlock(global);

    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(global, TRUE, &stream) != S_OK) {
        GlobalFree(global);
        return NULL;
    }

    // The bitmap is deleted inside bitmap_to_tray_icon, so the stream may be
    // released right afterwards.
    HICON icon = bitmap_to_tray_icon(Gdiplus::Bitmap::FromStream(stream));
    stream->Release();
    return icon;
}

void apply_tray_state() {
    if (tray_hwnd == NULL) {
        return;
    }

    bool connected;
    std::wstring tip;
    {
        std::lock_guard<std::mutex> lock(tray_mutex);
        connected = tray_connected;
        tip = tray_tooltip;
    }

    tray_data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    if (connected && tray_icon_online != NULL) {
        tray_data.hIcon = tray_icon_online;
    } else if (!connected && tray_icon_offline != NULL) {
        tray_data.hIcon = tray_icon_offline;
    } else {
        tray_data.hIcon = tray_icon_fallback;
    }

    wcsncpy(tray_data.szTip, tip.c_str(), 127);
    tray_data.szTip[127] = L'\0';

    Shell_NotifyIconW(NIM_MODIFY, &tray_data);
}

// Safe to call from any thread.
void tray_set_state(bool connected, const std::wstring& tooltip) {
    {
        std::lock_guard<std::mutex> lock(tray_mutex);
        tray_connected = connected;
        tray_tooltip = tooltip;
    }
    if (tray_hwnd != NULL) {
        PostMessageW(tray_hwnd, WM_TRAY_UPDATE, 0, 0);
    }
}

void tray_set_state_utf8(bool connected, const std::string& tooltip) {
    tray_set_state(connected, widen(tooltip));
}

// Stop the client and remove the icon. Safe to call from the tray thread.
void tray_request_exit() {
    g_shutdown = true;

    {
        std::lock_guard<std::mutex> lock(control_mutex);
        peer_lost = true;
    }
    control_cv.notify_all();

    if (control_sock != INVALID_SOCKET) {
        shutdown(control_sock, SD_BOTH);
    }

    if (tray_hwnd != NULL) {
        PostMessageW(tray_hwnd, WM_TRAY_EXIT, 0, 0);
    }
}

// Right-click menu: current connection status (not clickable) plus Exit.
HMENU build_tray_menu(const std::wstring& status) {
    HMENU menu = CreatePopupMenu();
    if (menu == NULL) {
        return NULL;
    }

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 1, status.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Exit");
    return menu;
}

void show_tray_menu(HWND hwnd) {
    std::wstring status;
    {
        std::lock_guard<std::mutex> lock(tray_mutex);
        status = tray_tooltip;
    }

    HMENU menu = build_tray_menu(status);
    if (menu == NULL) {
        return;
    }

    POINT cursor;
    GetCursorPos(&cursor);

    // The window must be in the foreground for the menu to close when the
    // user clicks somewhere else.
    SetForegroundWindow(hwnd);
    int command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, hwnd, NULL);
    DestroyMenu(menu);
    PostMessageW(hwnd, WM_NULL, 0, 0);

    if (command == IDM_TRAY_EXIT) {
        tray_request_exit();
    }
}
LRESULT CALLBACK tray_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (msg == WM_TRAY_UPDATE) {
        apply_tray_state();
        return 0;
    }

    if (msg == WM_TRAY_CALLBACK) {
        if (LOWORD(lparam) == WM_RBUTTONUP) {
            show_tray_menu(hwnd);
        } else if (LOWORD(lparam) == WM_LBUTTONUP || LOWORD(lparam) == NIN_SELECT) {
            status_panel_toggle();  // left click shows/hides the panel
        }
        return 0;
    }

    if (msg == WM_TRAY_EXIT) {
        Shell_NotifyIconW(NIM_DELETE, &tray_data);
        DestroyWindow(hwnd);
        PostQuitMessage(0);
        return 0;
    }

    if (taskbar_created_message != 0 && msg == taskbar_created_message) {
        // Explorer restarted: the icon has to be added again.
        Shell_NotifyIconW(NIM_ADD, &tray_data);
        apply_tray_state();
        return 0;
    }

    // Parameters must be forwarded: CreateWindowExW needs the WM_NCCREATE
    // result from DefWindowProc, otherwise the window cannot be created.
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

void tray_thread_fn() {
    std::string exe_dir = get_exe_dir();
    std::wstring icon_dir = widen(exe_dir + "\\resources\\icons");

    // Icons ship in resources/icons; the embedded copies are only a fallback
    // for a stripped deployment without the resources folder.
    tray_icon_online = load_png_icon(icon_dir + L"\\tray_online_tarla_ag.png");
    if (tray_icon_online == NULL) {
        tray_icon_online = load_png_icon_resource(IDR_TRAY_ONLINE);
    }

    tray_icon_offline = load_png_icon(icon_dir + L"\\tray_offline_tarla_ag.png");
    if (tray_icon_offline == NULL) {
        tray_icon_offline = load_png_icon_resource(IDR_TRAY_OFFLINE);
    }

    tray_icon_fallback = LoadIconW(NULL, MAKEINTRESOURCEW(32512));  // IDI_APPLICATION

    if (tray_icon_online == NULL || tray_icon_offline == NULL) {
        std::cerr << "Warning: tray icons could not be loaded." << std::endl;
    }

    taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = tray_wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"P2PTunnelTrayWindow";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"RootLayer", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (hwnd == NULL) {
        std::cerr << "Failed to create the tray window. Error: " << GetLastError() << std::endl;
        return;
    }
    tray_hwnd = hwnd;

    ZeroMemory(&tray_data, sizeof(tray_data));
    tray_data.cbSize = sizeof(tray_data);
    tray_data.hWnd = hwnd;
    tray_data.uID = TRAY_ICON_ID;
    tray_data.uCallbackMessage = WM_TRAY_CALLBACK;

    apply_tray_state();
    if (!Shell_NotifyIconW(NIM_ADD, &tray_data)) {
        std::cerr << "Warning: the tray icon could not be added." << std::endl;
    }
    apply_tray_state();

    // The status panel lives in this thread as well, so its messages are
    // handled by the same message loop.
    create_status_panel();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    Shell_NotifyIconW(NIM_DELETE, &tray_data);
    tray_hwnd = NULL;
}
