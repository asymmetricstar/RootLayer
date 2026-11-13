// client/ui/panel.cpp - small dark Win32 status panel.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "shared_state.h"
#include "ui/panel.h"

// ------------------------------------------------------------ Status panel
//
// Small dark window with the essentials of the connection: assigned IP,
// uptime of the control channel and the ping to the gateway the server
// reported. A left click on the
// tray icon shows and hides it; the X only hides it too - the tunnel keeps
// running until Exit is picked in the tray menu.

HWND panel_hwnd = NULL;
bool panel_visible = false;
bool panel_close_hover = false;
HFONT panel_title_font = NULL;
HFONT panel_label_font = NULL;
HFONT panel_value_font = NULL;

std::mutex panel_mutex;
std::string panel_ip;
std::string panel_ping_target;
std::atomic<long long> panel_connected_since(0);  // unix seconds, 0 = offline
std::atomic<int> panel_ping_ms(-1);               // -1 = no answer yet
std::atomic<int> panel_zone_status(0);            // 0 = checking, 1 = ok, 2 = down

static const int PANEL_W = 300;
static const int PANEL_H = 170;
static const int PANEL_TITLE_H = 34;

static const COLORREF PANEL_BG = RGB(30, 30, 32);
static const COLORREF PANEL_TITLE_CLR = RGB(235, 235, 238);
static const COLORREF PANEL_LABEL_CLR = RGB(150, 150, 158);
static const COLORREF PANEL_VALUE_ON = RGB(120, 205, 140);
static const COLORREF PANEL_VALUE_OFF = RGB(122, 122, 130);
static const COLORREF PANEL_VALUE_WARN = RGB(220, 180, 80);
static const COLORREF PANEL_LINE = RGB(58, 58, 62);
static const COLORREF PANEL_BORDER = RGB(70, 70, 76);
static const COLORREF PANEL_HOVER = RGB(52, 52, 56);

static bool point_in(const RECT& rc, int x, int y) {
    return x >= rc.left && x < rc.right && y >= rc.top && y < rc.bottom;
}

static RECT panel_close_rect(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    RECT close_rc = {rc.right - 36, 4, rc.right - 8, PANEL_TITLE_H - 4};
    return close_rc;
}

// Called from the connection loop: the panel follows the control channel.
std::string panel_ping_target_value() {
    std::lock_guard<std::mutex> lock(panel_mutex);
    return panel_ping_target.empty() ? signaling_server_ip : panel_ping_target;
}

void panel_set_connected(bool connected, const std::string& ip) {
    {
        std::lock_guard<std::mutex> lock(panel_mutex);
        panel_ip = connected ? ip : "";
        panel_ping_target.clear();
        if (connected) {
            // Server-provided gateway only; without one there is no tunnel-side
            // address to measure.
            panel_ping_target = gateway_ip;
        }
    }
    panel_connected_since.store(connected ? (long long)std::time(NULL) : 0);
    panel_ping_ms.store(-1);
    if (panel_hwnd != NULL) {
        InvalidateRect(panel_hwnd, NULL, FALSE);
    }
}

static int ping_once(const std::string& target, DWORD timeout_ms) {
    DWORD address = inet_addr(target.c_str());
    if (address == INADDR_NONE || address == INADDR_ANY) {
        return -1;
    }

    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        return -1;
    }

    // The reply buffer has to hold the ICMP_ECHO_REPLY header plus the payload.
    char payload[] = "p2p";
    char reply[sizeof(ICMP_ECHO_REPLY) + 8] = {0};
    int result = -1;
    if (IcmpSendEcho(icmp, address, payload, sizeof(payload) - 1, NULL, reply, sizeof(reply), timeout_ms) != 0) {
        ICMP_ECHO_REPLY* echo = reinterpret_cast<ICMP_ECHO_REPLY*>(reply);
        result = (int)echo->RoundTripTime;
    }
    IcmpCloseHandle(icmp);
    return result;
}

// Round trip to the server's DNS responder over the tunnel. ICMP is usually
// filtered on the server's tunnel interface, while its DNS service always
// answers, so this is the measurement the panel falls back to.
static int dns_rtt_once(const std::string& server_ip, int timeout_ms) {
    DWORD address = inet_addr(server_ip.c_str());
    if (address == INADDR_NONE || address == INADDR_ANY) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    sockaddr_in target;
    ZeroMemory(&target, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    target.sin_addr.s_addr = address;

    // Minimal A query for a single label: any answer (even NXDOMAIN) proves the
    // tunnel carries a packet to the server's DNS server and back.
    const char label[] = "rootlayer-probe";
    unsigned char query[12 + 1 + sizeof(label) - 1 + 4] = {0};
    const unsigned short id = (unsigned short)(GetTickCount() & 0xFFFF);
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)(id & 0xFF);
    query[2] = 0x01;  // recursion desired
    query[5] = 0x01;  // one question
    size_t offset = 12;
    query[offset++] = (unsigned char)(sizeof(label) - 1);
    memcpy(query + offset, label, sizeof(label) - 1);
    offset += sizeof(label) - 1;
    query[offset++] = 0x00;  // end of name
    query[offset++] = 0x00;  // type A
    query[offset++] = 0x01;
    query[offset++] = 0x00;  // class IN
    query[offset++] = 0x01;

    const DWORD started = GetTickCount();
    if (sendto(sock, (const char*)query, (int)offset, 0, (sockaddr*)&target, sizeof(target)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int result = -1;
    if (select(0, &read_set, NULL, NULL, &tv) > 0) {
        char reply[512];
        if (recv(sock, reply, sizeof(reply), 0) > 0) {
            result = (int)(GetTickCount() - started);
            if (result < 0) {
                result = 0;
            }
        }
    }
    closesocket(sock);
    return result;
}

// Measures the ping in the background so the panel never blocks the UI.
void panel_worker_thread() {
    for (;;) {
        sleep_or_shutdown(2000);
        if (g_shutdown) {
            break;
        }

        int ping = -1;
        if (panel_connected_since.load() > 0) {
            std::string target;
            {
                std::lock_guard<std::mutex> lock(panel_mutex);
                // Re-read the server-reported gateway on every tick: it can
                // arrive after the panel was told the client is online.
                panel_ping_target = gateway_ip;
                target = panel_ping_target;
            }
            if (!target.empty()) {
                ping = ping_once(target, 1000);
            }
            if (ping < 0 && !target.empty()) {
                // The server's tunnel address usually ignores ICMP; its DNS
                // responder always answers, so measure that path instead.
                const int dns_ms = dns_rtt_once(target, 1000);
                if (dns_ms >= 0) {
                    ping = dns_ms;
                }
            }
            if (ping < 0 && !signaling_server_ip.empty() && signaling_server_ip != target) {
                // Still nothing over the tunnel: measure the server's physical
                // address so the card is not left empty.
                target = signaling_server_ip;
                ping = ping_once(target, 1000);
            }
            {
                std::lock_guard<std::mutex> lock(panel_mutex);
                panel_ping_target = target;
            }
        }

        panel_ping_ms.store(ping);
        if (panel_hwnd != NULL) {
            InvalidateRect(panel_hwnd, NULL, FALSE);
        }
    }
}

static std::wstring panel_format_uptime() {
    long long since = panel_connected_since.load();
    if (since <= 0) {
        return L"\x2014";  // em dash
    }

    long long seconds = (long long)std::time(NULL) - since;
    if (seconds < 0) {
        seconds = 0;
    }

    wchar_t buffer[32];
    swprintf(buffer, 32, L"%02lld:%02lld:%02lld",
             seconds / 3600, (seconds / 60) % 60, seconds % 60);
    return buffer;
}

static void panel_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc;
    GetClientRect(hwnd, &rc);

    // Paint off screen first: the window has no background brush, so a direct
    // paint would flicker on every timer tick.
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bitmap = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
    HGDIOBJ old_bitmap = SelectObject(mem, bitmap);

    HBRUSH background = CreateSolidBrush(PANEL_BG);
    FillRect(mem, &rc, background);
    DeleteObject(background);
    SetBkMode(mem, TRANSPARENT);

    // Title bar.
    HGDIOBJ old_font = SelectObject(mem, panel_title_font);
    SetTextColor(mem, PANEL_TITLE_CLR);
    RECT title_rc = {16, 0, rc.right - 44, PANEL_TITLE_H};
    DrawTextW(mem, L"RootLayer", -1, &title_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    RECT close_rc = panel_close_rect(hwnd);
    if (panel_close_hover) {
        HBRUSH hover = CreateSolidBrush(PANEL_HOVER);
        FillRect(mem, &close_rc, hover);
        DeleteObject(hover);
    }
    SetTextColor(mem, panel_close_hover ? PANEL_TITLE_CLR : RGB(170, 170, 175));
    DrawTextW(mem, L"\x00D7", -1, &close_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // Separator under the title.
    HPEN line_pen = CreatePen(PS_SOLID, 1, PANEL_LINE);
    HGDIOBJ old_pen = SelectObject(mem, line_pen);
    MoveToEx(mem, 14, PANEL_TITLE_H, NULL);
    LineTo(mem, rc.right - 14, PANEL_TITLE_H);

    // Values.
    bool online = panel_connected_since.load() > 0;
    bool peer_ok = false;
    {
        std::lock_guard<std::mutex> lock(tunnel_mutex);
        peer_ok = peer_valid;
    }

    std::wstring values[4];
    {
        std::lock_guard<std::mutex> lock(panel_mutex);
        values[0] = panel_ip.empty() ? L"\x2014" : widen(panel_ip);
    }
    values[1] = panel_format_uptime();

    int ping = panel_ping_ms.load();
    values[2] = (ping < 0) ? L"\x2014" : std::to_wstring(ping) + L" ms";

    std::wstring tunnel_text;
    COLORREF tunnel_color = PANEL_VALUE_OFF;
    if (!online) {
        tunnel_text = L"Offline";
        tunnel_color = PANEL_VALUE_OFF;
    } else if (!peer_ok) {
        tunnel_text = L"Offline";
        tunnel_color = PANEL_VALUE_WARN;
    } else if (ping < 0) {
        tunnel_text = L"Degraded";
        tunnel_color = PANEL_VALUE_WARN;
    } else {
        tunnel_text = L"Online";
        tunnel_color = PANEL_VALUE_ON;
    }
    values[3] = tunnel_text;

    const wchar_t* labels[4] = {L"IP address", L"Uptime", L"Ping", L"Tunneling"};
    int row_top = PANEL_TITLE_H + 8;
    int row_height = 30;

    for (int i = 0; i < 4; ++i) {
        RECT label_rc = {16, row_top + i * row_height, 140, row_top + (i + 1) * row_height};
        DrawTextW(mem, labels[i], -1, &label_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        SelectObject(mem, panel_value_font);
        if (i == 3) {
            SetTextColor(mem, tunnel_color);
        } else {
            SetTextColor(mem, online ? PANEL_VALUE_ON : PANEL_VALUE_OFF);
        }
        RECT value_rc = {120, row_top + i * row_height, rc.right - 16, row_top + (i + 1) * row_height};
        DrawTextW(mem, values[i].c_str(), -1, &value_rc,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(mem, panel_label_font);
    }

    // Thin border around the rounded shape.
    HPEN border_pen = CreatePen(PS_SOLID, 1, PANEL_BORDER);
    SelectObject(mem, border_pen);
    SelectObject(mem, GetStockObject(NULL_BRUSH));
    RoundRect(mem, 0, 0, rc.right - 1, rc.bottom - 1, 16, 16);

    BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);

    SelectObject(mem, old_font);
    SelectObject(mem, old_pen);
    SelectObject(mem, old_bitmap);
    DeleteObject(line_pen);
    DeleteObject(border_pen);
    DeleteObject(bitmap);
    DeleteDC(mem);

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK panel_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_PAINT:
            panel_paint(hwnd);
            return 0;

        case WM_ERASEBKGND:
            return 1;  // painted in WM_PAINT

        case WM_TIMER:
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case WM_NCHITTEST: {
            POINT pt = {(int)(short)LOWORD(lparam), (int)(short)HIWORD(lparam)};
            ScreenToClient(hwnd, &pt);
            if (point_in(panel_close_rect(hwnd), pt.x, pt.y)) {
                return HTCLIENT;
            }
            // The title bar drags the window; the borderless style has no
            // other way to move it.
            return (pt.y < PANEL_TITLE_H) ? HTCAPTION : HTCLIENT;
        }

        case WM_MOUSEMOVE: {
            int x = (int)(short)LOWORD(lparam);
            int y = (int)(short)HIWORD(lparam);
            bool hover = point_in(panel_close_rect(hwnd), x, y);
            if (hover != panel_close_hover) {
                panel_close_hover = hover;
                RECT close_rc = panel_close_rect(hwnd);
                InvalidateRect(hwnd, &close_rc, FALSE);
            }
            return 0;
        }

        case WM_LBUTTONUP: {
            int x = (int)(short)LOWORD(lparam);
            int y = (int)(short)HIWORD(lparam);
            if (point_in(panel_close_rect(hwnd), x, y)) {
                panel_visible = false;
                ShowWindow(hwnd, SW_HIDE);
            }
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

void status_panel_toggle() {
    if (panel_hwnd == NULL) {
        return;
    }
    panel_visible = !panel_visible;
    ShowWindow(panel_hwnd, panel_visible ? SW_SHOWNOACTIVATE : SW_HIDE);
}

void create_status_panel() {
    panel_title_font = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    panel_label_font = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    panel_value_font = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = panel_wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"P2PStatusPanel";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    RECT work_area;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
    int x = work_area.right - PANEL_W - 20;
    int y = work_area.bottom - PANEL_H - 20;

    HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, L"RootLayer", WS_POPUP,
                                x, y, PANEL_W, PANEL_H, NULL, NULL, wc.hInstance, NULL);
    if (hwnd == NULL) {
        std::cerr << "Warning: the status panel could not be created." << std::endl;
        return;
    }

    // Rounded corners: the region is owned by the window afterwards.
    HRGN region = CreateRoundRectRgn(0, 0, PANEL_W + 1, PANEL_H + 1, 18, 18);
    SetWindowRgn(hwnd, region, TRUE);

    SetTimer(hwnd, 1, 1000, NULL);

    panel_hwnd = hwnd;
    panel_visible = true;
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    UpdateWindow(hwnd);
}
