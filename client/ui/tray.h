
// client/ui/tray.h
//
// Win32 notification area icon (only used when the Qt panel is NOT in charge).
#ifndef ROOTLAYER_TRAY_H
#define ROOTLAYER_TRAY_H

#include "core/win_headers.h"

// Owned by the tray thread; run_tunnel() waits for tray_hwnd to become NULL
// on exit and initializes GDI+ through gdiplus_token.
extern HWND tray_hwnd;
extern ULONG_PTR gdiplus_token;

void tray_set_state(bool connected, const std::wstring& tooltip);
void tray_set_state_utf8(bool connected, const std::string& tooltip);

// Request a clean shutdown from the tray menu (also declared in
// shared_state.h for the Qt panel).
void tray_request_exit();

void tray_thread_fn();

#endif  // ROOTLAYER_TRAY_H
