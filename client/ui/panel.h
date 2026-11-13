
// client/ui/panel.h
//
// Small dark Win32 status panel shown on a left click on the tray icon.
#ifndef ROOTLAYER_PANEL_H
#define ROOTLAYER_PANEL_H

#include "core/win_headers.h"

// Called from the connection loop: the panel follows the control channel.
void panel_set_connected(bool connected, const std::string& ip);

// Background thread measuring the ping shown in the panel.
void panel_worker_thread();

void status_panel_toggle();
void create_status_panel();

#endif  // ROOTLAYER_PANEL_H
