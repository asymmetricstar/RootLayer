// service/winservice.h
//
// Windows service wrapper shared by the server and the client executable.
//
// The same .exe is used in two roles:
//   <exe>                      normal interactive run (GUI / console)
//   <exe> --service start      installs the automatic-start service and starts it
//   <exe> --service stop       stops the service and deletes it
//   <exe> --service status     prints the current service state
//   <exe> --service run        internal: the entry point the SCM calls
//
// Both executables carry a requireAdministrator manifest, so "start"/"stop"
// raise the UAC prompt and the SCM commands need no extra prompting. The
// service itself runs as LocalSystem, which is what TAP/netsh need.
#ifndef ROOTLAYER_WINSERVICE_H
#define ROOTLAYER_WINSERVICE_H

#include <windows.h>

namespace winservice {

struct Config {
    const char* name;          // SCM service name, e.g. "RootLayerServer"
    const char* display_name;  // shown in services.msc
    const char* description;   // long description
    int (*run_app)();          // the program's normal entry body
    void (*on_stop)();         // optional: flush state before the process exits
};

// True when the command line contains "--service".
bool requested();

// Handles "--service <action>" and returns the process exit code.
// Only called when requested() is true.
int handle(const Config& config);

// True inside the process the SCM started ("--service run"). The client uses
// it to force headless mode: a service has no desktop, so no tray and no Qt.
bool running_as_service();

}  // namespace winservice

#endif  // ROOTLAYER_WINSERVICE_H
