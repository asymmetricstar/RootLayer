// service/winservice.cpp
//
// Install / remove / host a Windows service for the RootLayer executables.
// The service is registered with the executable itself as binary path plus
// "--service run", so there is only one file to deploy and no wrapper script.
#include "service/winservice.h"

#include <shellapi.h>

#include <io.h>

#include <cstdio>
#include <string>
#include <vector>

namespace winservice {
namespace {

SERVICE_STATUS_HANDLE g_status_handle = NULL;
SERVICE_STATUS g_status;
const Config* g_config = NULL;
bool g_as_service = false;

std::string exe_path() {
    char buffer[MAX_PATH * 4];
    DWORD length = GetModuleFileNameA(NULL, buffer, sizeof(buffer));
    if (length == 0 || length == sizeof(buffer)) {
        return std::string();
    }
    return std::string(buffer, length);
}

std::string exe_dir() {
    std::string path = exe_path();
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return ".";
    }
    return path.substr(0, pos);
}

std::string error_text(DWORD code) {
    return std::to_string((unsigned long)code);
}

// argc/argv are unreliable here (the client is a GUI subsystem binary), so the
// command line is split from the real one.
std::vector<std::string> command_line_args() {
    std::vector<std::string> args;
    int count = 0;
    LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wide == NULL) {
        return args;
    }
    for (int i = 0; i < count; ++i) {
        int needed = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, NULL, 0, NULL, NULL);
        if (needed <= 1) {
            args.push_back(std::string());
            continue;
        }
        std::string text(needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, &text[0], needed, NULL, NULL);
        text.resize(needed - 1);
        args.push_back(text);
    }
    LocalFree(wide);
    return args;
}

// "--service start" and "--service=start" are both accepted.
bool find_service_flag(const std::vector<std::string>& args, std::string& action, bool& found) {
    found = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg.size() < 9 || lstrcmpiA(arg.substr(0, 9).c_str(), "--service") != 0) {
            continue;
        }
        found = true;
        if (arg.size() == 9) {
            action = (i + 1 < args.size()) ? args[i + 1] : std::string();
        } else if (arg[9] == '=') {
            action = arg.substr(10);
        } else {
            action.clear();
        }
        return true;
    }
    return false;
}

// A GUI subsystem binary has no console. Attach to the shell that launched the
// command so "start"/"stop" can report what happened.
void prepare_console() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD type = (out == NULL || out == INVALID_HANDLE_VALUE) ? FILE_TYPE_UNKNOWN
                                                             : GetFileType(out);
    if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE || type == FILE_TYPE_CHAR) {
        return;
    }
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
}

void report(const std::string& message, bool is_error) {
    FILE* stream = is_error ? stderr : stdout;
    fprintf(stream, "%s\n", message.c_str());
    fflush(stream);
    // No usable console (started from a shortcut or the Explorer): a message
    // box is the only feedback the user would get.
    if (GetConsoleWindow() == NULL) {
        MessageBoxA(NULL, message.c_str(), "RootLayer Service",
                    MB_OK | (is_error ? MB_ICONERROR : MB_ICONINFORMATION) | MB_SETFOREGROUND);
    }
}

// The SCM starts the process without a console, so the program's own output
// goes to a log file next to the executable.
void redirect_output(const Config& config) {
    std::string log_path = exe_dir() + "\\" + config.name + "-service.log";
    FILE* log = fopen(log_path.c_str(), "a");
    if (log == NULL) {
        return;
    }
    _dup2(_fileno(log), _fileno(stdout));
    _dup2(_fileno(log), _fileno(stderr));
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

DWORD WINAPI service_control(DWORD control, DWORD event_type, LPVOID data, LPVOID context);

void set_state(DWORD state, DWORD controls, DWORD wait_hint) {
    if (g_status_handle == NULL) {
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = controls;
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = 0;
    g_status.dwWaitHint = wait_hint;
    SetServiceStatus(g_status_handle, &g_status);
}

VOID WINAPI service_main_impl(DWORD argc, LPSTR* argv) {
    (void)argc;
    (void)argv;

    // Only here is the process really the service: a manual "--service run"
    // keeps the console so it can report why the SCM connection failed.
    redirect_output(*g_config);

    g_status_handle = RegisterServiceCtrlHandlerExA(g_config->name, service_control, NULL);
    if (g_status_handle == NULL) {
        return;
    }
    set_state(SERVICE_START_PENDING, 0, 3000);
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0);

    int exit_code = g_config->run_app();

    set_state(SERVICE_STOPPED, 0, 0);
    g_status.dwWin32ExitCode = (DWORD)exit_code;
    SetServiceStatus(g_status_handle, &g_status);
}

DWORD WINAPI service_control(DWORD control, DWORD event_type, LPVOID data, LPVOID context) {
    (void)event_type;
    (void)data;
    (void)context;

    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        set_state(SERVICE_STOP_PENDING, 0, 5000);
        if (g_config != NULL && g_config->on_stop != NULL) {
            // Called synchronously: a stop has to persist pending writes before
            // the process disappears.
            g_config->on_stop();
        }
        set_state(SERVICE_STOPPED, 0, 0);
        // The accept / tunnel loops are blocked in socket calls and cannot be
        // unwound from here, so the process ends once the state is reported.
        ExitProcess(0);
    } else if (control == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_status_handle, &g_status);
    }
    return NO_ERROR;
}

int run(const Config& config) {
    g_config = &config;
    g_as_service = true;

    // The SCM starts services in System32; the ini files, databases and the
    // TAP/resource lookups all live next to the executable.
    std::string directory = exe_dir();
    if (!directory.empty()) {
        SetCurrentDirectoryA(directory.c_str());
    }

    SERVICE_TABLE_ENTRYA table[] = {
        {(LPSTR)config.name, (LPSERVICE_MAIN_FUNCTIONA)service_main_impl},
        {NULL, NULL},
    };

    if (!StartServiceCtrlDispatcherA(table)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            report("\"--service run\" only works when the service control manager starts "
                   "the program. Use \"--service start\" to install and start the service.",
                   true);
        } else {
            report("Service dispatcher failed (error " + error_text(error) + ").", true);
        }
        g_as_service = false;
        return 1;
    }
    return 0;
}

bool wait_for_state(SC_HANDLE service, DWORD wanted, DWORD timeout_ms) {
    SERVICE_STATUS status;
    DWORD waited = 0;
    for (;;) {
        if (!QueryServiceStatus(service, &status)) {
            return false;
        }
        if (status.dwCurrentState == wanted) {
            return true;
        }
        if (waited >= timeout_ms) {
            return false;
        }
        Sleep(200);
        waited += 200;
    }
}

std::string state_name(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED: return "stopped";
        case SERVICE_START_PENDING: return "start pending";
        case SERVICE_STOP_PENDING: return "stop pending";
        case SERVICE_RUNNING: return "running";
        case SERVICE_CONTINUE_PENDING: return "continue pending";
        case SERVICE_PAUSE_PENDING: return "pause pending";
        case SERVICE_PAUSED: return "paused";
        default: return "unknown";
    }
}

int install(const Config& config) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (scm == NULL) {
        report("The service manager could not be opened (error " + error_text(GetLastError()) +
                   "). Run this command as administrator.",
               true);
        return 1;
    }

    const std::string program = exe_path();
    if (program.empty()) {
        report("The path of this executable could not be determined.", true);
        CloseServiceHandle(scm);
        return 1;
    }
    const std::string binary = "\"" + program + "\" --service run";

    SC_HANDLE service = CreateServiceA(
        scm, config.name, config.display_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,             // starts at boot without a login
        SERVICE_ERROR_NORMAL,
        binary.c_str(),
        NULL,                           // no load-order group
        NULL,                           // no tag
        NULL,                           // no dependencies
        NULL,                           // LocalSystem
        NULL);

    bool created = service != NULL;
    if (service == NULL && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceA(scm, config.name, SERVICE_ALL_ACCESS);
        if (service != NULL) {
            // The service already exists: point it at this executable (the
            // folder may have moved) and keep automatic start.
            ChangeServiceConfigA(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, binary.c_str(), NULL, NULL, NULL,
                                 NULL, NULL, config.display_name);
        }
    }
    if (service == NULL) {
        report("The service \"" + std::string(config.name) + "\" could not be created (error " +
                   error_text(GetLastError()) + ").",
               true);
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_DESCRIPTIONA description;
    description.lpDescription = (LPSTR)config.description;
    ChangeServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, &description);

    // Delayed start: the TAP adapter and the network are ready by then, so the
    // boot is not delayed and the first start does not race the network stack.
    SERVICE_DELAYED_AUTO_START_INFO delayed;
    delayed.fDelayedAutostart = TRUE;
    ChangeServiceConfig2A(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

    // Restart on crash so the tunnel comes back without user interaction.
    SC_ACTION actions[3];
    for (int i = 0; i < 3; ++i) {
        actions[i].Type = SC_ACTION_RESTART;
        actions[i].Delay = 5000;
    }
    SERVICE_FAILURE_ACTIONSA failure;
    failure.dwResetPeriod = 86400;
    failure.lpRebootMsg = NULL;
    failure.lpCommand = NULL;
    failure.cActions = 3;
    failure.lpsaActions = actions;
    ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);

    std::string result = std::string(config.name) + (created ? " installed" : " updated") +
                         " (automatic start at boot) in \"" + program + "\".";

    if (!StartServiceA(service, 0, NULL)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            result += "\nThe service is already running.";
        } else {
            result += "\nThe service was installed but could not be started (error " +
                      error_text(error) + ").";
        }
    } else if (wait_for_state(service, SERVICE_RUNNING, 15000)) {
        result += "\nThe service is running.";
    } else {
        result += "\nThe service was started; the SCM is still reporting a pending state.";
    }

    result += "\nLog: " + exe_dir() + "\\" + config.name + "-service.log";

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    report(result, false);
    return 0;
}

int uninstall(const Config& config) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        report("The service manager could not be opened (error " + error_text(GetLastError()) +
                   "). Run this command as administrator.",
               true);
        return 1;
    }

    SC_HANDLE service = OpenServiceA(scm, config.name,
                                     SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_START |
                                         DELETE);
    if (service == NULL) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            report("The service \"" + std::string(config.name) + "\" is not installed.", false);
            return 0;
        }
        report("The service \"" + std::string(config.name) + "\" could not be opened (error " +
                   error_text(error) + ").",
               true);
        return 1;
    }

    std::string result = std::string(config.name);
    SERVICE_STATUS status;
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        result += " stopped";
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
            result += " was not running";
        } else {
            result += " could not be stopped (error " + error_text(error) + ")";
        }
    }

    if (!wait_for_state(service, SERVICE_STOPPED, 20000)) {
        result += "; it is still stopping, the SCM deletes it when it has finished";
    }

    bool deleted = DeleteService(service) != FALSE;
    if (!deleted && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE) {
        deleted = true;  // a previous stop already queued the removal
    }
    if (deleted) {
        result += " and removed.";
    } else {
        result += " but could not be removed (error " + error_text(GetLastError()) + ").";
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    report(result, !deleted);
    return deleted ? 0 : 1;
}

int query(const Config& config) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        report("The service manager could not be opened (error " + error_text(GetLastError()) +
                   "). Run this command as administrator.",
               true);
        return 1;
    }
    SC_HANDLE service = OpenServiceA(scm, config.name, SERVICE_QUERY_STATUS);
    if (service == NULL) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            report("The service \"" + std::string(config.name) + "\" is not installed.", false);
            return 0;
        }
        report("The service could not be opened (error " + error_text(error) + ").", true);
        return 1;
    }

    SERVICE_STATUS status;
    std::string result;
    if (QueryServiceStatus(service, &status)) {
        result = std::string(config.name) + ": " + state_name(status.dwCurrentState);
    } else {
        result = "The service state could not be read (error " + error_text(GetLastError()) + ").";
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    report(result, false);
    return 0;
}

void usage(const Config& config) {
    report(std::string("Usage: ") + config.name +
               ".exe --service <start|stop|status>\n"
               "  start   install the service for automatic start at boot and start it\n"
               "  stop    stop the service and delete it\n"
               "  status  show the current service state",
           false);
}

}  // namespace

bool requested() {
    std::string action;
    bool found = false;
    find_service_flag(command_line_args(), action, found);
    return found;
}

bool running_as_service() {
    return g_as_service;
}

int handle(const Config& config) {
    std::string action;
    bool found = false;
    find_service_flag(command_line_args(), action, found);
    if (!found) {
        return 1;
    }

    g_config = &config;

    if (lstrcmpiA(action.c_str(), "run") == 0) {
        return run(config);
    }

    prepare_console();

    if (lstrcmpiA(action.c_str(), "start") == 0) {
        return install(config);
    }
    if (lstrcmpiA(action.c_str(), "stop") == 0) {
        return uninstall(config);
    }
    if (lstrcmpiA(action.c_str(), "status") == 0) {
        return query(config);
    }

    usage(config);
    return 1;
}

}  // namespace winservice
