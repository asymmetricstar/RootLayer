// console/main.cpp
//
// RootLayer console: a separate program (own build, console.exe) that drives
// the running server's records - names, TLDs and certificates. All work happens
// through the server's admin protocol, so the server's write buffer, live TLD
// set and in-memory CA stay authoritative.
#include <windows.h>

#include <iostream>
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/options.h"
#include "core/output.h"
#include "core/text.h"
#include "net/admin_client.h"

namespace {

// "name add" style: the longest command name that matches the first words.
Command* resolve_command(const std::vector<std::string>& words, size_t* consumed) {
    for (size_t length = (words.size() < 2 ? words.size() : 2); length > 0; --length) {
        std::string candidate = words[0];
        for (size_t i = 1; i < length; ++i) {
            candidate += " " + words[i];
        }
        if (Command* command = find_command(candidate)) {
            *consumed = length;
            return command;
        }
    }
    return nullptr;
}

}  // namespace

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    register_all_commands();

    const Options options = parse_options(argc, argv);

    if (options.config_error) {
        print_error(options.config_error_text);
        print_info("run console.exe --help for the options");
        return kExitUsage;
    }
    if (options.help) {
        print_help();
        return kExitOk;
    }
    if (options.version) {
        print_version();
        return kExitOk;
    }
    if (options.command.empty()) {
        print_help();
        return kExitUsage;
    }

    size_t consumed = 0;
    Command* command = resolve_command(options.command, &consumed);
    if (command == nullptr) {
        print_error("unknown command: " + options.command[0]);
        print_info("run console.exe --help for the command list");
        return kExitUsage;
    }

    const std::vector<std::string> args(options.command.begin() + consumed, options.command.end());

    AdminClient client(options.config);
    CommandContext context{options.config, client, args};
    return command->run(context);
}
