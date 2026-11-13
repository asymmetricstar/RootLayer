// console/commands/registry.cpp
#include "commands/registry.h"

#include <algorithm>
#include <iostream>

#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

std::vector<Command*>& command_registry() {
    static std::vector<Command*> commands;
    return commands;
}

Command* find_command(const std::string& name) {
    for (Command* command : command_registry()) {
        if (command->name() == name) return command;
    }
    return nullptr;
}

void register_all_commands() {
    register_name_commands();
    register_tld_commands();
    register_cert_commands();
    register_server_commands();

    std::sort(command_registry().begin(), command_registry().end(),
              [](const Command* left, const Command* right) {
                  return left->name() < right->name();
              });
}

void print_usage(const Command& command) {
    std::cout << "usage: console.exe " << command.usage() << std::endl;
    std::cout << "  " << command.summary() << std::endl;
}

void print_help() {
    std::cout << "RootLayer console - server helper for domain records and certificates\n\n";
    std::cout << "usage: console.exe [options] <command> [arguments]\n\n";
    std::cout << "options:\n";
    std::cout << "  --server IP     server address (default: server.ini local_ip, else 127.0.0.1)\n";
    std::cout << "  --port N        signaling port (default: server.ini listening_port, else 40000)\n";
    std::cout << "  --timeout MS    connect/read timeout in ms (default 5000)\n";
    std::cout << "  --help, -h      this screen\n";
    std::cout << "  --version, -v   version\n\n";

    if (command_registry().empty()) return;

    std::cout << "commands:\n";
    std::string group;
    for (Command* command : command_registry()) {
        const std::string current = split(command->name(), ' ').front();
        if (current != group) {
            group = current;
            std::cout << "\n  " << group << "\n";
        }
        std::cout << "    " << command->usage() << "\n";
        std::cout << "        " << command->summary() << "\n";
    }
    std::cout << "\nexit codes: 0 ok, 1 usage, 2 server refused, 3 not connected\n";
}

int report_failure(const AdminResult& result) {
    if (result.transport_failed) {
        print_error(result.error);
        return kExitConnection;
    }
    print_error("server refused: " + result.error);
    if (result.error == "local_only") {
        print_info("admin commands are only accepted on the server machine itself");
    }
    return kExitServer;
}
