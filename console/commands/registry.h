// console/commands/registry.h
//
// One Command per verb. Each group file (name/tld/cert/server) registers its
// own commands; main() knows nothing about them.
#ifndef ROOTLAYER_CONSOLE_REGISTRY_H
#define ROOTLAYER_CONSOLE_REGISTRY_H

#include <string>
#include <vector>

#include "core/config.h"
#include "net/admin_client.h"

// Everything a command needs: the resolved settings, the client and the
// arguments that followed the command name.
struct CommandContext {
    const ConsoleConfig& config;
    AdminClient& client;
    const std::vector<std::string>& args;
};

class Command {
public:
    virtual ~Command() {}
    virtual std::string name() const = 0;     // "name add"
    virtual std::string usage() const = 0;    // "name add <name> <ip> [--ttl N]"
    virtual std::string summary() const = 0;  // one line for the help screen
    virtual int run(CommandContext& ctx) = 0;
};

std::vector<Command*>& command_registry();
Command* find_command(const std::string& name);

// Called once from main(): fills the registry from every group file.
void register_all_commands();

// Implemented by the group files.
void register_name_commands();
void register_tld_commands();
void register_cert_commands();
void register_server_commands();

void print_help();
void print_usage(const Command& command);

// Turns a failed AdminResult into a printed error and an exit code.
int report_failure(const AdminResult& result);

#endif  // ROOTLAYER_CONSOLE_REGISTRY_H
