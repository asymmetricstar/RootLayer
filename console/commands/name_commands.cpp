// console/commands/name_commands.cpp
//
// name add <name> <ip> [--ttl N] [--identity ID] [--info TEXT]
// name del <name>
// name list [--limit N]
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

class NameAddCommand : public Command {
public:
    std::string name() const override { return "name add"; }
    std::string usage() const override {
        return "name add <name> <ip> [--ttl N] [--identity ID] [--info TEXT]";
    }
    std::string summary() const override {
        return "register a name -> virtual IP record in domain.db";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.size() < 2) {
            print_usage(*this);
            return kExitUsage;
        }

        int ttl = 60;
        std::string value;
        if (find_option(ctx.args, "--ttl", value) && !parse_int(value, &ttl)) {
            print_error("--ttl must be a number");
            return kExitUsage;
        }

        std::string request = "ADMIN NAME_ADD NAME:" + required[0] + " IP:" + required[1] +
                              " TTL:" + std::to_string(ttl);
        if (find_option(ctx.args, "--identity", value)) {
            request += " IDENTITY:" + sanitize_token(value);
        }
        if (find_option(ctx.args, "--info", value)) {
            request += " INFO:" + sanitize_token(value);
        }

        const AdminResult result = ctx.client.call(request);
        if (!result.ok) {
            return report_failure(result);
        }

        print_ok(token_value(result.response, "NAME") + " -> " + token_value(result.response, "IP"));
        print_info("ttl " + token_value(result.response, "TTL") + ", owner " +
                   token_value(result.response, "OWNER"));
        return kExitOk;
    }
};

class NameDelCommand : public Command {
public:
    std::string name() const override { return "name del"; }
    std::string usage() const override { return "name del <name>"; }
    std::string summary() const override { return "delete a name record from domain.db"; }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN NAME_DEL NAME:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }
        print_ok("deleted " + token_value(result.response, "NAME"));
        return kExitOk;
    }
};

class NameListCommand : public Command {
public:
    std::string name() const override { return "name list"; }
    std::string usage() const override { return "name list [--limit N]"; }
    std::string summary() const override { return "list the registered name records"; }

    int run(CommandContext& ctx) override {
        int limit = 200;
        std::string value;
        if (find_option(ctx.args, "--limit", value) && !parse_int(value, &limit)) {
            print_error("--limit must be a number");
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN NAME_LIST LIMIT:" + std::to_string(limit));
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& record : token_records(result.response, "NAMES")) {
            const std::vector<std::string> fields = split_fields(record);
            if (fields.size() < 5) continue;
            rows.push_back({fields[0], fields[1], fields[2], fields[3], fields[4]});
        }

        print_table({"NAME", "IP", "TTL", "OWNER", "INFO"}, rows);
        print_info(token_value(result.response, "COUNT") + " record(s)");
        return kExitOk;
    }
};

}  // namespace

void register_name_commands() {
    command_registry().push_back(new NameAddCommand());
    command_registry().push_back(new NameDelCommand());
    command_registry().push_back(new NameListCommand());
}
