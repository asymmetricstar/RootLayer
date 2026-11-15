// console/commands/limit_commands.cpp
//
// limit set <virtual-ip> <up-kbps> <down-kbps>
// limit list
// limit clear <virtual-ip>
//
// The server enforces the cap on the frames it forwards in both directions
// (client -> segment and segment -> client). kbit/s, 0 lifts that direction.
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

class LimitSetCommand : public Command {
public:
    std::string name() const override { return "limit set"; }
    std::string usage() const override {
        return "limit set <virtual-ip> <up-kbps> <down-kbps>";
    }
    std::string summary() const override {
        return "cap one client's bandwidth (kbit/s, 0 = unlimited)";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.size() < 3) {
            print_usage(*this);
            return kExitUsage;
        }

        int up = 0;
        int down = 0;
        if (!parse_int(required[1], &up) || !parse_int(required[2], &down) || up < 0 ||
            down < 0) {
            print_error("up/down must be non-negative kbit/s numbers");
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN LIMIT_SET IP:" + required[0] +
                                                   " UP:" + std::to_string(up) +
                                                   " DOWN:" + std::to_string(down));
        if (!result.ok) {
            return report_failure(result);
        }

        print_ok(token_value(result.response, "KEY") + " up " +
                 token_value(result.response, "UP") + " kbit/s, down " +
                 token_value(result.response, "DOWN") + " kbit/s");
        if (token_value(result.response, "LIVE") != "1") {
            print_info("no live session on that address yet; the cap applies when it joins");
        }
        return kExitOk;
    }
};

class LimitListCommand : public Command {
public:
    std::string name() const override { return "limit list"; }
    std::string usage() const override { return "limit list"; }
    std::string summary() const override { return "list the per-client bandwidth caps"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN LIMIT_LIST");
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& record : token_records(result.response, "LIMITS")) {
            const std::vector<std::string> fields = split_fields(record);
            if (fields.size() < 3) continue;
            rows.push_back({fields[0], fields[1], fields[2]});
        }

        print_table({"VIRTUAL IP", "UP kbit/s", "DOWN kbit/s"}, rows);
        print_info(token_value(result.response, "COUNT") + " cap(s)");
        return kExitOk;
    }
};

class LimitClearCommand : public Command {
public:
    std::string name() const override { return "limit clear"; }
    std::string usage() const override { return "limit clear <virtual-ip>"; }
    std::string summary() const override { return "drop a cap, back to the server.ini default"; }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN LIMIT_CLEAR IP:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }
        print_ok("cleared " + token_value(result.response, "KEY"));
        return kExitOk;
    }
};

}  // namespace

void register_limit_commands() {
    command_registry().push_back(new LimitSetCommand());
    command_registry().push_back(new LimitListCommand());
    command_registry().push_back(new LimitClearCommand());
}
