// console/commands/ip_commands.cpp
//
// ip list
// ip set <hardware-id> <virtual-ip>
// ip clear <hardware-id>
//
// Fixed addresses are an admin decision: the console pins a virtual address to
// a client's hardware id, and the server hands exactly that address out on the
// client's next connect. There is no client-side setting for it, so a machine
// cannot pick its own address.
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

// Seconds since the client was last seen, as words. -1 means the server has
// no record of it since it started.
std::string last_seen_text(const std::string& raw) {
    int seconds = -1;
    if (!parse_int(raw, &seconds) || seconds < 0) {
        return "unknown";
    }
    if (seconds < 60) return std::to_string(seconds) + "s ago";
    if (seconds < 3600) return std::to_string(seconds / 60) + "m ago";
    if (seconds < 86400) return std::to_string(seconds / 3600) + "h ago";
    return std::to_string(seconds / 86400) + "d ago";
}

class IpListCommand : public Command {
public:
    std::string name() const override { return "ip list"; }
    std::string usage() const override { return "ip list"; }
    std::string summary() const override {
        return "list the fixed addresses pinned to client hardware ids";
    }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN IP_LIST");
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& record : token_records(result.response, "IPS")) {
            const std::vector<std::string> fields = split_fields(record);
            if (fields.size() < 2) continue;
            const std::string state = fields.size() > 2 ? fields[2] : "";
            // An online client is seen right now; an offline one shows when it
            // last checked in.
            const std::string seen = (state == "online")
                                         ? "now"
                                         : last_seen_text(fields.size() > 3 ? fields[3] : "-1");
            rows.push_back({fields[0], fields[1], state, seen});
        }

        print_table({"HW ID", "VIRTUAL IP", "STATE", "LAST SEEN"}, rows);
        print_info(token_value(result.response, "COUNT") + " pinned address(es)");
        return kExitOk;
    }
};

class IpSetCommand : public Command {
public:
    std::string name() const override { return "ip set"; }
    std::string usage() const override { return "ip set <hardware-id> <virtual-ip>"; }
    std::string summary() const override {
        return "pin a client's hardware id to a fixed virtual address";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.size() < 2) {
            print_usage(*this);
            return kExitUsage;
        }

        // The hardware id keeps its ':' separators: the protocol only splits on
        // spaces, so it travels unchanged.
        const AdminResult result = ctx.client.call("ADMIN IP_SET HW:" + required[0] +
                                                   " IP:" + required[1]);
        if (!result.ok) {
            const std::string code = result.error;
            if (code == "ip_in_use") {
                print_error("that address is held by another live client");
            } else if (code == "ip_taken") {
                print_error("that address already belongs to another hardware id");
            } else if (code == "ip_outside_pool") {
                print_error("the address is outside the client pool");
            } else if (code == "bad_hw_id") {
                print_error("expected a hardware id like 02-cc-3e-5c-96-14");
            } else if (code == "bad_ip") {
                print_error("expected a dotted IPv4 address");
            }
            return report_failure(result);
        }

        print_ok(token_value(result.response, "IP") + " pinned to " +
                 token_value(result.response, "HW"));
        if (token_value(result.response, "LIVE") == "1") {
            print_info("the client was online; its session was dropped so it reconnects "
                       "with the new address");
        }
        return kExitOk;
    }
};

class IpClearCommand : public Command {
public:
    std::string name() const override { return "ip clear"; }
    std::string usage() const override { return "ip clear <hardware-id>"; }
    std::string summary() const override {
        return "release a pinned address; the client gets a free one next time";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN IP_CLEAR HW:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }

        print_ok(token_value(result.response, "FREED") + " released for " +
                 token_value(result.response, "HW"));
        if (token_value(result.response, "LIVE") == "1") {
            print_info("the client was online; its session was dropped so it reconnects "
                       "with a fresh address");
        }
        return kExitOk;
    }
};

}  // namespace

void register_ip_commands() {
    command_registry().push_back(new IpListCommand());
    command_registry().push_back(new IpSetCommand());
    command_registry().push_back(new IpClearCommand());
}
