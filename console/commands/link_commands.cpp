// console/commands/link_commands.cpp
//
// link / federation - server-to-server peering control and diagnostics.
//
//   link status              mode, role, primary, peers, epoch
//   link connect <ip>        make this server a replica of <ip> (live)
//   link disconnect          return to SINGLE mode with the local database
//   federation status        same summary as link status
//   federation peers         the servers this server is peered with
//
// These run on the running server through the admin protocol and are accepted
// only on the server host, like every other console command.
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

void print_status(const AdminResult& result) {
    const std::vector<std::vector<std::string>> rows = {
        {"mode", token_value(result.response, "MODE")},
        {"role", token_value(result.response, "ROLE")},
        {"primary", token_value(result.response, "LINK")},
        {"own prefix", token_value(result.response, "PREFIX")},
        {"peers", token_value(result.response, "PEERS")},
        {"locations", token_value(result.response, "LOCATIONS")},
        {"epoch", token_value(result.response, "EPOCH")},
        {"heartbeat age", token_value(result.response, "AGE")},
        {"routing", token_value(result.response, "ROUTE")},
    };
    print_table({"FIELD", "VALUE"}, rows);

    const std::string routing = token_value(result.response, "ROUTE");
    if (routing == "client") {
        print_info("peer blocks are outside this server's client subnet; each client installs "
                   "them as routes through the tunnel gateway (ROUTES token)");
    } else if (routing == "outside") {
        print_info("a peer owns an address block outside this server's subnet and clients did "
                   "not install a route; update the clients or use the same virtual_ip_prefix "
                   "on every server with a pool slice inside it");
    }

    const std::string mode = token_value(result.response, "MODE");
    if (mode == "DEGRADED") {
        print_info("primary unreachable: reads use the synced copy, global writes are refused");
    } else if (mode == "SINGLE") {
        print_info("single server mode: the local database is authoritative");
    }
}

class LinkStatusCommand : public Command {
public:
    std::string name() const override { return "link status"; }
    std::string usage() const override { return "link status"; }
    std::string summary() const override { return "federation mode, role and link state"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN LINK_STATUS");
        if (!result.ok) return report_failure(result);
        print_status(result);
        return kExitOk;
    }
};

class LinkConnectCommand : public Command {
public:
    std::string name() const override { return "link connect"; }
    std::string usage() const override { return "link connect <primary-ip> [--port N]"; }
    std::string summary() const override {
        return "link this server to a primary (live, written to server.ini)";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> positional = positional_args(ctx.args);
        if (positional.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        std::string line = "ADMIN LINK_CONNECT IP:" + positional[0];
        std::string port_text;
        if (find_option(ctx.args, "--port", port_text)) {
            int port = 0;
            if (!parse_int(port_text, &port) || port < 1 || port > 65535) {
                print_error("--port must be 1..65535");
                return kExitUsage;
            }
            line += " PORT:" + std::to_string(port);
        }

        const AdminResult result = ctx.client.call(line);
        if (!result.ok) return report_failure(result);
        print_info("link " + token_value(result.response, "LINK") + ", mode " +
                   token_value(result.response, "STATUS"));
        return kExitOk;
    }
};

class LinkDisconnectCommand : public Command {
public:
    std::string name() const override { return "link disconnect"; }
    std::string usage() const override { return "link disconnect"; }
    std::string summary() const override {
        return "close the link and keep serving from the local database";
    }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN LINK_DISCONNECT");
        if (!result.ok) return report_failure(result);
        print_info("mode " + token_value(result.response, "STATUS"));
        return kExitOk;
    }
};

class FederationStatusCommand : public Command {
public:
    std::string name() const override { return "federation status"; }
    std::string usage() const override { return "federation status"; }
    std::string summary() const override { return "federation summary (same as link status)"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN FED_STATUS");
        if (!result.ok) return report_failure(result);
        print_status(result);
        return kExitOk;
    }
};

class FederationPeersCommand : public Command {
public:
    std::string name() const override { return "federation peers"; }
    std::string usage() const override { return "federation peers"; }
    std::string summary() const override { return "servers linked to this one"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN FED_PEERS");
        if (!result.ok) return report_failure(result);

        const std::vector<std::string> records = token_records(result.response, "PEERS");
        std::vector<std::vector<std::string>> rows;
        for (const auto& record : records) {
            if (record.empty()) continue;
            std::vector<std::string> fields = split_fields(record);
            while (fields.size() < 6) fields.push_back("");
            rows.push_back({fields[0], fields[1] + ":" + fields[2], fields[3], fields[4],
                            fields[5]});
        }
        if (rows.empty()) {
            print_info("no peers linked");
            return kExitOk;
        }
        print_table({"PEER", "ENDPOINT", "PREFIX", "ROLE", "SEEN(S)"}, rows);
        return kExitOk;
    }
};

}  // namespace

void register_link_commands() {
    command_registry().push_back(new LinkStatusCommand());
    command_registry().push_back(new LinkConnectCommand());
    command_registry().push_back(new LinkDisconnectCommand());
    command_registry().push_back(new FederationStatusCommand());
    command_registry().push_back(new FederationPeersCommand());
}
