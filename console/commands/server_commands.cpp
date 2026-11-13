// console/commands/server_commands.cpp
//
// info - one screen with everything the console needs to know about the
// server it is talking to.
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

class InfoCommand : public Command {
public:
    std::string name() const override { return "info"; }
    std::string usage() const override { return "info"; }
    std::string summary() const override { return "server summary (records, TLDs, CA)"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN INFO");
        if (!result.ok) {
            return report_failure(result);
        }

        const std::vector<std::vector<std::string>> rows = {
            {"server", ctx.config.server + ":" + std::to_string(ctx.config.port)},
            {"domains", token_value(result.response, "DOMAINS")},
            {"tlds", token_value(result.response, "TLDS")},
            {"gateway", token_value(result.response, "GATEWAY")},
            {"certificates", token_value(result.response, "CERTS")},
            {"ca fingerprint", token_value(result.response, "CA")},
        };
        print_table({"FIELD", "VALUE"}, rows);
        return kExitOk;
    }
};

}  // namespace

void register_server_commands() {
    command_registry().push_back(new InfoCommand());
}
