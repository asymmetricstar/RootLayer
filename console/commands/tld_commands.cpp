// console/commands/tld_commands.cpp
//
// tld add <suffix>
// tld del <suffix>
// tld list
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

class TldAddCommand : public Command {
public:
    std::string name() const override { return "tld add"; }
    std::string usage() const override { return "tld add <suffix>   (example: mesh)"; }
    std::string summary() const override {
        return "add a virtual TLD; clients pick it up from the server automatically";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN TLD_ADD SUFFIX:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }
        print_ok("TLD " + token_value(result.response, "TLD") + " added");
        print_info("active TLDs: " + token_value(result.response, "TLDS"));
        return kExitOk;
    }
};

class TldDelCommand : public Command {
public:
    std::string name() const override { return "tld del"; }
    std::string usage() const override { return "tld del <suffix>"; }
    std::string summary() const override { return "remove a virtual TLD (never the last one)"; }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.empty()) {
            print_usage(*this);
            return kExitUsage;
        }

        const AdminResult result = ctx.client.call("ADMIN TLD_DEL SUFFIX:" + required[0]);
        if (!result.ok) {
            return report_failure(result);
        }
        print_ok("TLD " + token_value(result.response, "TLD") + " removed");
        print_info("active TLDs: " + token_value(result.response, "TLDS"));
        return kExitOk;
    }
};

class TldListCommand : public Command {
public:
    std::string name() const override { return "tld list"; }
    std::string usage() const override { return "tld list"; }
    std::string summary() const override { return "show the virtual TLDs the server serves"; }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN TLD_LIST");
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& suffix : split(token_value(result.response, "TLDS"), ',')) {
            rows.push_back({"." + suffix});
        }
        print_table({"TLD"}, rows);
        return kExitOk;
    }
};

}  // namespace

void register_tld_commands() {
    command_registry().push_back(new TldAddCommand());
    command_registry().push_back(new TldDelCommand());
    command_registry().push_back(new TldListCommand());
}
