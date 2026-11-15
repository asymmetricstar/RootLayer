// console/commands/config_commands.cpp
//
// config list
// config set <key> <value>
//
// The settings that live in server.ini. The running server owns the file and
// the values, so a change is written there and, for the settings that can move
// under live sessions (message of the day, bandwidth defaults, shield limits),
// applied immediately. Ports, bind address and the subnet geometry are saved
// for the next start.
#include <string>
#include <vector>

#include "commands/registry.h"
#include "core/exit_codes.h"
#include "core/output.h"
#include "core/text.h"

namespace {

// The server sends spaces as %20 and '%' as %25 so a value with spaces (a
// message of the day, a path) stays readable across the token protocol.
std::string decode_field(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size()) {
            const std::string code = text.substr(i + 1, 2);
            if (code == "20") {
                out.push_back(' ');
                i += 2;
                continue;
            }
            if (code == "25") {
                out.push_back('%');
                i += 2;
                continue;
            }
        }
        out.push_back(text[i]);
    }
    return out;
}

class ConfigListCommand : public Command {
public:
    std::string name() const override { return "config list"; }
    std::string usage() const override { return "config list"; }
    std::string summary() const override {
        return "list server.ini settings and whether they apply live";
    }

    int run(CommandContext& ctx) override {
        const AdminResult result = ctx.client.call("ADMIN CONFIG_LIST");
        if (!result.ok) {
            return report_failure(result);
        }

        std::vector<std::vector<std::string>> rows;
        for (const auto& record : token_records(result.response, "CONFIG")) {
            const std::vector<std::string> fields = split_fields(record);
            if (fields.size() < 2) continue;
            std::string value = decode_field(fields[1]);
            if (value.empty()) value = "(unset)";
            rows.push_back({fields[0], value, fields.size() > 2 ? fields[2] : ""});
        }

        print_table({"KEY", "VALUE", "APPLIES"}, rows);
        print_info(token_value(result.response, "COUNT") + " setting(s) from " +
                   decode_field(token_value(result.response, "PATH")));
        return kExitOk;
    }
};

class ConfigSetCommand : public Command {
public:
    std::string name() const override { return "config set"; }
    std::string usage() const override { return "config set <key> <value>"; }
    std::string summary() const override {
        return "change one server.ini setting (live when possible)";
    }

    int run(CommandContext& ctx) override {
        const std::vector<std::string> required = positional_args(ctx.args);
        if (required.size() < 2) {
            print_usage(*this);
            return kExitUsage;
        }

        // Base64 keeps spaces and punctuation (a message of the day) inside the
        // token protocol.
        const std::string key = required[0];
        std::string value = required[1];
        for (size_t i = 2; i < required.size(); ++i) {
            value += " " + required[i];
        }

        const AdminResult result = ctx.client.call("ADMIN CONFIG_SET KEY:" + key +
                                                   " TEXT64:" + base64_encode(value));
        if (!result.ok) {
            const std::string code = result.error;
            if (code == "unknown_key") {
                print_error("no such setting; run console.exe config list");
            } else if (code == "bad_port") {
                print_error("a port is 1..65535");
            } else if (code == "bad_switch") {
                print_error("expected 0 or 1");
            } else if (code == "bad_prefix") {
                print_error("the prefix length is 8..30");
            } else if (code == "bad_ip") {
                print_error("expected a dotted IPv4 address");
            } else if (code == "bad_number") {
                print_error("expected a whole number (0 or more)");
            }
            return report_failure(result);
        }

        print_ok(key + " = " + decode_field(token_value(result.response, "VALUE")));
        if (token_value(result.response, "APPLY") == "restart") {
            print_info("saved to server.ini; it takes effect when the server restarts");
        } else {
            print_info("applied to the running server");
        }
        return kExitOk;
    }
};

}  // namespace

void register_config_commands() {
    command_registry().push_back(new ConfigListCommand());
    command_registry().push_back(new ConfigSetCommand());
}
