// console/core/options.cpp
#include "core/options.h"

#include "core/text.h"

namespace {

const char* kServerFlag = "--server";
const char* kPortFlag = "--port";
const char* kTimeoutFlag = "--timeout";

bool is_flag(const std::string& value) {
    return value.size() > 1 && value[0] == '-';
}

}  // namespace

Options parse_options(int argc, char** argv) {
    Options options;
    load_ini_defaults(options.config);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        // Options are read only before the command: the first word that is not
        // an option starts the command, and everything after it belongs to that
        // command (--ttl, --out, ... are parsed by the command itself).
        if (!is_flag(arg)) {
            for (int j = i; j < argc; ++j) {
                options.command.push_back(argv[j]);
            }
            break;
        }

        if (arg == "--help" || arg == "-h") {
            options.help = true;
            continue;
        }
        if (arg == "--version" || arg == "-v") {
            options.version = true;
            continue;
        }

        if (arg == kServerFlag || arg == kPortFlag || arg == kTimeoutFlag) {
            if (i + 1 >= argc || is_flag(argv[i + 1])) {
                options.config_error = true;
                options.config_error_text = arg + " needs a value";
                return options;
            }
            const std::string value = argv[++i];

            if (arg == kServerFlag) {
                options.config.server = value;
                continue;
            }

            int number = 0;
            if (!parse_int(value, &number)) {
                options.config_error = true;
                options.config_error_text = arg + " must be a number";
                return options;
            }
            if (arg == kPortFlag) {
                if (number <= 0 || number > 65535) {
                    options.config_error = true;
                    options.config_error_text = "--port must be 1..65535";
                    return options;
                }
                options.config.port = number;
            } else {
                if (number < 100 || number > 60000) {
                    options.config_error = true;
                    options.config_error_text = "--timeout must be 100..60000 ms";
                    return options;
                }
                options.config.timeout_ms = number;
            }
            continue;
        }

        options.config_error = true;
        options.config_error_text = "unknown option " + arg;
        return options;
    }

    return options;
}
