// console/core/options.h
//
// Command line: connection flags first, then the command and its arguments.
//   console.exe [--server IP] [--port N] [--timeout MS] <command> [args]
#ifndef ROOTLAYER_CONSOLE_OPTIONS_H
#define ROOTLAYER_CONSOLE_OPTIONS_H

#include <string>
#include <vector>

#include "core/config.h"

struct Options {
    ConsoleConfig config;
    std::vector<std::string> command;  // command words + arguments
    bool help = false;
    bool version = false;
    bool config_error = false;         // a flag value could not be parsed
    std::string config_error_text;
};

Options parse_options(int argc, char** argv);

#endif  // ROOTLAYER_CONSOLE_OPTIONS_H
