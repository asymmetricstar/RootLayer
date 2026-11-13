// console/core/output.cpp
#include "core/output.h"

#include "version.h"  // CONSOLE_VERSION_STRING (same source as console.rc)

#include <windows.h>

#include <cstdio>
#include <iostream>

namespace {

const char* kBold = "\x1b[1m";
const char* kDim = "\x1b[2m";
const char* kGreen = "\x1b[32m";
const char* kYellow = "\x1b[33m";
const char* kRed = "\x1b[31m";
const char* kReset = "\x1b[0m";

// Colour only when the output is a console (a redirect stays clean for scripts).
bool use_colour() {
    static const bool enabled = [] {
        HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        return handle != NULL && handle != INVALID_HANDLE_VALUE &&
               GetConsoleMode(handle, &mode) != 0;
    }();
    return enabled;
}

const char* colour(const char* code) {
    return use_colour() ? code : "";
}

}  // namespace

void print_ok(const std::string& text) {
    std::cout << colour(kGreen) << "OK" << colour(kReset) << " " << text << std::endl;
}

void print_info(const std::string& text) {
    std::cout << colour(kDim) << text << colour(kReset) << std::endl;
}

void print_warning(const std::string& text) {
    std::cout << colour(kYellow) << "!" << colour(kReset) << " " << text << std::endl;
}

void print_error(const std::string& text) {
    std::cerr << colour(kRed) << "ERROR" << colour(kReset) << " " << text << std::endl;
}

void print_table(const std::vector<std::string>& headers,
                 const std::vector<std::vector<std::string>>& rows) {
    if (rows.empty()) {
        print_info("(no records)");
        return;
    }

    std::vector<size_t> widths(headers.size(), 0);
    for (size_t column = 0; column < headers.size(); ++column) {
        widths[column] = headers[column].size();
    }
    for (const auto& row : rows) {
        for (size_t column = 0; column < row.size() && column < widths.size(); ++column) {
            if (row[column].size() > widths[column]) {
                widths[column] = row[column].size();
            }
        }
    }

    std::cout << colour(kBold);
    for (size_t column = 0; column < headers.size(); ++column) {
        std::cout << headers[column];
        if (column + 1 < headers.size()) {
            std::cout << std::string(widths[column] - headers[column].size() + 2, ' ');
        }
    }
    std::cout << colour(kReset) << std::endl;

    for (const auto& row : rows) {
        for (size_t column = 0; column < row.size() && column < widths.size(); ++column) {
            std::cout << row[column];
            if (column + 1 < widths.size()) {
                std::cout << std::string(widths[column] - row[column].size() + 2, ' ');
            }
        }
        std::cout << std::endl;
    }
}

void print_version() {
    std::cout << "RootLayer console " CONSOLE_VERSION_STRING << std::endl;
}
