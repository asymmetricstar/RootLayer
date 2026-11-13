// console/core/output.h
//
// All console output goes through here, so the presentation can change in one
// place without touching the commands.
#ifndef ROOTLAYER_CONSOLE_OUTPUT_H
#define ROOTLAYER_CONSOLE_OUTPUT_H

#include <string>
#include <vector>

void print_ok(const std::string& text);
void print_info(const std::string& text);
void print_warning(const std::string& text);
void print_error(const std::string& text);

// Left-aligned columns; the last column is not padded.
void print_table(const std::vector<std::string>& headers,
                 const std::vector<std::vector<std::string>>& rows);

void print_version();

#endif  // ROOTLAYER_CONSOLE_OUTPUT_H
