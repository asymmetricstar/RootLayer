// console/core/text.h
//
// String helpers shared by the console. No dependency on the server code or on
// Qt: the console is a separate project and only speaks the text protocol.
#ifndef ROOTLAYER_CONSOLE_TEXT_H
#define ROOTLAYER_CONSOLE_TEXT_H

#include <string>
#include <vector>

std::string trim(const std::string& text);
std::string to_lower(std::string text);

// Splits on `separator`, trimming each part and dropping empty ones.
std::vector<std::string> split(const std::string& text, char separator);

// Splits on '|' and keeps empty fields, so table columns stay aligned.
std::vector<std::string> split_fields(const std::string& record);

bool parse_int(const std::string& text, int* out);

// Value of "KEY:value" anywhere in the answer (answers may span lines).
std::string token_value(const std::string& text, const std::string& key);

// "KEY:a;b;c" -> {"a", "b", "c"}.
std::vector<std::string> token_records(const std::string& text, const std::string& key);

// "--flag value" lookup; returns false when the flag is absent.
bool find_option(const std::vector<std::string>& args, const std::string& name, std::string& value);

// Arguments that are not "--flag value" pairs.
std::vector<std::string> positional_args(const std::vector<std::string>& args);

// Replaces the characters that would break the token protocol.
std::string sanitize_token(const std::string& text);

// Standard base64 (padding optional on input).
std::string base64_decode(const std::string& in);

// Standard base64 with padding. Used to carry values that contain spaces
// ("Jane Doe") through the token protocol.
std::string base64_encode(const std::string& in);

#endif  // ROOTLAYER_CONSOLE_TEXT_H
