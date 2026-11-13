
// client/core/json.h
//
// One JSON object per line on stdout (headless mode / test automation).
#ifndef ROOTLAYER_JSON_H
#define ROOTLAYER_JSON_H

#include "core/win_headers.h"

std::string json_string_field(const std::string& key, const std::string& value);
std::string json_number_field(const std::string& key, long long value);
void json_event(const std::string& event, const std::string& fields = "");

#endif  // ROOTLAYER_JSON_H
