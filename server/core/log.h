// server/core/log.h
//
// Console formatting for the server: sectioned blocks for the startup summary
// and one aligned row per client event, so the live log stays readable instead
// of printing values side by side in one long line.
#ifndef ROOTLAYER_SERVER_LOG_H
#define ROOTLAYER_SERVER_LOG_H

#include "core/win_headers.h"

namespace srvlog {

// Blank line, "== Title ====..." banner and, for client events, the column
// captions. Repeated calls with the same title only add the banner once.
void section(const std::string& title);

// "  Label          value" inside the current section.
void item(const std::string& label, const std::string& value);

// One client event row: TIME  EVENT  HW ID  VIRTUAL IP  DETAIL.
// virtual_ip may be empty ("-"), detail may be empty.
void event(const std::string& tag, const std::string& hw_id, const std::string& virtual_ip,
           const std::string& detail);

// Same columns on stderr, for refused/failed sessions.
void error(const std::string& tag, const std::string& hw_id, const std::string& virtual_ip,
           const std::string& detail);

// The column captions for the client event table.
void events_header();

}  // namespace srvlog

#endif  // ROOTLAYER_SERVER_LOG_H
