// server/core/limits.h
//
// Per-client bandwidth caps.
//
//   default   : client_upload_kbps / client_download_kbps from server.ini
//   override  : LIMIT_SET from the admin console, keyed by virtual IP or
//               hardware id, applied to live sessions immediately and to the
//               sessions that connect later (runtime only, not written to disk)
//
// Units: the admin vocabulary and server.ini use kbit/s, the buckets work in
// bytes/second.
#ifndef ROOTLAYER_SERVER_LIMITS_H
#define ROOTLAYER_SERVER_LIMITS_H

#include "core/win_headers.h"

#include <string>

struct Session;

namespace limits {

// Called once from the config loader. 0 disables the cap.
void set_defaults(double up_bytes_per_sec, double down_bytes_per_sec);
void defaults(double& up_bytes_per_sec, double& down_bytes_per_sec);

// The rate a session should start with (override for this address or hardware
// id, else the default).
void rates_for(const std::string& virtual_ip, const std::string& hw_id,
               double& up_bytes_per_sec, double& down_bytes_per_sec);

// Applies the effective rates to a newly created session.
void apply(Session& session);

// Runtime override. Returns false when no live session matched the key (the
// override is still remembered for future connections).
bool set_for(const std::string& key, double up_bytes_per_sec, double down_bytes_per_sec);
bool clear(const std::string& key);

// "key|up_kbps|down_kbps;..." for LIMIT_LIST.
std::string list_csv();

}  // namespace limits

#endif  // ROOTLAYER_SERVER_LIMITS_H
