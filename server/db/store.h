// server/db/store.h
//
// client_ips SQLite store: identity -> virtual IP mappings.
//
// This module owns the collision rules for statically assigned addresses:
// an address can only ever belong to one identity, claims are atomic, and a
// legacy database with duplicate mappings is repaired at open time.
#ifndef ROOTLAYER_SERVER_DB_STORE_H
#define ROOTLAYER_SERVER_DB_STORE_H

#include "core/win_headers.h"

#include <unordered_set>

bool db_open(const std::string& exe_dir);
std::string db_lookup_ip(const std::string& identity);
bool db_ip_taken(const std::string& ip);

// Starts the write-behind flusher. Until this call every write runs
// synchronously (startup repair, unit tests keep the old behavior).
void db_start_write_buffer();

// Console diagnostics: "pending 3/4096, written 1200, retried 4".
std::string db_write_stats();

// Atomically claim ip for identity: the ownership check and the write happen
// in one critical section, and a foreign owner is never overwritten (returns
// false instead). This is the unit that prevents two identities from ending
// up with the same static address.
bool db_save_ip(const std::string& identity, const std::string& ip);

// Every address currently mapped to an identity. One query, so the allocator
// can screen candidate addresses in memory instead of issuing one SQL round
// trip per candidate.
std::unordered_set<std::string> db_taken_ips();

// Drops mappings that fell outside the usable pool (config change) or point
// at the server address itself.
void db_prune_stale_rows();

#endif  // ROOTLAYER_SERVER_DB_STORE_H
