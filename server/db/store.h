// server/db/store.h
//
// client_ips SQLite store: client key -> virtual IP mappings.
//
// The client key is the hardware id (aa:bb:cc:dd:ee:ff) for every current
// client; the legacy static identity string is only used for old clients that
// send no HWID. The SQL column is still named `identity`, so an existing
// database keeps working - the meaning of the value is the client key.
//
// This module owns the collision rules for persisted addresses:
// an address can only ever belong to one key, claims are atomic, and a
// legacy database with duplicate mappings is repaired at open time.
#ifndef ROOTLAYER_SERVER_DB_STORE_H
#define ROOTLAYER_SERVER_DB_STORE_H

#include "core/win_headers.h"

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

bool db_open(const std::string& exe_dir);
std::string db_lookup_ip(const std::string& client_key);
bool db_ip_taken(const std::string& ip);

// Starts the write-behind flusher. Until this call every write runs
// synchronously (startup repair, unit tests keep the old behavior).
void db_start_write_buffer();

// Console diagnostics: "pending 3/4096, written 1200, retried 4".
std::string db_write_stats();

// Atomically claim ip for a client key: the ownership check and the write
// happen in one critical section, and a foreign owner is never overwritten
// (returns false instead). This is the unit that prevents two clients from
// ending up with the same address.
bool db_save_ip(const std::string& client_key, const std::string& ip);

// One-time migration: moves the address owned by `old_key` (a pre-hw-id static
// identity row) onto `new_key` (the client's hardware id), so a client that is
// upgrading keeps the address it had before the switch. When `new_key` already
// owns an address the leftover old row is simply deleted. Returns true when a
// row was moved or removed.
bool db_adopt_key(const std::string& old_key, const std::string& new_key);

// Every address currently mapped to a client key. One query, so the allocator
// can screen candidate addresses in memory instead of issuing one SQL round
// trip per candidate.
std::unordered_set<std::string> db_taken_ips();

// Drops mappings that fell outside the usable pool (config change) or point
// at the server address itself.
void db_prune_stale_rows();

// Admin console: every client key -> address mapping (pending claims
// included), ordered by address, at most `limit` rows.
std::vector<std::pair<std::string, std::string>> db_list_ips(size_t limit);

// Drops one client key's address row so its next connect takes a fresh address
// from the pool. Returns the address that was released ("" when the key had
// no row). The delete is queued behind any pending claim of the same key, so
// a queued write can never resurrect the row.
std::string db_delete_ip(const std::string& client_key);

#endif  // ROOTLAYER_SERVER_DB_STORE_H
