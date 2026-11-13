// server/arpa/arpa.h
//
// TLD name service: domain.db name -> virtual IP records (tld_list, domain_list).
#ifndef ROOTLAYER_SERVER_ARPA_H
#define ROOTLAYER_SERVER_ARPA_H

#include "core/win_headers.h"

#include <string>
#include <vector>

std::string arpa_db_get_setting(const std::string& key);
bool arpa_db_set_setting(const std::string& key, const std::string& value);
bool arpa_open(const std::string& exe_dir);

// Starts the write-behind flusher for domain.db. Until this call every
// write runs synchronously (startup reservations keep the old behavior).
void arpa_start_write_buffer();

// Console diagnostics: "pending 3/4096, written 1200, retried 4".
std::string arpa_write_stats();

std::string arpa_normalize(const std::string& raw);
std::string arpa_set(const std::string& raw_name, const std::string& identity,
                     const std::string& ip, int ttl, const std::string& info,
                     std::string* canonical_out);
std::string arpa_get(const std::string& raw_name, std::string* owner_out,
                     std::string* info_out = NULL);

// Name -> IP for the DNS responder: newest value first (in-memory write
// buffer), then the database. `normalized_name` must already be normalized.
// `info_out`, when non-NULL, receives the domain_info column value.
std::string arpa_lookup(const std::string& normalized_name, int* ttl_out,
                        std::string* info_out = NULL);

// Return just the domain_info text for a name (empty string when unknown).
std::string arpa_domain_info(const std::string& raw_name);

void arpa_reserve_root(const std::string& ip, int ttl = 60);

// Number of registered domain records (domain_list rows). The console shows
// this count instead of enumerating the domains.
long long arpa_domain_count();

// ------------------------------------------------------------ admin (console)
// One registered name with the pending (not yet flushed) writes merged in.
struct ArpaRecord {
    std::string name;
    std::string identity;
    std::string ip;
    std::string info;
    int ttl = 60;
};

// Registered names, pending writes first, capped at `limit`.
std::vector<ArpaRecord> arpa_list(size_t limit = 200);

// Removes a name from the pending buffer and from domain.db. Returns true when
// something was actually removed.
bool arpa_delete(const std::string& raw_name);

// Runtime TLD management: the live suffix set (used by the DNS responder and
// by the TLD: field sent to clients) and the tld_list table.
bool arpa_tld_add(const std::string& raw_suffix, std::string* canonical_out = NULL);
bool arpa_tld_delete(const std::string& raw_suffix);
std::vector<std::string> arpa_tld_list();

#endif  // ROOTLAYER_SERVER_ARPA_H
