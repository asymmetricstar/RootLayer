// server/db/store.cpp - client_ips SQLite store.
//
// Collision units for statically assigned addresses:
//   * db_open()            repairs duplicate mappings of legacy files and
//                          installs a UNIQUE index on ip as a hard backstop;
//   * db_save_ip()         claims an address in memory and refuses to take
//                          an address another identity already owns;
//   * db_taken_ips()       one-shot snapshot used to screen candidates in
//                          memory (no per-candidate SQL round trip);
//   * db_prune_stale_rows() drops mappings outside the usable pool.
//
// Write protection: db_save_ip() only validates and records the intent; the
// row write goes through the write-behind queue (db/write_queue.h), which
// commits it when the database is free. Reads (db_lookup_ip, db_ip_taken,
// db_taken_ips) merge the in-memory intent, so callers always see the
// newest mapping, flushed or not.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "db/store.h"
#include "db/write_queue.h"

#include <map>

namespace {

// Newest claims that are not on disk yet. Both maps are guarded by db_mutex
// (the same lock the flusher holds while it commits), which keeps the
// in-memory view and the database snapshot consistent.
std::map<std::string, std::string> g_pending_claims;    // identity -> ip
std::map<std::string, std::string> g_pending_owner_by_ip;  // ip -> identity

bool store_retryable() {
    int code = sqlite3_errcode(client_db) & 0xff;
    return code == SQLITE_BUSY || code == SQLITE_LOCKED;
}

// Assumes db_mutex is held. Owner of ip in the database file (the pending
// intents are checked separately, so an external writer is never masked by
// this process's own queued claim).
std::string db_ip_owner_locked(const std::string& ip) {
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT identity FROM client_ips WHERE ip = ?1",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    std::string owner;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) owner = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);
    return owner;
}

// Executed by the flusher under db_mutex. Writes the CURRENT in-memory claim
// for identity, so a newer claim that replaced the queued one is never
// overwritten by a stale value. Returns false only when the database is
// busy/locked (retry); conflicts are resolved (dropped) and reported as
// success so the entry does not spin forever.
bool flush_claim_locked(const std::string& identity) {
    auto pending = g_pending_claims.find(identity);
    if (pending == g_pending_claims.end()) {
        return true;  // already persisted or superseded
    }
    const std::string ip = pending->second;

    // Re-check ownership at write time: an external writer may have taken
    // the address while this claim waited in memory.
    std::string owner = db_ip_owner_locked(ip);
    if (!owner.empty() && owner != identity) {
        std::cerr << "IP conflict refused on flush: " << ip << " belongs to "
                  << owner << ", not giving it to " << identity << std::endl;
        return true;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db,
                           "INSERT INTO client_ips (identity, ip, created_at) VALUES (?1, ?2, ?3) "
                           "ON CONFLICT(identity) DO UPDATE SET ip = excluded.ip",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return !store_retryable();
    }
    sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)std::time(NULL));
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (store_retryable()) {
            return false;
        }
        // Only reachable when an external writer owns the address; the
        // UNIQUE index keeps both sides honest. Drop, it cannot succeed by
        // retrying.
        std::cerr << "IP claim failed on flush for " << identity << " on " << ip
                  << ": " << sqlite3_errmsg(client_db) << std::endl;
    }
    return true;
}

// Called by the queue after COMMIT, under db_mutex: the row is really on
// disk, so the in-memory copy can go.
void on_client_committed(const std::string& identity) {
    auto pending = g_pending_claims.find(identity);
    if (pending == g_pending_claims.end()) {
        return;
    }
    auto reverse = g_pending_owner_by_ip.find(pending->second);
    if (reverse != g_pending_owner_by_ip.end() && reverse->second == identity) {
        g_pending_owner_by_ip.erase(reverse);
    }
    g_pending_claims.erase(pending);
}

WriteQueue g_write_queue;

}  // namespace

// Assumes db_mutex is held. Older builds created client_ips without the
// UNIQUE constraint on ip, so such a file can map one address to several
// identities. Keep the oldest mapping (created_at, then insertion order) and
// release the duplicates - those identities simply receive a fresh free
// address on their next connect. Runs before the unique index is created,
// because the index cannot be built while duplicates exist.
static void repair_duplicate_ips_locked() {
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db,
                           "SELECT ip, COUNT(*) FROM client_ips GROUP BY ip HAVING COUNT(*) > 1",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }

    struct Conflict {
        std::string ip;
        std::string keeper;
        std::vector<std::string> losers;
    };
    std::vector<Conflict> conflicts;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* ip_text = sqlite3_column_text(stmt, 0);
        if (ip_text == NULL) continue;

        Conflict c;
        c.ip = reinterpret_cast<const char*>(ip_text);

        sqlite3_stmt* owner_stmt = NULL;
        if (sqlite3_prepare_v2(client_db,
                               "SELECT identity FROM client_ips WHERE ip = ?1 "
                               "ORDER BY created_at ASC, rowid ASC",
                               -1, &owner_stmt, NULL) != SQLITE_OK) {
            continue;
        }
        sqlite3_bind_text(owner_stmt, 1, c.ip.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(owner_stmt) == SQLITE_ROW) {
            const unsigned char* id = sqlite3_column_text(owner_stmt, 0);
            if (id == NULL) continue;
            std::string identity = reinterpret_cast<const char*>(id);
            if (identity.empty()) continue;
            if (c.keeper.empty()) {
                c.keeper = identity;
            } else {
                c.losers.push_back(identity);
            }
        }
        sqlite3_finalize(owner_stmt);

        if (!c.keeper.empty() && !c.losers.empty()) {
            conflicts.push_back(c);
        }
    }
    sqlite3_finalize(stmt);

    for (const auto& c : conflicts) {
        for (const auto& loser : c.losers) {
            sqlite3_stmt* del = NULL;
            if (sqlite3_prepare_v2(client_db, "DELETE FROM client_ips WHERE identity = ?1",
                                   -1, &del, NULL) != SQLITE_OK) {
                continue;
            }
            sqlite3_bind_text(del, 1, loser.c_str(), -1, SQLITE_TRANSIENT);
            bool ok = (sqlite3_step(del) == SQLITE_DONE);
            sqlite3_finalize(del);
            if (ok) {
                std::cerr << "IP conflict repaired: " << c.ip << " was mapped to both "
                          << c.keeper << " and " << loser << "; kept " << c.keeper
                          << ", released " << loser << std::endl;
            }
        }
    }
}

bool db_open(const std::string& exe_dir) {
    std::string db_path = exe_dir + "\\server.db";
    if (sqlite3_open(db_path.c_str(), &client_db) != SQLITE_OK) {
        std::cerr << "Could not open " << db_path << ": "
                  << (client_db ? sqlite3_errmsg(client_db) : "?") << std::endl;
        if (client_db != NULL) {
            sqlite3_close(client_db);
            client_db = NULL;
        }
        return false;
    }

    sqlite3_busy_timeout(client_db, 5000);

    // Attach the write-behind buffer now, but let the caller start its
    // flusher after the repair work below (and after the startup steps).
    // Until start() the queue writes synchronously.
    g_write_queue.setup(client_db, &db_mutex, on_client_committed, 4096);

    std::lock_guard<std::mutex> lock(db_mutex);

    const char* schema =
        "CREATE TABLE IF NOT EXISTS client_ips ("
        " identity TEXT PRIMARY KEY,"
        " ip TEXT NOT NULL UNIQUE,"
        " created_at INTEGER NOT NULL);";

    char* error = NULL;
    if (sqlite3_exec(client_db, schema, NULL, NULL, &error) != SQLITE_OK) {
        std::cerr << "Could not create client_ips table: " << (error ? error : "?") << std::endl;
        sqlite3_free(error);
        sqlite3_close(client_db);
        client_db = NULL;
        return false;
    }

    // Collision integrity: heal legacy duplicates first, then make the
    // database itself reject a second owner for the same address. From here
    // on no code path - not even an INSERT that skips the checks - can map
    // one address to two identities.
    repair_duplicate_ips_locked();

    error = NULL;
    if (sqlite3_exec(client_db,
                     "CREATE UNIQUE INDEX IF NOT EXISTS idx_client_ips_ip ON client_ips(ip)",
                     NULL, NULL, &error) != SQLITE_OK) {
        std::cerr << "Could not enforce unique address index: "
                  << (error ? error : "?") << std::endl;
        sqlite3_free(error);
    }
    return true;
}

void db_start_write_buffer() {
    if (client_db == NULL) return;
    g_write_queue.start("identity database");
}

std::string db_write_stats() {
    return g_write_queue.stats();
}

std::string db_lookup_ip(const std::string& identity) {
    if (identity.empty()) {
        return "";
    }
    std::lock_guard<std::mutex> lock(db_mutex);

    // The in-memory intent is newer than the file.
    auto pending = g_pending_claims.find(identity);
    if (pending != g_pending_claims.end()) {
        return pending->second;
    }
    if (client_db == NULL) {
        return "";
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT ip FROM client_ips WHERE identity = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
    std::string ip;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) {
            ip = reinterpret_cast<const char*>(text);
        }
    }
    sqlite3_finalize(stmt);
    return ip;
}
bool db_ip_taken(const std::string& ip) {
    if (ip.empty()) return false;
    std::lock_guard<std::mutex> lock(db_mutex);

    if (g_pending_owner_by_ip.find(ip) != g_pending_owner_by_ip.end()) {
        return true;
    }
    if (client_db == NULL) {
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT 1 FROM client_ips WHERE ip = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    bool taken = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return taken;
}

// Claim ip for identity. The ownership check runs in one critical section
// against both the pending intents and the file, so a concurrent writer can
// never slip a second owner in between. The row write is deferred to the
// write-behind queue: the connection path returns as soon as the intent is
// recorded, and the flusher commits it when the database is free.
bool db_save_ip(const std::string& identity, const std::string& ip) {
    if (client_db == NULL || identity.empty() || ip.empty()) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(db_mutex);

        auto pending_owner = g_pending_owner_by_ip.find(ip);
        if (pending_owner != g_pending_owner_by_ip.end() && pending_owner->second != identity) {
            std::cerr << "IP conflict refused: " << ip << " belongs to "
                      << pending_owner->second << ", not giving it to " << identity << std::endl;
            return false;
        }

        std::string owner = db_ip_owner_locked(ip);
        if (!owner.empty() && owner != identity) {
            std::cerr << "IP conflict refused: " << ip << " belongs to " << owner
                      << ", not giving it to " << identity << std::endl;
            return false;
        }

        // Moving to a new address frees the identity's previous pending one.
        auto old = g_pending_claims.find(identity);
        if (old != g_pending_claims.end() && old->second != ip) {
            auto reverse = g_pending_owner_by_ip.find(old->second);
            if (reverse != g_pending_owner_by_ip.end() && reverse->second == identity) {
                g_pending_owner_by_ip.erase(reverse);
            }
        }
        g_pending_claims[identity] = ip;
        g_pending_owner_by_ip[ip] = identity;
    }

    g_write_queue.enqueue(identity, [identity] { return flush_claim_locked(identity); });
    return true;
}

std::unordered_set<std::string> db_taken_ips() {
    std::unordered_set<std::string> taken;
    std::lock_guard<std::mutex> lock(db_mutex);

    // Everything already promised in memory, plus the file's rows. A row
    // that a pending claim is about to move keeps its old address reserved
    // until the flush lands - conservative, never double-books.
    for (const auto& entry : g_pending_claims) {
        taken.insert(entry.second);
    }
    if (client_db == NULL) {
        return taken;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT ip FROM client_ips", -1, &stmt, NULL) != SQLITE_OK) {
        return taken;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) {
            taken.insert(reinterpret_cast<const char*>(text));
        }
    }
    sqlite3_finalize(stmt);
    return taken;
}

void db_prune_stale_rows() {
    if (client_db == NULL) return;
    std::lock_guard<std::mutex> lock(db_mutex);
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(client_db, "SELECT identity, ip FROM client_ips", -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    std::vector<std::string> stale;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 1);
        std::string ip = (text != NULL) ? reinterpret_cast<const char*>(text) : "";
        uint32_t u = string_to_ip(ip);
        if (u < virtual_ip_first_client || u > virtual_ip_last || u == virtual_ip_server) {
            const unsigned char* id = sqlite3_column_text(stmt, 0);
            if (id != NULL) stale.push_back(reinterpret_cast<const char*>(id));
        }
    }
    sqlite3_finalize(stmt);
    for (const auto& id : stale) {
        sqlite3_stmt* del = NULL;
        if (sqlite3_prepare_v2(client_db, "DELETE FROM client_ips WHERE identity = ?1", -1, &del, NULL) == SQLITE_OK) {
            sqlite3_bind_text(del, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(del);
            sqlite3_finalize(del);
            std::cerr << "Pruned stale identity row: " << id << std::endl;
        }
    }
}
