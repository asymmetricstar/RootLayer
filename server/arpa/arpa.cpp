// server/arpa/arpa.cpp - TLD name service (domain.db).
//
// Write protection: name registrations and settings are first recorded in
// memory and then committed by the shared write-behind queue
// (db/write_queue.h) when the database is free. Lookups (arpa_get,
// arpa_lookup, arpa_domain_count) merge the in-memory intents, so DNS and
// ARPA_QUERY answers always reflect the newest state.
#include "core/win_headers.h"
#include "core/globals.h"
#include "db/write_queue.h"
#include "arpa/arpa.h"

#include <map>

namespace {

// How a pending domain record reaches the database.
const int kModeUpsert = 0;       // client registration: create or update
const int kModeInsertOrIgnore = 1;  // root reservation: never touch an existing row

struct PendingDomain {
    std::string identity;
    std::string ip;
    int ttl = 60;
    std::string info;     // free-form description stored in domain_info column
    bool is_new = false;  // row did not exist yet -> counts toward the total
    int mode = kModeUpsert;
};

// Guarded by arpa_mutex (the same lock the flusher holds while committing).
std::map<std::string, PendingDomain> g_pending_domains;
long long g_pending_new_domains = 0;
std::map<std::string, std::string> g_pending_settings;

WriteQueue g_write_queue;

bool arpa_retryable() {
    int code = sqlite3_errcode(arpa_db) & 0xff;
    return code == SQLITE_BUSY || code == SQLITE_LOCKED;
}

// Assumes arpa_mutex is held.
bool db_domain_exists_locked(const std::string& name) {
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT 1 FROM domain_list WHERE name = ?1",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

// Assumes arpa_mutex is held.
std::string db_domain_owner_locked(const std::string& name) {
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT identity FROM domain_list WHERE name = ?1",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::string owner;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) owner = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);
    return owner;
}

// Newest value for a normalized name: pending intent first, then the file.
// Assumes arpa_mutex is held.
std::string lookup_locked(const std::string& name, std::string* owner_out,
                          int* ttl_out, std::string* info_out) {
    std::string ip, owner, info;
    int ttl = 60;

    auto pending = g_pending_domains.find(name);
    if (pending != g_pending_domains.end()) {
        ip = pending->second.ip;
        owner = pending->second.identity;
        ttl = pending->second.ttl;
        info = pending->second.info;
    } else if (arpa_db != NULL) {
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(arpa_db,
                               "SELECT identity, ip, ttl, domain_info FROM domain_list "
                               "WHERE name = ?1",
                               -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* o = sqlite3_column_text(stmt, 0);
                const unsigned char* i = sqlite3_column_text(stmt, 1);
                const unsigned char* inf = sqlite3_column_text(stmt, 3);
                if (o != NULL) owner = reinterpret_cast<const char*>(o);
                if (i != NULL) ip = reinterpret_cast<const char*>(i);
                if (inf != NULL) info = reinterpret_cast<const char*>(inf);
                ttl = sqlite3_column_int(stmt, 2);
            }
            sqlite3_finalize(stmt);
        }
    }

    if (owner_out != NULL) *owner_out = owner;
    if (ttl_out != NULL) *ttl_out = ttl;
    if (info_out != NULL) *info_out = info;
    return ip;
}

// Executed by the flusher under arpa_mutex. Writes the CURRENT pending
// record for the name, so a newer registration replaces the queued one.
bool flush_domain_locked(const std::string& name) {
    auto pending = g_pending_domains.find(name);
    if (pending == g_pending_domains.end()) {
        return true;  // already persisted or superseded
    }
    const PendingDomain rec = pending->second;

    std::string sql;
    if (rec.mode == kModeInsertOrIgnore) {
        sql = "INSERT OR IGNORE INTO domain_list "
              "(name, identity, ip, ttl, domain_info, created_at, updated_at) "
              "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
    } else {
        // Update only while the row still belongs to the same identity: a
        // domain taken by somebody else meanwhile is never overwritten.
        sql = "INSERT INTO domain_list "
              "(name, identity, ip, ttl, domain_info, created_at, updated_at) "
              "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
              "ON CONFLICT(name) DO UPDATE SET identity = excluded.identity, "
              "ip = excluded.ip, ttl = excluded.ttl, "
              "domain_info = excluded.domain_info, updated_at = excluded.updated_at "
              "WHERE domain_list.identity = excluded.identity";
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
        return !arpa_retryable();
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.identity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, rec.ttl);
    sqlite3_bind_text(stmt, 5, rec.info.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)std::time(NULL));
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)std::time(NULL));

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(arpa_db);
    std::string error = (rc == SQLITE_DONE) ? "" : sqlite3_errmsg(arpa_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (arpa_retryable()) {
            return false;  // database busy/locked: retry later
        }
        std::cerr << "Domain write failed for " << name << ": " << error << std::endl;
        return true;  // constraint error: retrying cannot succeed
    }
    if (rec.mode == kModeUpsert && changes == 0) {
        std::cerr << "Domain write skipped: " << name
                  << " belongs to another identity" << std::endl;
    }
    return true;
}

// Called by the queue after COMMIT, under arpa_mutex: the rows are on disk,
// so the in-memory copies can go and the new-row counter catches up.
void on_arpa_committed(const std::string& key) {
    if (key.compare(0, 7, "domain:") == 0) {
        auto pending = g_pending_domains.find(key.substr(7));
        if (pending != g_pending_domains.end()) {
            if (pending->second.is_new && g_pending_new_domains > 0) {
                --g_pending_new_domains;
            }
            g_pending_domains.erase(pending);
        }
        return;
    }
    if (key.compare(0, 8, "setting:") == 0) {
        g_pending_settings.erase(key.substr(8));
    }
}

}  // namespace

std::string arpa_db_get_setting(const std::string& key) {
    if (arpa_db == NULL || key.empty()) return "";
    std::lock_guard<std::mutex> lock(arpa_mutex);

    auto pending = g_pending_settings.find(key);
    if (pending != g_pending_settings.end()) {
        return pending->second;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT value FROM settings WHERE key = ?1", -1, &stmt, NULL) != SQLITE_OK) {
        return "";
    }
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    std::string value;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text != NULL) value = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);
    return value;
}

// Set a string setting in domain.db settings table. Recorded in memory and
// committed by the write-behind queue; reads see it immediately.
bool arpa_db_set_setting(const std::string& key, const std::string& value) {
    if (arpa_db == NULL || key.empty()) return false;
    {
        std::lock_guard<std::mutex> lock(arpa_mutex);
        g_pending_settings[key] = value;
    }

    g_write_queue.enqueue("setting:" + key, [key] {
        auto pending = g_pending_settings.find(key);
        if (pending == g_pending_settings.end()) {
            return true;  // already persisted or superseded
        }
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(arpa_db, "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                               -1, &stmt, NULL) != SQLITE_OK) {
            if (arpa_retryable()) return false;
            std::cerr << "Setting write failed for " << key << ": "
                      << sqlite3_errmsg(arpa_db) << std::endl;
            return true;
        }
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, pending->second.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || !arpa_retryable();
    });
    return true;
}
bool arpa_open(const std::string& exe_dir) {
    std::string db_path = exe_dir + "\\domain.db";
    if (sqlite3_open(db_path.c_str(), &arpa_db) != SQLITE_OK) {
        std::cerr << "Could not open " << db_path << ": "
                  << (arpa_db ? sqlite3_errmsg(arpa_db) : "?") << std::endl;
        if (arpa_db != NULL) { sqlite3_close(arpa_db); arpa_db = NULL; }
        return false;
    }
    sqlite3_busy_timeout(arpa_db, 5000);

    const char* schema =
        "CREATE TABLE IF NOT EXISTS tld_list ("
        " id INTEGER PRIMARY KEY,"
        " suffix TEXT NOT NULL UNIQUE);"
        "CREATE TABLE IF NOT EXISTS domain_list ("
        " name TEXT PRIMARY KEY,"
        " identity TEXT NOT NULL,"
        " ip TEXT NOT NULL,"
        " ttl INTEGER NOT NULL DEFAULT 60,"
        " domain_info TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS settings ("
        " key TEXT PRIMARY KEY,"
        " value TEXT NOT NULL);";

    char* error = NULL;
    if (sqlite3_exec(arpa_db, schema, NULL, NULL, &error) != SQLITE_OK) {
        std::cerr << "Could not create domain tables: " << (error ? error : "?") << std::endl;
        sqlite3_free(error);
        sqlite3_close(arpa_db);
        arpa_db = NULL;
        return false;
    }

    // Legacy databases created before this column existed: add domain_info.
    // "duplicate column name" is expected on already-migrated databases.
    if (sqlite3_exec(arpa_db,
                     "ALTER TABLE domain_list ADD COLUMN domain_info TEXT NOT NULL DEFAULT ''",
                     NULL, NULL, &error) != SQLITE_OK) {
        if (error != NULL && strstr(error, "duplicate column") == NULL) {
            std::cerr << "Could not add domain_info column: " << error << std::endl;
        }
        sqlite3_free(error);
    }

    // Load suffixes from tld_list table into arpa_suffixes set.
    // Each row is one TLD (p2p, abc, name, vpn, mesh, etc.).
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT suffix FROM tld_list", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            if (text != NULL) {
                std::string suf = reinterpret_cast<const char*>(text);
                std::string lowered;
                for (char c : suf) lowered.push_back((char)tolower((unsigned char)c));
                if (!lowered.empty()) {
                    arpa_suffixes.insert(lowered);
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // If no suffixes in database, add defaults: p2p, abc, name
    if (arpa_suffixes.empty()) {
        arpa_suffixes.insert("p2p");
        arpa_suffixes.insert("abc");
        arpa_suffixes.insert("name");
    }

    // Persist current suffix set to tld_list table (id, suffix).
    for (const auto& suf : arpa_suffixes) {
        sqlite3_stmt* ins = NULL;
        if (sqlite3_prepare_v2(arpa_db, "INSERT OR IGNORE INTO tld_list (suffix) VALUES (?1)", -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins, 1, suf.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(ins);
            sqlite3_finalize(ins);
        }
    }

    // Attach the write-behind buffer; the flusher starts later so the
    // startup reservations below keep their synchronous behavior.
    g_write_queue.setup(arpa_db, &arpa_mutex, on_arpa_committed, 4096);
    return true;
}

void arpa_start_write_buffer() {
    if (arpa_db == NULL) return;
    g_write_queue.start("name database");
}

std::string arpa_write_stats() {
    return g_write_queue.stats();
}
std::string arpa_normalize(const std::string& raw) {
    std::string value = raw;
    size_t begin = value.find_first_not_of(" \t\r\n");
    size_t end = value.find_last_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    value = value.substr(begin, end - begin + 1);

    // lowercase
    std::string lowered;
    for (char c : value) {
        lowered.push_back((char)tolower((unsigned char)c));
    }

    // strip a single trailing dot
    if (!lowered.empty() && lowered.back() == '.') {
        lowered.pop_back();
    }

    // Check if name already ends with a configured suffix (e.g. mypc.p2p, mypc.abc).
    // If not, append the first configured suffix.
    bool has_suffix = false;
    for (const auto& suf : arpa_suffixes) {
        std::string sfx_dot = "." + suf;
        if (lowered.size() >= sfx_dot.size() &&
            lowered.compare(lowered.size() - sfx_dot.size(), sfx_dot.size(), sfx_dot) == 0) {
            has_suffix = true;
            break;
        }
    }
    if (!has_suffix && !arpa_suffixes.empty()) {
        lowered += "." + *arpa_suffixes.begin();
    }

    // validate every label
    if (lowered.empty() || lowered.size() > 253) return "";
    size_t pos = 0;
    while (pos < lowered.size()) {
        size_t dot = lowered.find('.', pos);
        if (dot == std::string::npos) dot = lowered.size();
        std::string label = lowered.substr(pos, dot - pos);
        if (label.empty() || label.size() > 63) return "";
        if (label.front() == '-' || label.back() == '-') return "";
        for (char c : label) {
            if (!(isalnum((unsigned char)c) || c == '-')) return "";
        }
        pos = dot + 1;
    }

    // reserve the root label for the server itself
    std::string first_label = lowered.substr(0, lowered.find('.'));
    if (first_label == "root") {
        return "";   // handled separately by the server
    }
    return lowered;
}

std::string arpa_set(const std::string& raw_name, const std::string& identity,
                     const std::string& ip, int ttl, const std::string& info,
                     std::string* canonical_out) {
    std::string name = arpa_normalize(raw_name);
    if (name.empty()) {
        // distinguish reserved root
        std::string lowered = raw_name;
        for (char& c : lowered) c = (char)tolower((unsigned char)c);
        size_t b = lowered.find_first_not_of(" \t\r\n");
        size_t e = lowered.find_last_not_of(" \t\r\n");
        std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
        if (t == "root" || t == "root." + arpa_suffix) {
            return "reserved";
        }
        return "invalid";
    }
    if (identity.size() < 8 || identity.size() > 64) {
        return "identity_required";
    }
    if (arpa_db == NULL) {
        return "storage";
    }

    bool is_new = false;
    {
        std::lock_guard<std::mutex> lock(arpa_mutex);

        auto pending = g_pending_domains.find(name);
        std::string owner;
        if (pending != g_pending_domains.end()) {
            owner = pending->second.identity;
        } else {
            owner = db_domain_owner_locked(name);
        }

        if (!owner.empty() && owner != identity) {
            return "taken";
        }

        // A record already queued keeps its "new row" bookkeeping; a fresh
        // one is new only when the database does not have it yet.
        const bool had_pending = (pending != g_pending_domains.end());
        if (had_pending) {
            is_new = pending->second.is_new;
        } else {
            is_new = owner.empty();
        }

        PendingDomain rec;
        rec.identity = identity;
        rec.ip = ip;
        rec.ttl = ttl;
        rec.info = info;
        rec.is_new = is_new;
        rec.mode = kModeUpsert;
        g_pending_domains[name] = rec;

        if (is_new && !had_pending) {
            ++g_pending_new_domains;
        }
    }

    g_write_queue.enqueue("domain:" + name, [name] { return flush_domain_locked(name); });

    if (canonical_out != NULL) *canonical_out = name;
    return "ok";
}

std::string arpa_get(const std::string& raw_name, std::string* owner_out,
                     std::string* info_out) {
    std::string name = arpa_normalize(raw_name);
    // allow root even though normalize() rejects it
    if (name.empty()) {
        std::string lowered = raw_name;
        for (char& c : lowered) c = (char)tolower((unsigned char)c);
        size_t b = lowered.find_first_not_of(" \t\r\n");
        size_t e = lowered.find_last_not_of(" \t\r\n");
        std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
        bool is_root = (t == "root");
        for (const auto& suf : arpa_suffixes) {
            if (t == "root." + suf) { is_root = true; break; }
        }
        if (is_root && !arpa_suffixes.empty()) {
            name = "root." + *arpa_suffixes.begin();
        } else {
            return "";
        }
    }
    if (arpa_db == NULL) return "";

    std::lock_guard<std::mutex> lock(arpa_mutex);
    return lookup_locked(name, owner_out, NULL, info_out);
}

std::string arpa_lookup(const std::string& normalized_name, int* ttl_out,
                        std::string* info_out) {
    if (normalized_name.empty()) {
        if (ttl_out != NULL) *ttl_out = 60;
        return "";
    }
    if (arpa_db == NULL) {
        if (ttl_out != NULL) *ttl_out = 60;
        return "";
    }

    std::lock_guard<std::mutex> lock(arpa_mutex);
    return lookup_locked(normalized_name, NULL, ttl_out, info_out);
}

void arpa_reserve_root(const std::string& ip, int ttl) {
    if (arpa_db == NULL || ip.empty()) return;

    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(arpa_mutex);
        for (const auto& suf : arpa_suffixes) {
            std::string name = "root." + suf;
            // INSERT OR IGNORE semantics: an existing (possibly manually
            // assigned) root record stays untouched.
            if (g_pending_domains.find(name) != g_pending_domains.end()) continue;
            if (db_domain_exists_locked(name)) continue;

            PendingDomain rec;
            rec.identity = "server";
            rec.ip = ip;
            rec.ttl = ttl;
            rec.is_new = true;
            rec.mode = kModeInsertOrIgnore;
            g_pending_domains[name] = rec;
            ++g_pending_new_domains;
            names.push_back(name);
        }
    }

    for (const auto& name : names) {
        g_write_queue.enqueue("domain:" + name, [name] { return flush_domain_locked(name); });
    }
}

// Return just the domain_info text for a name (empty string when unknown).
std::string arpa_domain_info(const std::string& raw_name) {
    std::string name = arpa_normalize(raw_name);
    if (name.empty()) {
        return "";
    }
    if (arpa_db == NULL) {
        return "";
    }
    std::string info;
    std::lock_guard<std::mutex> lock(arpa_mutex);
    lookup_locked(name, NULL, NULL, &info);
    return info;
}

// ------------------------------------------------------------ admin (console)
std::vector<ArpaRecord> arpa_list(size_t limit) {
    std::vector<ArpaRecord> out;
    if (arpa_db == NULL || limit == 0) return out;

    std::lock_guard<std::mutex> lock(arpa_mutex);

    // Pending writes are the newest state, so they are listed first.
    for (const auto& entry : g_pending_domains) {
        if (out.size() >= limit) break;
        ArpaRecord rec;
        rec.name = entry.first;
        rec.identity = entry.second.identity;
        rec.ip = entry.second.ip;
        rec.info = entry.second.info;
        rec.ttl = entry.second.ttl;
        out.push_back(rec);
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db,
                           "SELECT name, identity, ip, ttl, domain_info FROM domain_list "
                           "ORDER BY name",
                           -1, &stmt, NULL) == SQLITE_OK) {
        while (out.size() < limit && sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* name_text = sqlite3_column_text(stmt, 0);
            const std::string name = name_text ? reinterpret_cast<const char*>(name_text) : "";
            bool already_listed = false;
            for (const auto& rec : out) {
                if (rec.name == name) {
                    already_listed = true;
                    break;
                }
            }
            if (already_listed) continue;

            ArpaRecord rec;
            rec.name = name;
            const unsigned char* owner = sqlite3_column_text(stmt, 1);
            const unsigned char* ip = sqlite3_column_text(stmt, 2);
            const unsigned char* info = sqlite3_column_text(stmt, 4);
            rec.identity = owner ? reinterpret_cast<const char*>(owner) : "";
            rec.ip = ip ? reinterpret_cast<const char*>(ip) : "";
            rec.info = info ? reinterpret_cast<const char*>(info) : "";
            rec.ttl = sqlite3_column_int(stmt, 3);
            out.push_back(rec);
        }
        sqlite3_finalize(stmt);
    }
    return out;
}

bool arpa_delete(const std::string& raw_name) {
    std::string name = arpa_normalize(raw_name);
    if (name.empty() || arpa_db == NULL) return false;

    std::lock_guard<std::mutex> lock(arpa_mutex);

    bool removed = false;
    auto pending = g_pending_domains.find(name);
    if (pending != g_pending_domains.end()) {
        // A row still waiting in the write buffer never reaches the file: the
        // queued flush finds nothing to write and becomes a no-op.
        if (pending->second.is_new && g_pending_new_domains > 0) {
            --g_pending_new_domains;
        }
        g_pending_domains.erase(pending);
        removed = true;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "DELETE FROM domain_list WHERE name = ?1", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(arpa_db) > 0) {
            removed = true;
        }
        sqlite3_finalize(stmt);
    }
    return removed;
}

// One TLD label: lowercase letters, digits and '-', 2..63 characters.
static std::string normalize_suffix(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        const unsigned char u = (unsigned char)c;
        if (c == '.' && out.empty()) continue;  // accept a leading dot
        if (!isalnum(u) && c != '-') continue;
        out.push_back((char)tolower(u));
    }
    while (!out.empty() && out.front() == '-') out.erase(out.begin());
    while (!out.empty() && out.back() == '-') out.pop_back();
    return out;
}

bool arpa_tld_add(const std::string& raw_suffix, std::string* canonical_out) {
    const std::string suffix = normalize_suffix(raw_suffix);
    if (suffix.size() < 2 || suffix.size() > 63 || arpa_db == NULL) return false;

    {
        std::lock_guard<std::mutex> lock(arpa_mutex);
        arpa_suffixes.insert(suffix);

        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(arpa_db, "INSERT OR IGNORE INTO tld_list (suffix) VALUES (?1)",
                               -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, suffix.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    if (canonical_out != NULL) *canonical_out = suffix;
    return true;
}

bool arpa_tld_delete(const std::string& raw_suffix) {
    const std::string suffix = normalize_suffix(raw_suffix);
    if (suffix.empty() || arpa_db == NULL) return false;

    std::lock_guard<std::mutex> lock(arpa_mutex);

    // The name service always needs one suffix: the root record and the DNS
    // apex are derived from it.
    if (arpa_suffixes.size() <= 1) return false;
    if (arpa_suffixes.erase(suffix) == 0) return false;

    // Removing the primary suffix hands the role to another one so "root" and
    // the DNS apex keep working.
    if (arpa_suffix == suffix) {
        arpa_suffix = *arpa_suffixes.begin();
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "DELETE FROM tld_list WHERE suffix = ?1", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, suffix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    return true;
}

std::vector<std::string> arpa_tld_list() {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(arpa_mutex);
    out.reserve(arpa_suffixes.size());
    for (const auto& suffix : arpa_suffixes) {
        out.push_back(suffix);
    }
    return out;
}

// Number of registered domain records (domain_list rows). The console prints
// this single figure instead of listing the domains: a deployment can hold
// hundreds of thousands of records and one line each would flood the screen.
// Rows still waiting in the write buffer are counted as well, so the number
// is correct the moment a record is registered.
long long arpa_domain_count() {
    if (arpa_db == NULL) return 0;
    std::lock_guard<std::mutex> lock(arpa_mutex);

    long long count = g_pending_new_domains;
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(arpa_db, "SELECT COUNT(*) FROM domain_list", -1, &stmt, NULL) != SQLITE_OK) {
        return count;
    }
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count += (long long)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}
