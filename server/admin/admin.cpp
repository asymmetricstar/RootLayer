// server/admin/admin.cpp
//
// One request line in, one answer line out. The vocabulary mirrors the client
// protocol ("TOKEN:value"), so the console can grow new commands without any
// change to the transport.
//
//   INFO                                      server summary
//   NAME_LIST LIMIT:200                       name|ip|ttl|owner|info records
//   NAME_ADD NAME:x IP:y [TTL:n] [IDENTITY:i] [INFO:t]
//   NAME_DEL NAME:x
//   TLD_LIST / TLD_ADD SUFFIX:x / TLD_DEL SUFFIX:x
//   CERT_ISSUE NAME:x [DAYS:n] [SUBJ_O:b64] [SUBJ_E:b64] [SUBJ_L:b64]
//              [SUBJ_S:b64] [SUBJ_C:b64]      TLS server certificate + key
//                                             (the SUBJ_* values are only
//                                             written into the certificate)
//   CERT_LIST / CERT_DEL CN:x
//   LIMIT_SET IP:10.0.0.5 UP:1024 DOWN:4096    per-client band cap in kbit/s
//   LIMIT_LIST / LIMIT_CLEAR IP:10.0.0.5       (0 lifts that direction)
//   IP_LIST [LIMIT:n]                          hardware id -> virtual address
//   IP_SET HW:aa-bb-cc-dd-ee-ff IP:10.0.0.5    pin an address to a client
//   IP_CLEAR HW:aa-bb-cc-dd-ee-ff              release it to the pool
//   CONFIG_LIST                                server.ini settings in effect
//   CONFIG_SET KEY:x VALUE:y                   change one; [TEXT64:base64]
//                                              carries a value with spaces
//
// Only the console (server machine) can pin an address: a client cannot ask
// for one, it always accepts what the server hands out.
//
// Field values never contain spaces: the console replaces them with '_' and
// this layer sanitizes again, so a record cannot break the token format.
#include "admin/admin.h"

#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "arpa/arpa.h"
#include "ca/ca.h"
#include "core/guard.h"
#include "core/limits.h"
#include "db/store.h"
#include "session/session.h"
#include "federation/federation.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

namespace {

std::string sanitize_token(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '|' || c == ':') {
            out.push_back('_');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// Strict dotted quad: inet_addr() alone accepts garbage and reports
// INADDR_NONE for both "999.1.1.1" and "255.255.255.255".
bool valid_ipv4(const std::string& text) {
    int parts = 0;
    size_t start = 0;
    while (start <= text.size()) {
        size_t dot = text.find('.', start);
        if (dot == std::string::npos) dot = text.size();
        const std::string part = text.substr(start, dot - start);
        if (part.empty() || part.size() > 3) return false;
        for (char c : part) {
            if (c < '0' || c > '9') return false;
        }
        const int value = std::atoi(part.c_str());
        if (value < 0 || value > 255) return false;
        ++parts;
        if (dot >= text.size()) break;
        start = dot + 1;
    }
    if (parts != 4) return false;
    const unsigned long address = inet_addr(text.c_str());
    return address != INADDR_NONE && address != INADDR_ANY;
}

// Canonical aa:bb:cc:dd:ee:ff hardware id. ':' and '-' are both accepted, so a
// value copied from `ip list` (which prints '-' to stay one token) can be
// pasted straight back into `ip set`.
std::string normalize_hw(const std::string& text) {
    if (text.size() != 17) return "";
    std::string out;
    out.reserve(17);
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (i % 3 == 2) {
            if (c != ':' && c != '-') return "";
            out.push_back(':');
        } else {
            if (!isxdigit((unsigned char)c)) return "";
            out.push_back((char)tolower((unsigned char)c));
        }
    }
    return out;
}

// Hardware id as it travels in an answer: '-' instead of ':' keeps it a single
// token in the space separated protocol.
std::string hw_token(const std::string& hw) {
    std::string out = hw;
    for (char& c : out) {
        if (c == ':') c = '-';
    }
    return out;
}

// ---- server.ini settings the console may change --------------------------
// `live` means the running server picks the new value up immediately; the
// others are written to server.ini and take effect on the next start (ports,
// bind address and the subnet geometry cannot move under live sessions).
struct ConfigKey {
    const char* name;
    bool live;
};

const ConfigKey kConfigKeys[] = {
    {"motd", true},
    {"client_upload_kbps", true},
    {"client_download_kbps", true},
    {"guard_max_connections", true},
    {"guard_max_pps", true},
    {"guard_min_pps", true},
    {"guard_max_budget_pps", true},
    {"guard_per_ip_pps", true},
    {"guard_connect_limit", true},
    {"guard_connect_window_sec", true},
    {"guard_source_table", true},
    {"guard_source_idle_sec", true},
    {"guard_log_interval_sec", true},
    {"link", true},
    {"link_port", false},
    {"link_primary_port", false},
    {"link_data_port", false},
    {"link_id", false},
    {"link_secret", false},
    {"link_cache_ttl_sec", true},
    {"listening_port", false},
    {"relay_port", false},
    {"local_ip", false},
    {"gateway_ip", false},
    {"virtual_ip_prefix", false},
    {"virtual_ip_mask", false},
    {"pool_start", false},
    {"pool_end", false},
    {"tap_gateway", false},
    {"nat", false},
};

const ConfigKey* find_config_key(const std::string& name) {
    for (const auto& key : kConfigKeys) {
        if (name == key.name) return &key;
    }
    return nullptr;
}

// A value that may contain spaces (message of the day, a file path) keeps them
// readable: spaces travel as %20, '%' as %25, and only the protocol
// separators are replaced. The console turns them back into text.
std::string encode_field(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == '%') {
            out += "%25";
        } else if (c == ' ') {
            out += "%20";
        } else if (c == '|' || c == ';' || c == '\t' || c == '\r' || c == '\n') {
            out.push_back('_');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// The value currently in server.ini (empty = unset).
std::string config_ini_value(const std::string& key) {
    char buffer[512] = {0};
    GetPrivateProfileStringA("Settings", key.c_str(), "", buffer, sizeof(buffer),
                             server_ini_path().c_str());
    return trim(std::string(buffer));
}

bool all_digits(const std::string& text) {
    if (text.empty()) return false;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

// Every stored value is a plain integer, so validation is per key family.
bool validate_config_value(const std::string& key, const std::string& value,
                           std::string* error) {
    if (key == "motd") {
        return true;  // free text, may be empty
    }
    if (key == "local_ip") {
        if (value.empty() || valid_ipv4(value)) return true;
        *error = "bad_ip";
        return false;
    }
    if (key == "gateway_ip" || key == "pool_start" || key == "pool_end" ||
        key == "virtual_ip_mask") {
        if (valid_ipv4(value)) return true;
        *error = "bad_ip";
        return false;
    }
    if (key == "link") {
        // Empty / false returns the server to SINGLE mode; an address links it.
        if (value.empty() || value == "0" || value == "false" || value == "off" ||
            value == "no") {
            return true;
        }
        if (valid_ipv4(value)) return true;
        *error = "bad_ip";
        return false;
    }
    if (key == "link_secret") {
        return true;  // free text, empty disables authentication
    }
    if (key == "link_id") {
        if (value.empty()) return true;
        for (char c : value) {
            if (!isalnum((unsigned char)c) && c != '-' && c != '_' && c != '.') {
                *error = "bad_id";
                return false;
            }
        }
        return value.size() <= 32 ? true : (*error = "bad_id", false);
    }
    if (key == "link_cache_ttl_sec") {
        const int ttl = all_digits(value) ? std::atoi(value.c_str()) : -1;
        if (ttl >= 1 && ttl <= 3600) return true;
        *error = "bad_number";
        return false;
    }
    if (key == "link_port" || key == "link_primary_port" || key == "link_data_port" ||
        key == "listening_port" || key == "relay_port") {
        const int port = all_digits(value) ? std::atoi(value.c_str()) : -1;
        if (port >= 1 && port <= 65535) return true;
        *error = "bad_port";
        return false;
    }
    if (key == "tap_gateway" || key == "nat") {
        if (value == "0" || value == "1") return true;
        *error = "bad_switch";
        return false;
    }
    if (key == "virtual_ip_prefix") {
        const int prefix = all_digits(value) ? std::atoi(value.c_str()) : -1;
        if (prefix >= 8 && prefix <= 30) return true;
        *error = "bad_prefix";
        return false;
    }
    if (key.rfind("client_", 0) == 0) {
        if (all_digits(value)) return true;  // kbit/s, 0 = unlimited
        *error = "bad_number";
        return false;
    }
    if (key.rfind("guard_", 0) == 0) {
        const int number = all_digits(value) ? std::atoi(value.c_str()) : -1;
        if (number >= 1) return true;
        *error = "bad_number";
        return false;
    }
    *error = "unknown_key";
    return false;
}

// Applies one guard_* value to the running shield (clamped there).
void apply_guard_setting(const std::string& key, int value) {
    guard::Settings shield = guard::settings();
    if (key == "guard_max_connections") shield.max_connections = value;
    else if (key == "guard_max_pps") shield.max_pps = value;
    else if (key == "guard_min_pps") shield.min_pps = value;
    else if (key == "guard_max_budget_pps") shield.max_budget_pps = value;
    else if (key == "guard_per_ip_pps") shield.per_ip_pps = value;
    else if (key == "guard_connect_limit") shield.connect_limit = value;
    else if (key == "guard_connect_window_sec") shield.connect_window_sec = value;
    else if (key == "guard_source_table") shield.source_table = value;
    else if (key == "guard_source_idle_sec") shield.source_idle_sec = value;
    else if (key == "guard_log_interval_sec") shield.log_interval_sec = value;
    else return;
    guard::configure(shield);
}

std::string tld_csv() {
    std::string out;
    for (const auto& suffix : arpa_tld_list()) {
        if (suffix.empty()) continue;
        if (!out.empty()) out += ",";
        out += suffix;
    }
    return out;
}

std::string ok(const std::string& body) {
    return body.empty() ? std::string("ADMIN_OK") : "ADMIN_OK " + body;
}

std::string fail(const std::string& code) {
    return "ADMIN_ERR:" + code;
}

// Splits "ADMIN NAME_ADD NAME:x ..." into the command word and the rest.
void split_request(const std::string& request, std::string& command, std::string& rest) {
    std::string body = trim(request);
    if (body.rfind("ADMIN", 0) == 0) {
        body = trim(body.substr(5));
    }
    const size_t space = body.find_first_of(" \t");
    if (space == std::string::npos) {
        command = body;
        rest.clear();
    } else {
        command = body.substr(0, space);
        rest = trim(body.substr(space + 1));
    }
}

}  // namespace

bool admin_peer_allowed(const sockaddr_in& peer) {
    if (peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        return true;
    }
    // Bound to one local address: the console reaches the server on that
    // address, so the peer address is it instead of 127.0.0.1.
    if (server_local_ip_u32 != 0 && peer.sin_addr.s_addr == htonl(server_local_ip_u32)) {
        return true;
    }
    return false;
}

bool admin_request(const std::string& request, std::string& response) {
    std::string command;
    std::string rest;
    split_request(request, command, rest);

    if (command == "INFO") {
        response = ok("VERSION:1 DOMAINS:" + std::to_string(arpa_domain_count()) +
                      " TLDS:" + tld_csv() +
                      " GATEWAY:" + server_virtual_ip() +
                      " CA:" + ca::fingerprint() +
                      " CERTS:" + std::to_string(ca::issued_subjects().size()) +
                      " " + fed::status_tokens());
        return true;
    }

    // ---- federation / link -------------------------------------------
    // All of these act on the RUNNING server only; the console still has to
    // run on the server host (admin_peer_allowed).
    if (command == "LINK_STATUS" || command == "FED_STATUS") {
        response = ok(fed::status_tokens());
        return true;
    }

    if (command == "FED_PEERS") {
        const std::string csv = fed::peers_csv();
        const size_t count =
            csv.empty() ? 0 : (size_t)std::count(csv.begin(), csv.end(), ';') + 1;
        response = ok("COUNT:" + std::to_string(count) + " PEERS:" + csv);
        return true;
    }

    if (command == "LINK_CONNECT") {
        const std::string ip = token_value(rest, "IP");
        int port = token_int(rest, "PORT", fed::link_primary_port);
        if (ip.empty()) {
            response = fail("missing_argument");
            return false;
        }
        std::string error;
        if (!fed::link_connect(ip, port, error)) {
            response = fail(error.empty() ? "link_failed" : error);
            return false;
        }
        response = ok("LINK:" + ip + ":" + std::to_string(port) + " STATUS:" +
                      fed::mode_name());
        return true;
    }

    if (command == "LINK_DISCONNECT") {
        std::string error;
        if (!fed::link_disconnect(error)) {
            response = fail(error.empty() ? "link_failed" : error);
            return false;
        }
        response = ok("STATUS:" + fed::mode_name());
        return true;
    }

    if (command == "NAME_LIST") {
        int limit = token_int(rest, "LIMIT", 200);
        if (limit <= 0 || limit > 5000) {
            limit = 200;
        }
        const std::vector<ArpaRecord> records = arpa_list((size_t)limit);
        std::string list;
        for (const auto& rec : records) {
            if (!list.empty()) list += ";";
            list += sanitize_token(rec.name) + "|" + sanitize_token(rec.ip) + "|" +
                    std::to_string(rec.ttl) + "|" + sanitize_token(rec.identity) + "|" +
                    sanitize_token(rec.info);
        }
        response = ok("COUNT:" + std::to_string(records.size()) + " NAMES:" + list);
        return true;
    }

    if (command == "NAME_ADD") {
        const std::string name = token_value(rest, "NAME");
        const std::string ip = token_value(rest, "IP");
        std::string identity = token_value(rest, "IDENTITY");
        const std::string info = sanitize_token(token_value(rest, "INFO"));
        int ttl = token_int(rest, "TTL", 60);

        if (name.empty() || ip.empty()) {
            response = fail("missing_argument");
            return false;
        }
        if (!valid_ipv4(ip)) {
            response = fail("bad_ip");
            return false;
        }
        if (ttl < 1 || ttl > 86400) {
            response = fail("bad_ttl");
            return false;
        }
        if (identity.empty()) {
            identity = "admin.server";
        }

        // A replica does not own the global name space: the write is forwarded
        // to the primary and only counts once the primary accepts it.
        if (!fed::link_target.empty()) {
            std::string error;
            std::string canonical;
            if (!fed::name_add(name, ip, ttl, identity, error, &canonical, info)) {
                response = fail(error.empty() ? "primary_refused" : error);
                return false;
            }
            response = ok("NAME:" + (canonical.empty() ? name : canonical) + " IP:" + ip +
                          " TTL:" + std::to_string(ttl) + " OWNER:" + identity +
                          " VIA:primary");
            return true;
        }

        std::string canonical;
        const std::string result = arpa_set(name, identity, ip, ttl, info, &canonical);
        if (result != "ok") {
            response = fail(result);
            return false;
        }
        // A primary owns the global name space: every replica gets the change.
        fed::announce_name(canonical, ip, ttl, identity, info);
        response = ok("NAME:" + canonical + " IP:" + ip + " TTL:" + std::to_string(ttl) +
                      " OWNER:" + identity);
        return true;
    }

    if (command == "NAME_DEL") {
        const std::string name = token_value(rest, "NAME");
        if (name.empty()) {
            response = fail("missing_argument");
            return false;
        }
        if (!fed::link_target.empty()) {
            std::string error;
            if (!fed::name_del(name, error)) {
                response = fail(error.empty() ? "primary_refused" : error);
                return false;
            }
            response = ok("NAME:" + name + " VIA:primary");
            return true;
        }
        if (!arpa_delete(name)) {
            response = fail("not_found");
            return false;
        }
        fed::announce_name_delete(name);
        response = ok("NAME:" + name);
        return true;
    }

    if (command == "TLD_LIST") {
        response = ok("TLDS:" + tld_csv());
        return true;
    }

    if (command == "TLD_ADD") {
        std::string canonical;
        if (!arpa_tld_add(token_value(rest, "SUFFIX"), &canonical)) {
            response = fail("bad_suffix");
            return false;
        }
        response = ok("TLD:" + canonical + " TLDS:" + tld_csv());
        return true;
    }

    if (command == "TLD_DEL") {
        const std::string suffix = token_value(rest, "SUFFIX");
        if (!arpa_tld_delete(suffix)) {
            response = fail("unknown_or_last_suffix");
            return false;
        }
        response = ok("TLD:" + suffix + " TLDS:" + tld_csv());
        return true;
    }

    if (command == "CERT_LIST") {
        const std::vector<std::string> subjects = ca::issued_subjects();
        std::string list;
        for (const auto& cn : subjects) {
            if (!list.empty()) list += ";";
            list += sanitize_token(cn) + "|" + sanitize_token(ca::cert_status_for(cn));
        }
        response = ok("COUNT:" + std::to_string(subjects.size()) + " CERTS:" + list);
        return true;
    }

    if (command == "CERT_ISSUE") {
        const std::string name = token_value(rest, "NAME");
        int days = token_int(rest, "DAYS", 397);
        if (name.empty()) {
            response = fail("missing_argument");
            return false;
        }
        if (days < 1 || days > 3650) {
            days = 397;
        }

        // The root server acts as a registrar (NIC): it does not need the
        // requested name to be present in the name table before issuing a
        // certificate. DNS-level prefixes such as "www." are resolved by the
        // client's own name server, so a certificate can be issued for any
        // name the operator asks for (e.g. www.root.name).
        std::vector<std::string> names;
        names.push_back(name);
        if (name.rfind("www.", 0) != 0) {
            names.push_back("www." + name);
        }

        // Optional subject fields, sent by the console for this one certificate
        // (base64 keeps spaces and non-ASCII out of the token format). Nothing
        // is stored: the values only travel into the certificate itself.
        ca::CertificateProfile profile;
        profile.name = ca::base64_decode(token_value(rest, "SUBJ_O"));
        profile.email = ca::base64_decode(token_value(rest, "SUBJ_E"));
        profile.city = ca::base64_decode(token_value(rest, "SUBJ_L"));
        profile.state = ca::base64_decode(token_value(rest, "SUBJ_S"));
        profile.country = ca::base64_decode(token_value(rest, "SUBJ_C"));

        std::string key_pem;
        const std::string cert_pem = ca::issue_server_cert(names, days, &key_pem, profile);
        if (cert_pem.empty() || key_pem.empty()) {
            response = fail("sign_failed");
            return false;
        }

        std::string body = "NAME:" + name + " DAYS:" + std::to_string(days);
        body += " CERT:" + ca::base64_encode(cert_pem);
        body += " KEY:" + ca::base64_encode(key_pem);
        const std::string ca_pem = ca::ca_cert_pem();
        if (!ca_pem.empty()) {
            body += " CACERT:" + ca::base64_encode(ca_pem);
        }
        response = ok(body);
        return true;
    }

    // Per-client bandwidth caps. IP is the virtual address the client was
    // given (it is what the logs show); UP/DOWN are kbit/s, 0 lifts the cap.
    // The override applies to a live session immediately and is remembered for
    // the next connection of that address or hardware id (runtime only).
    if (command == "LIMIT_SET") {
        // The key is the virtual IP: it has no ':' and it is what the logs
        // and the client both show.
        const std::string key = token_value(rest, "IP");
        const int up = token_int(rest, "UP", -1);
        const int down = token_int(rest, "DOWN", -1);
        if (key.empty()) {
            response = fail("missing_argument");
            return false;
        }
        if (!key.empty() && key.find('.') != std::string::npos && !valid_ipv4(key)) {
            response = fail("bad_ip");
            return false;
        }
        if (up < 0 || down < 0) {
            response = fail("bad_rate");
            return false;
        }
        const double up_bps = (double)up * 1000.0 / 8.0;
        const double down_bps = (double)down * 1000.0 / 8.0;
        const bool live = limits::set_for(key, up_bps, down_bps);
        response = ok("KEY:" + key + " UP:" + std::to_string(up) +
                      " DOWN:" + std::to_string(down) +
                      " LIVE:" + (live ? "1" : "0"));
        return true;
    }

    if (command == "LIMIT_LIST") {
        const std::string csv = limits::list_csv();
        const size_t count = csv.empty() ? 0 : (size_t)std::count(csv.begin(), csv.end(), ';') + 1;
        response = ok("COUNT:" + std::to_string(count) + " LIMITS:" + csv);
        return true;
    }

    if (command == "LIMIT_CLEAR") {
        const std::string key = token_value(rest, "IP");
        if (key.empty()) {
            response = fail("missing_argument");
            return false;
        }
        limits::clear(key);
        response = ok("KEY:" + key);
        return true;
    }

    // Fixed address management. Only this admin path can pin an address to a
    // client key; clients never request one, they take what they are given.
    if (command == "IP_LIST") {
        int limit = token_int(rest, "LIMIT", 200);
        if (limit <= 0 || limit > 5000) {
            limit = 200;
        }
        const std::vector<std::pair<std::string, std::string>> rows =
            db_list_ips((size_t)limit);
        // hw|address|online/offline|seconds since last seen (-1 = not seen
        // since this server start). The console turns the age into words, so
        // the server never has to know the console's clock.
        const long long now = (long long)std::time(NULL);
        std::string list;
        for (const auto& row : rows) {
            const bool live = ip_active(row.second);
            const long long seen = live ? now : client_last_seen(row.first);
            const long long age = (seen > 0 && now >= seen) ? now - seen : -1;
            if (!list.empty()) list += ";";
            list += hw_token(row.first) + "|" + sanitize_token(row.second) + "|" +
                    (live ? "online" : "offline") + "|" + std::to_string(age);
        }
        response = ok("COUNT:" + std::to_string(rows.size()) + " IPS:" + list);
        return true;
    }

    if (command == "IP_SET") {
        const std::string hw = normalize_hw(token_value(rest, "HW"));
        const std::string ip = token_value(rest, "IP");
        if (hw.empty()) {
            response = fail("bad_hw_id");
            return false;
        }
        if (!valid_ipv4(ip)) {
            response = fail("bad_ip");
            return false;
        }
        const uint32_t address = string_to_ip(ip);
        if (address < virtual_ip_first_client || address > virtual_ip_last ||
            address == virtual_ip_server) {
            response = fail("ip_outside_pool");
            return false;
        }
        // A live session of ANOTHER client already using it is a hard stop; a
        // live session of this same client is fine (it reconnects below).
        const std::string holder = session_key_for_ip(ip);
        if (!holder.empty() && holder != hw) {
            response = fail("ip_in_use");
            return false;
        }
        if (!db_save_ip(hw, ip)) {
            response = fail("ip_taken");
            return false;
        }
        // The client is online with another address: drop the session so it
        // comes back and takes the pinned one.
        const bool moved = retire_sessions_for_key(hw);
        response = ok("HW:" + hw_token(hw) + " IP:" + ip +
                      " LIVE:" + (moved ? "1" : "0"));
        return true;
    }

    if (command == "IP_CLEAR") {
        const std::string hw = normalize_hw(token_value(rest, "HW"));
        if (hw.empty()) {
            response = fail("bad_hw_id");
            return false;
        }
        const std::string freed = db_delete_ip(hw);
        if (freed.empty()) {
            response = fail("not_found");
            return false;
        }
        const bool moved = retire_sessions_for_key(hw);
        response = ok("HW:" + hw_token(hw) + " FREED:" + freed +
                      " LIVE:" + (moved ? "1" : "0"));
        return true;
    }

    if (command == "CERT_DEL") {
        const std::string cn = token_value(rest, "CN");
        if (cn.empty()) {
            response = fail("missing_argument");
            return false;
        }
        if (!ca::forget(cn)) {
            response = fail("unknown_certificate");
            return false;
        }
        response = ok("CN:" + cn);
        return true;
    }

    // server.ini at runtime. The file on disk is rewritten too, so the change
    // is still there after a restart.
    if (command == "CONFIG_LIST") {
        std::string list;
        for (const auto& key : kConfigKeys) {
            if (!list.empty()) list += ";";
            list += std::string(key.name) + "|" + encode_field(config_ini_value(key.name)) +
                    "|" + (key.live ? "live" : "restart");
        }
        response = ok("PATH:" + encode_field(server_ini_path()) + " COUNT:" +
                      std::to_string(sizeof(kConfigKeys) / sizeof(kConfigKeys[0])) +
                      " CONFIG:" + list);
        return true;
    }

    if (command == "CONFIG_SET") {
        const std::string key = token_value(rest, "KEY");
        std::string value = token_value(rest, "VALUE");
        const std::string encoded = token_value(rest, "TEXT64");
        if (!encoded.empty()) {
            value = ca::base64_decode(encoded);
        }
        if (key.empty()) {
            response = fail("missing_argument");
            return false;
        }
        const ConfigKey* entry = find_config_key(key);
        if (entry == nullptr) {
            response = fail("unknown_key");
            return false;
        }
        if (server_ini_path().empty()) {
            response = fail("config_unavailable");
            return false;
        }
        std::string error;
        if (!validate_config_value(key, value, &error)) {
            response = fail(error.empty() ? "bad_value" : error);
            return false;
        }
        if (WritePrivateProfileStringA("Settings", key.c_str(), value.c_str(),
                                       server_ini_path().c_str()) == 0) {
            response = fail("config_write_failed");
            return false;
        }

        // Live settings are applied to the running server right away.
        if (key == "motd") {
            set_server_motd(trim(value));
        } else if (key == "client_upload_kbps" || key == "client_download_kbps") {
            const double up = (double)std::atoi(config_ini_value("client_upload_kbps").c_str()) *
                              1000.0 / 8.0;
            const double down =
                (double)std::atoi(config_ini_value("client_download_kbps").c_str()) *
                1000.0 / 8.0;
            limits::set_defaults(up, down);
        } else if (key.rfind("guard_", 0) == 0) {
            apply_guard_setting(key, std::atoi(value.c_str()));
        } else if (key == "link") {
            // Applying `link` moves the running server between SINGLE and
            // LINKED without a restart (the console's `link connect` uses the
            // dedicated command; this keeps `config set link` consistent).
            std::string error;
            if (value.empty() || value == "0" || value == "false" || value == "off" ||
                value == "no") {
                if (!fed::link_target.empty()) fed::link_disconnect(error);
            } else if (!fed::link_connect(value, fed::link_primary_port, error)) {
                response = fail(error.empty() ? "link_failed" : error);
                return false;
            }
        } else if (key == "link_cache_ttl_sec") {
            fed::cache_ttl_sec = std::atoi(value.c_str());
        }

        response = ok("KEY:" + key + " VALUE:" + encode_field(value) +
                      " APPLY:" + (entry->live ? "live" : "restart"));
        return true;
    }

    response = fail("unknown_command");
    return false;
}
