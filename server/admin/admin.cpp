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
//
// Field values never contain spaces: the console replaces them with '_' and
// this layer sanitizes again, so a record cannot break the token format.
#include "admin/admin.h"

#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "arpa/arpa.h"
#include "ca/ca.h"

#include <cstdlib>
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
                      " CERTS:" + std::to_string(ca::issued_subjects().size()));
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

        std::string canonical;
        const std::string result = arpa_set(name, identity, ip, ttl, info, &canonical);
        if (result != "ok") {
            response = fail(result);
            return false;
        }
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
        if (!arpa_delete(name)) {
            response = fail("not_found");
            return false;
        }
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

    response = fail("unknown_command");
    return false;
}
