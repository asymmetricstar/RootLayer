// server/ca/ca.cpp
//
// Certificate Authority. The CA key/certificate are generated on first start
// and persisted to ca.key / ca.crt next to the executable so issued server
// certificates keep validating across restarts. Every CSR is answered over the
// signaling channel with base64 PEM, and issued certificates are remembered in
// memory so the connection log can report a per-identity certificate status.
#include "ca/ca.h"

#include "core/win_headers.h"
#include "core/utils.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

std::mutex& ca_mutex() {
    static std::mutex m;
    return m;
}

// The CA itself - owned by this process only, never persisted.
EVP_PKEY* g_ca_key = nullptr;
X509* g_ca_cert = nullptr;
std::string g_ca_cert_pem;
std::string g_fingerprint;

// SQLite handle for cert.db (CA + issued certificates). nullptr = unavailable.
sqlite3* g_cert_db = nullptr;

// Certificates signed by the current CA, keyed by subject CN. Entries die
// with the process: a restart creates a new CA, which would invalidate them.
std::map<std::string, X509*> g_issued;
std::deque<std::string> g_issued_order;
// Client identity -> subject CN. The certificate CN is the virtual IP, so the
// connection log still finds the certificate through the identity it knows.
std::map<std::string, std::string> g_issued_identity;
const size_t kMaxIssued = 512;

std::string bio_string(BIO* bio) {
    if (!bio) return "";
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    return (data && len > 0) ? std::string(data, (size_t)len) : std::string();
}

std::string pem_of_cert(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    std::string out;
    if (PEM_write_bio_X509(bio, cert)) {
        out = bio_string(bio);
    }
    BIO_free(bio);
    return out;
}

// "YYYY-MM-DD" (UTC) of an ASN1_TIME, OpenSSL's own format as a fallback.
std::string time_string(const ASN1_TIME* t) {
    if (!t) return "";
    struct tm value;
    if (ASN1_TIME_to_tm(t, &value) == 1) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                 value.tm_year + 1900, value.tm_mon + 1, value.tm_mday);
        return std::string(buf);
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    ASN1_TIME_print(bio, t);
    std::string out = bio_string(bio);
    BIO_free(bio);
    return out;
}

// First 16 hex characters of the SHA-256 of the certificate DER. The client
// computes the same value so CAFP: can be compared byte for byte.
std::string sha256_short(X509* cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!cert || !X509_digest(cert, EVP_sha256(), md, &md_len) || md_len < 8) {
        return "";
    }
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned int i = 0; i < 8; ++i) {
        out.push_back(hex[md[i] >> 4]);
        out.push_back(hex[md[i] & 0xF]);
    }
    return out;
}

std::string subject_cn(X509_NAME* name) {
    if (!name) return "";
    char buf[256] = {0};
    if (X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf)) <= 0) {
        return "";
    }
    return std::string(buf);
}

EVP_PKEY* generate_rsa_key(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

bool set_random_serial(X509* cert) {
    BIGNUM* bn = BN_new();
    if (!bn) return false;
    if (!BN_rand(bn, 64, 0, 0)) { BN_free(bn); return false; }
    ASN1_INTEGER* ai = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    if (!ai) return false;
    X509_set_serialNumber(cert, ai);
    ASN1_INTEGER_free(ai);
    return true;
}

X509* create_self_signed_ca(EVP_PKEY* pkey) {
    X509* cert = X509_new();
    if (!cert) return nullptr;

    X509_set_version(cert, 2);
    if (!set_random_serial(cert)) { X509_free(cert); return nullptr; }

    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * 3650L);

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"RootLayer CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"RootLayer", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // Basic constraints: CA:TRUE
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    // Key usage: a CA must be allowed to sign certificates. Some strict
    // verifiers reject a chain when this is missing, surfacing as
    // "invalid signature" even though the bytes are correct.
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    // Subject key identifier helps clients build the chain.
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

    if (!X509_sign(cert, pkey, EVP_sha256())) { X509_free(cert); return nullptr; }
    return cert;
}

void forget_issued() {
    for (auto& entry : g_issued) {
        if (entry.second) X509_free(entry.second);
    }
    g_issued.clear();
    g_issued_order.clear();
    g_issued_identity.clear();
    if (g_cert_db) {
        sqlite3_exec(g_cert_db, "DELETE FROM issued", nullptr, nullptr, nullptr);
    }
}

void load_issued_from_db() {
    if (!g_cert_db) return;
    forget_issued();
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(g_cert_db, "SELECT cn, cert_pem, identity FROM issued", -1, &stmt, nullptr) != SQLITE_OK) return;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* cnc = sqlite3_column_text(stmt, 0);
        const unsigned char* cpc = sqlite3_column_text(stmt, 1);
        const unsigned char* cic = sqlite3_column_text(stmt, 2);
        std::string cn = cnc ? reinterpret_cast<const char*>(cnc) : std::string();
        std::string cert_pem = cpc ? reinterpret_cast<const char*>(cpc) : std::string();
        std::string identity = cic ? reinterpret_cast<const char*>(cic) : std::string();
        if (cn.empty() || cert_pem.empty()) continue;
        BIO* bio = BIO_new_mem_buf(cert_pem.data(), (int)cert_pem.size());
        X509* cert = bio ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
        if (bio) BIO_free(bio);
        if (!cert) continue;
        g_issued[cn] = cert;
        g_issued_order.push_back(cn);
        if (!identity.empty()) g_issued_identity[identity] = cn;
    }
    sqlite3_finalize(stmt);
    // cap
    while (g_issued_order.size() > kMaxIssued) {
        const std::string oldest = g_issued_order.front();
        g_issued_order.pop_front();
        auto stale = g_issued.find(oldest);
        if (stale != g_issued.end()) {
            if (stale->second) X509_free(stale->second);
            g_issued.erase(stale);
        }
    }
}

// Open (or create) cert.db in exe_dir. Returns true on success.
bool open_cert_db(const std::string& exe_dir) {
    if (g_cert_db) return true;
    if (exe_dir.empty()) return false;
    std::string path = exe_dir + "\\\\cert.db";
    if (sqlite3_open(path.c_str(), &g_cert_db) != SQLITE_OK) {
        if (g_cert_db) { sqlite3_close(g_cert_db); g_cert_db = nullptr; }
        return false;
    }
    const char* ddl =
        "CREATE TABLE IF NOT EXISTS ca (id INTEGER PRIMARY KEY, key_pem TEXT NOT NULL, cert_pem TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS issued (cn TEXT PRIMARY KEY, cert_pem TEXT NOT NULL, identity TEXT NOT NULL DEFAULT '');";
    sqlite3_exec(g_cert_db, ddl, nullptr, nullptr, nullptr);
    return true;
}

void load_issued_from_db();

// Caller holds ca_mutex().
bool ensure_ca_impl() {
    if (g_ca_key && g_ca_cert) return true;

    const std::string exe_dir = get_exe_dir_server();
    open_cert_db(exe_dir);

    // 1) Try to load a persisted CA from cert.db.
    if (g_cert_db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_cert_db, "SELECT key_pem, cert_pem FROM ca LIMIT 1", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* kp = sqlite3_column_text(stmt, 0);
                const unsigned char* cp = sqlite3_column_text(stmt, 1);
                std::string key_pem = kp ? reinterpret_cast<const char*>(kp) : std::string();
                std::string cert_pem = cp ? reinterpret_cast<const char*>(cp) : std::string();

                BIO* kbio = BIO_new_mem_buf(key_pem.data(), (int)key_pem.size());
                BIO* cbio = BIO_new_mem_buf(cert_pem.data(), (int)cert_pem.size());
                EVP_PKEY* pkey = kbio ? PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr) : nullptr;
                X509* cert = cbio ? PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr) : nullptr;
                if (kbio) BIO_free(kbio);
                if (cbio) BIO_free(cbio);

                bool ok = false;
                if (pkey && cert) {
                    EVP_PKEY* cert_pub = X509_get_pubkey(cert);
                    if (cert_pub && EVP_PKEY_eq(pkey, cert_pub) == 1) ok = true;
                    if (cert_pub) EVP_PKEY_free(cert_pub);
                }

                if (ok) {
                    g_ca_key = pkey;
                    g_ca_cert = cert;
                    g_ca_cert_pem = cert_pem.empty() ? pem_of_cert(cert) : cert_pem;
                    if (g_ca_cert_pem.empty()) g_ca_cert_pem = pem_of_cert(cert);
                    g_fingerprint = sha256_short(cert);
                    forget_issued();
                    load_issued_from_db();
                    sqlite3_finalize(stmt);
                    return true;
                }
                if (pkey) EVP_PKEY_free(pkey);
                if (cert) X509_free(cert);
            }
            sqlite3_finalize(stmt);
        }
    }

    // 2) Generate a fresh CA.
    EVP_PKEY* pkey = generate_rsa_key(2048);
    if (!pkey) return false;

    X509* cert = create_self_signed_ca(pkey);
    if (!cert) { EVP_PKEY_free(pkey); return false; }

    g_ca_key = pkey;
    g_ca_cert = cert;
    g_ca_cert_pem = pem_of_cert(cert);
    g_fingerprint = sha256_short(cert);
    forget_issued();  // a brand new CA has signed nothing yet

    // 3) Persist to cert.db.
    if (g_cert_db) {
        BIO* bio = BIO_new(BIO_s_mem());
        std::string key_pem;
        if (bio && PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            char* data = nullptr;
            long n = BIO_get_mem_data(bio, &data);
            if (data && n > 0) key_pem.assign(data, (size_t)n);
        }
        if (bio) BIO_free(bio);

        sqlite3_exec(g_cert_db, "DELETE FROM ca", nullptr, nullptr, nullptr);
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_cert_db, "INSERT INTO ca (key_pem, cert_pem) VALUES (?,?)", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, key_pem.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, g_ca_cert_pem.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return true;
}

// Remember an issued certificate for the connection log (caller holds the
// mutex). The list is capped so a long running server stays bounded.
void remember_issued(const std::string& cn, X509* cert) {
    if (cn.empty()) return;
    X509* copy = X509_dup(cert);
    if (!copy) return;

    auto it = g_issued.find(cn);
    if (it != g_issued.end()) {
        if (it->second) X509_free(it->second);
        it->second = copy;
        if (g_cert_db) {
            std::string cert_pem = pem_of_cert(cert);
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(g_cert_db, "UPDATE issued SET cert_pem=? WHERE cn=?", -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, cert_pem.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, cn.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        return;
    }

    g_issued[cn] = copy;
    g_issued_order.push_back(cn);
    while (g_issued_order.size() > kMaxIssued) {
        const std::string oldest = g_issued_order.front();
        g_issued_order.pop_front();
        auto stale = g_issued.find(oldest);
        if (stale != g_issued.end()) {
            if (stale->second) X509_free(stale->second);
            g_issued.erase(stale);
        }
    }

    // Persist to cert.db (best effort).
    if (g_cert_db) {
        std::string cert_pem = pem_of_cert(cert);
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_cert_db, "INSERT OR REPLACE INTO issued (cn, cert_pem, identity) VALUES (?,?,?)", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, cn.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, cert_pem.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, "", -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

// Versions that kept the CA on disk wrote these next to the executable. The
// CA is memory-only now, so the leftovers (including the private key) go.
// (legacy CA-on-disk cleanup removed: the CA is now persisted to ca.key/ca.crt)

}  // namespace

namespace ca {

static const char* b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string& in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)b64_chars[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (T[c] == -1) continue; // skip whitespace/newlines
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

bool ensure_ca(const std::string& exe_dir) {
    (void)exe_dir;
    std::lock_guard<std::mutex> lock(ca_mutex());
    return ensure_ca_impl();
}

std::string ca_cert_pem() {
    std::lock_guard<std::mutex> lock(ca_mutex());
    if (!ensure_ca_impl()) return "";
    return g_ca_cert_pem;
}

std::string fingerprint() {
    std::lock_guard<std::mutex> lock(ca_mutex());
    if (!ensure_ca_impl()) return "";
    return g_fingerprint;
}

std::string status() {
    std::lock_guard<std::mutex> lock(ca_mutex());
    if (!ensure_ca_impl()) return "FAILED - could not create the certificate authority";

    std::string out = "OK";
    std::string cn = subject_cn(X509_get_subject_name(g_ca_cert));
    if (!cn.empty()) out += " CN=" + cn;
    std::string until = time_string(X509_get0_notAfter(g_ca_cert));
    if (!until.empty()) out += " valid until " + until;
    if (!g_fingerprint.empty()) out += " SHA256 " + g_fingerprint;
    out += " issued " + std::to_string(g_issued.size());
    return out;
}

std::string sign_csr(const std::string& csr_pem, std::string* cn_out,
                     const std::string& identity) {
    std::lock_guard<std::mutex> lock(ca_mutex());
    if (!ensure_ca_impl()) return "";

    BIO* csr_bio = BIO_new_mem_buf(csr_pem.data(), (int)csr_pem.size());
    X509_REQ* req = csr_bio ? PEM_read_bio_X509_REQ(csr_bio, nullptr, nullptr, nullptr) : nullptr;
    if (csr_bio) BIO_free(csr_bio);
    if (!req) return "";

    EVP_PKEY* req_pub = X509_REQ_get_pubkey(req);
    if (!req_pub || X509_REQ_verify(req, req_pub) != 1) {
        if (req_pub) EVP_PKEY_free(req_pub);
        X509_REQ_free(req);
        return "";
    }

    X509* cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(req_pub);
        X509_REQ_free(req);
        return "";
    }

    X509_set_version(cert, 2);
    if (!set_random_serial(cert)) {
        X509_free(cert);
        EVP_PKEY_free(req_pub);
        X509_REQ_free(req);
        return "";
    }

    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * 365L);

    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));
    X509_set_pubkey(cert, req_pub);

    // Copy requested extensions if present
    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
            X509_add_ext(cert, ext, -1);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    std::string out;
    if (X509_sign(cert, g_ca_key, EVP_sha256())) {
        out = pem_of_cert(cert);
        std::string cn = subject_cn(X509_REQ_get_subject_name(req));
        if (!cn.empty()) {
            remember_issued(cn, cert);
            if (cn_out) *cn_out = cn;
            if (!identity.empty()) {
                // Keep the certificate reachable by the identity the client
                // connects with (its CN is the assigned virtual IP).
                g_issued_identity[identity] = cn;
                if (g_cert_db) {
                    sqlite3_stmt* stmt = nullptr;
                    if (sqlite3_prepare_v2(g_cert_db, "UPDATE issued SET identity=? WHERE cn=?", -1, &stmt, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(stmt, 2, cn.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                }
            }
        }
    }

    X509_free(cert);
    EVP_PKEY_free(req_pub);
    X509_REQ_free(req);
    return out;
}

namespace {

bool ascii_letter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// X.520 wants exactly two letters for the country entry (TR, DE, ...).
// Anything else is dropped instead of producing an invalid subject.
std::string two_letter_country(const std::string& value) {
    std::string out;
    for (char c : value) {
        if (!ascii_letter(c)) continue;
        out.push_back((c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c);
        if (out.size() == 2) break;
    }
    return out.size() == 2 ? out : std::string();
}

// One optional subject field. Empty values are skipped (the field simply does
// not appear), control characters are dropped and over-long values are cut so
// a command line cannot produce a broken subject.
void add_subject_field(X509_NAME* name, const char* field, const std::string& value) {
    std::string clean;
    for (char c : value) {
        if ((unsigned char)c >= 0x20) clean.push_back(c);
        if (clean.size() == 64) break;
    }
    // Trim surrounding blanks: a stray space is not part of a name.
    size_t begin = clean.find_first_not_of(' ');
    if (begin == std::string::npos) return;
    const size_t end = clean.find_last_not_of(' ');
    clean = clean.substr(begin, end - begin + 1);
    if (clean.empty()) return;

    X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8,
                               (const unsigned char*)clean.c_str(), -1, -1, 0);
}

}  // namespace

std::string issue_server_cert(const std::vector<std::string>& dns_names, int validity_days,
                              std::string* key_pem_out, const CertificateProfile& profile) {
    if (dns_names.empty() || dns_names.front().empty()) return "";

    std::lock_guard<std::mutex> lock(ca_mutex());
    if (!ensure_ca_impl()) return "";

    EVP_PKEY* pkey = generate_rsa_key(2048);
    if (!pkey) return "";

    X509* cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return "";
    }

    X509_set_version(cert, 2);
    if (!set_random_serial(cert)) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return "";
    }

    // One minute of backdating covers a client clock that is slightly behind.
    X509_gmtime_adj(X509_getm_notBefore(cert), -60L);
    const long days = validity_days > 0 ? (long)validity_days : 397L;
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * days);

    X509_set_pubkey(cert, pkey);

    X509_NAME* subject = X509_get_subject_name(cert);
    // CN is the domain name the certificate is issued for, never the IP: TLS
    // compares it with the name the client typed.
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)dns_names.front().c_str(), -1, -1, 0);
    // Operator supplied fields (console: cert issue <name> --name/--mail/...).
    // Empty ones are left out; O falls back to the project name so a call
    // without any option keeps the certificate this server always issued.
    add_subject_field(subject, "O", profile.name.empty() ? std::string("RootLayer") : profile.name);
    add_subject_field(subject, "emailAddress", profile.email);
    add_subject_field(subject, "L", profile.city);
    add_subject_field(subject, "ST", profile.state);
    add_subject_field(subject, "C", two_letter_country(profile.country));
    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));

    auto add_ext = [&](int nid, const std::string& value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value.c_str());
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    };

    // A server certificate: terminal (never a CA) and usable for TLS only.
    add_ext(NID_basic_constraints, "critical,CA:FALSE");
    add_ext(NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext(NID_ext_key_usage, "serverAuth");
    add_ext(NID_subject_key_identifier, "hash");

    std::string san = "DNS:" + dns_names.front();
    for (size_t i = 1; i < dns_names.size(); ++i) {
        if (dns_names[i].empty()) continue;
        san += ",DNS:" + dns_names[i];
    }
    add_ext(NID_subject_alt_name, san);

    // Key identifiers make chain building robust for strict verifiers.
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, g_ca_cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext2 = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_key_identifier, "hash");
    if (ext2) { X509_add_ext(cert, ext2, -1); X509_EXTENSION_free(ext2); }
    ext2 = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_authority_key_identifier, "keyid:always,issuer");
    if (ext2) { X509_add_ext(cert, ext2, -1); X509_EXTENSION_free(ext2); }

    std::string cert_pem;
    if (X509_sign(cert, g_ca_key, EVP_sha256())) {
        cert_pem = pem_of_cert(cert);
        remember_issued(dns_names.front(), cert);
        if (key_pem_out) {
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio && PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
                char* data = nullptr;
                long n = BIO_get_mem_data(bio, &data);
                if (data && n > 0) key_pem_out->assign(data, (size_t)n);
            }
            if (bio) BIO_free(bio);
        }
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    return cert_pem;
}

std::vector<std::string> issued_subjects() {
    std::lock_guard<std::mutex> lock(ca_mutex());
    std::vector<std::string> out;
    out.reserve(g_issued_order.size());
    for (const auto& cn : g_issued_order) {
        out.push_back(cn);
    }
    return out;
}

bool forget(const std::string& subject_cn) {
    if (subject_cn.empty()) return false;

    std::lock_guard<std::mutex> lock(ca_mutex());
    auto it = g_issued.find(subject_cn);
    if (it == g_issued.end()) return false;

    if (it->second) X509_free(it->second);
    g_issued.erase(it);
    g_issued_order.erase(std::remove(g_issued_order.begin(), g_issued_order.end(), subject_cn),
                        g_issued_order.end());

    if (g_cert_db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(g_cert_db, "DELETE FROM issued WHERE cn=?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, subject_cn.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    for (auto alias = g_issued_identity.begin(); alias != g_issued_identity.end();) {
        alias = (alias->second == subject_cn) ? g_issued_identity.erase(alias) : std::next(alias);
    }
    return true;
}

std::string cert_status_for(const std::string& identity) {
    if (identity.empty()) return "n/a (dynamic)";

    std::lock_guard<std::mutex> lock(ca_mutex());
    auto it = g_issued.find(identity);
    if (it == g_issued.end()) {
        // The certificate subject CN is the virtual IP: follow the identity
        // alias recorded at enrollment.
        auto alias = g_issued_identity.find(identity);
        if (alias == g_issued_identity.end()) return "NOT ENROLLED";
        it = g_issued.find(alias->second);
    }
    if (it == g_issued.end() || !it->second) return "NOT ENROLLED";

    const ASN1_TIME* not_after = X509_get0_notAfter(it->second);
    if (X509_cmp_time(not_after, nullptr) < 0) return "EXPIRED";

    std::string until = time_string(not_after);
    return until.empty() ? std::string("VALID") : "VALID until " + until;
}

}  // namespace ca
