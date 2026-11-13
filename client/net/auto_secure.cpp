// client/net/auto_secure.cpp - automatic client CA trust and certificate enrollment.
//
// The PKI material (CA certificate, private key, client certificate) lives in
// process memory only: nothing is written to the disk. The CA is fetched and
// the client certificate is enrolled over the signaling channel, and the CA is
// installed into the Windows trust store so local apps/browsers trust
// CA-signed certificates without any user interaction.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/utils.h"
#include "core/json.h"
#include "net/signaling.h"
#include "net/auto_secure.h"

#include <wincrypt.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <string>
#include <vector>

namespace {

static const char* b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const std::string& in) {
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
    if (valb > -6) out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string b64_decode(const std::string& in) {
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

bool connect_signaling(SOCKET& sock) {
    sock = INVALID_SOCKET;
    std::string port_str = std::to_string(signaling_server_port);
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* resolved = NULL;
    if (getaddrinfo(signaling_server_ip.c_str(), port_str.c_str(), &hints, &resolved) != 0 || !resolved) {
        return false;
    }
    sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(resolved); return false; }
    DWORD timeout_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    if (connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock); sock = INVALID_SOCKET; freeaddrinfo(resolved); return false;
    }
    freeaddrinfo(resolved);
    return true;
}

std::string request_response(const std::string& request) {
    SOCKET sock = INVALID_SOCKET;
    if (!connect_signaling(sock)) return "";
    std::string req = request;
    if (req.empty() || req.back() != '\n') req.push_back('\n');
    send(sock, req.c_str(), (int)req.size(), 0);
    std::string resp;
    char buf[4096];
    for (;;) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n > 0) resp.append(buf, n);
        else break;
        if (resp.size() > (1 << 20)) break;
    }
    closesocket(sock);
    return resp;
}

std::string extract_token_line(const std::string& resp, const std::string& key) {
    std::string marker = key + ":";
    size_t p = resp.find(marker);
    if (p == std::string::npos) return "";
    p += marker.size();
    size_t e = resp.find_first_of("\r\n", p);
    std::string v = (e == std::string::npos) ? resp.substr(p) : resp.substr(p, e - p);
    size_t b = v.find_first_not_of(" \t");
    size_t en = v.find_last_not_of(" \t");
    if (b == std::string::npos) return "";
    return v.substr(b, en - b + 1);
}

// Remove other "RootLayer CA" roots from a store: the server rotates its
// in-memory CA on every restart, so without this the trust store would keep
// collecting stale roots. The certificate just added is identified by its DER
// and kept.
void prune_stale_roots(HCERTSTORE store, const std::vector<unsigned char>& keep_der) {
    if (keep_der.empty()) return;

    std::vector<PCCERT_CONTEXT> stale;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                             CERT_FIND_SUBJECT_STR, "RootLayer CA", ctx)) != NULL) {
        bool is_current = (ctx->cbCertEncoded == (DWORD)keep_der.size() &&
                           memcmp(ctx->pbCertEncoded, keep_der.data(), keep_der.size()) == 0);
        if (is_current) continue;  // the search continues from this context
        PCCERT_CONTEXT copy = CertDuplicateCertificateContext(ctx);
        if (copy) stale.push_back(copy);
    }
    for (PCCERT_CONTEXT candidate : stale) {
        CertDeleteCertificateFromStore(candidate);  // frees candidate
    }
}

// Best effort: install into the OS trust store so local apps/browsers trust
// CA-signed endpoint certs without manual steps (admin/headless).
bool install_ca_trust_pem(const std::string& pem) {
    if (pem.empty()) return false;
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509* cert = bio ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio) BIO_free(bio);
    if (!cert) return false;
    int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0) { X509_free(cert); return false; }
    std::vector<unsigned char> der((size_t)der_len);
    unsigned char* p = der.data();
    i2d_X509(cert, &p);
    X509_free(cert);

    bool ok = false;
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV_LEGACY)NULL,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
                                     "ROOT");
    if (store) {
        if (CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                             der.data(), (DWORD)der.size(),
                                             CERT_STORE_ADD_REPLACE_EXISTING, nullptr)) {
            ok = true;
            prune_stale_roots(store, der);
        }
        CertCloseStore(store, 0);
    }
    if (!ok) {
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV_LEGACY)NULL,
                              CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                              "ROOT");
        if (store) {
            if (CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                 der.data(), (DWORD)der.size(),
                                                 CERT_STORE_ADD_REPLACE_EXISTING, nullptr)) {
                ok = true;
                prune_stale_roots(store, der);
            }
            CertCloseStore(store, 0);
        }
    }
    return ok;
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

// Subject of the client certificate: E, CN, O, L, S, C.
struct CertificateProfile {
    std::string common_name;  // CN - virtual IP assigned by the server
    std::string email;        // E  - user@mail.tld
    std::string name;         // O  - user name
    std::string city;         // L  - city
    std::string state;        // S  - state / province
    std::string country;      // C  - two letter country code
};

void add_subject_entry(X509_NAME* name, const char* field, const std::string& value) {
    if (value.empty()) return;
    X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8,
                               (const unsigned char*)value.c_str(), -1, -1, 0);
}

// X.520 wants a two letter country code: keep the first two letters, uppercase.
std::string normalize_country(const std::string& value) {
    std::string out;
    for (char c : value) {
        if (!isalpha((unsigned char)c)) continue;
        out.push_back((char)toupper((unsigned char)c));
        if (out.size() == 2) break;
    }
    return out.size() == 2 ? out : std::string();
}

std::string make_csr_pem(EVP_PKEY* pkey, const CertificateProfile& profile) {
    X509_REQ* req = X509_REQ_new();
    if (!req) return "";
    X509_REQ_set_version(req, 0);
    X509_NAME* name = X509_REQ_get_subject_name(req);

    add_subject_entry(name, "CN", profile.common_name);
    add_subject_entry(name, "emailAddress", profile.email);
    add_subject_entry(name, "O", profile.name);
    add_subject_entry(name, "L", profile.city);
    add_subject_entry(name, "ST", profile.state);
    add_subject_entry(name, "C", normalize_country(profile.country));

    X509_REQ_set_pubkey(req, pkey);
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) { X509_REQ_free(req); return ""; }
    BIO* bio = BIO_new(BIO_s_mem());
    std::string out;
    if (bio && PEM_write_bio_X509_REQ(bio, req)) {
        char* data = nullptr; long len = BIO_get_mem_data(bio, &data);
        if (data && len > 0) out.assign(data, (size_t)len);
    }
    if (bio) BIO_free(bio);
    X509_REQ_free(req);
    return out;
}

// ------------------------------------------------------------ in-memory PKI
//
// Nothing here is ever written to disk. The material lives as long as the
// process does; a restart re-enrolls automatically.

std::mutex pki_mutex;
bool enrolled = false;          // a key + certificate were obtained this run
bool trust_installed = false;   // the CA is in the OS trust store
EVP_PKEY* client_key = nullptr;
std::string client_cert_pem;
std::string ca_pem;             // CA certificate received from the server
std::string local_ca_fp;        // fingerprint of ca_pem
std::string server_ca_fp;       // fingerprint advertised by the server (CAFP:)

// First 16 hex characters of the SHA-256 of the certificate DER - the exact
// value the server puts into CAFP:, so the two can be compared directly.
std::string cert_fingerprint_pem(const std::string& pem) {
    if (pem.empty()) return "";
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509* cert = bio ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio) BIO_free(bio);
    if (!cert) return "";

    std::string out;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) && md_len >= 8) {
        static const char* hex = "0123456789ABCDEF";
        for (unsigned int i = 0; i < 8; ++i) {
            out.push_back(hex[md[i] >> 4]);
            out.push_back(hex[md[i] & 0xF]);
        }
    }
    X509_free(cert);
    return out;
}

// Take over a CA received from the server. Returns true when it differs from
// the one already known, which means the trust store needs a refresh.
bool adopt_ca(const std::string& pem) {
    std::string fp = cert_fingerprint_pem(pem);
    if (fp.empty()) return false;
    if (!ca_pem.empty() && fp == local_ca_fp) return false;
    ca_pem = pem;
    local_ca_fp = fp;
    trust_installed = false;  // new CA: install it and prune the old root
    return true;
}

void forget_material() {
    if (client_key) {
        EVP_PKEY_free(client_key);
        client_key = nullptr;
    }
    client_cert_pem.clear();
    enrolled = false;
    trust_installed = false;
    ca_pem.clear();
    local_ca_fp.clear();
}

// Older versions kept ca.crt / client.key / client.crt next to the
// executable. The PKI is memory-only now, so those leftovers are removed.
void remove_legacy_files() {
    static bool done = false;
    if (done) return;
    done = true;
    std::string dir = get_exe_dir();
    DeleteFileA((dir + "\\ca.crt").c_str());
    DeleteFileA((dir + "\\client.key").c_str());
    DeleteFileA((dir + "\\client.crt").c_str());
}

}  // namespace

bool ensure_client_auto_security() {
    std::lock_guard<std::mutex> lock(pki_mutex);
    remove_legacy_files();

    // Fast path: provisioned for the CA the server is using right now.
    const bool ca_rotated = !server_ca_fp.empty() && server_ca_fp != local_ca_fp;
    if (enrolled && trust_installed && !ca_rotated) {
        return true;
    }

    const bool need_cert = !enrolled || ca_rotated;
    bool answered = false;

    // 1) Enrollment: one round trip that also carries the CA certificate.
    if (need_cert) {
        EVP_PKEY* key = generate_rsa_key(2048);
        if (key) {
            // CN is the virtual IP the server assigned for this session; the
            // identity is sent alongside so the server can still report the
            // certificate for this client.
            CertificateProfile profile;
            profile.common_name = !virtual_ip.empty()
                                      ? virtual_ip
                                      : (client_identity.empty() ? std::string("rootlayer-client")
                                                                 : client_identity);
            profile.email = profile_email;
            profile.name = profile_full_name;
            profile.city = profile_city;
            profile.state = profile_state;
            profile.country = profile_country;

            std::string csr_pem = make_csr_pem(key, profile);
            std::string cert_pem;
            if (!csr_pem.empty()) {
                std::string request = "CSR:" + b64_encode(csr_pem);
                if (!client_identity.empty()) {
                    request += " IDENTITY:" + client_identity;
                }
                std::string resp = request_response(request);
                answered = !resp.empty();
                cert_pem = b64_decode(extract_token_line(resp, "CERT"));
                adopt_ca(b64_decode(extract_token_line(resp, "CACERT")));
            }
            if (!cert_pem.empty()) {
                if (client_key) EVP_PKEY_free(client_key);
                client_key = key;
                client_cert_pem = cert_pem;
                enrolled = true;
            } else {
                EVP_PKEY_free(key);
            }
        }
    }

    // 2) CA certificate. Skipped in the same round when the server did not
    // answer at all: a second request would only wait for another timeout.
    const bool ca_stale = ca_pem.empty() ||
                          (!server_ca_fp.empty() && server_ca_fp != local_ca_fp);
    if (ca_stale && (!need_cert || answered)) {
        std::string resp = request_response("CA_CERT");
        adopt_ca(b64_decode(extract_token_line(resp, "CACERT")));
    }

    // 3) Trust store (best effort: the machine-wide store needs admin).
    if (!ca_pem.empty() && !trust_installed) {
        trust_installed = install_ca_trust_pem(ca_pem);
    }

    return enrolled;
}

void auto_secure_on_server_ca(const std::string& fingerprint) {
    if (fingerprint.empty()) return;

    std::lock_guard<std::mutex> lock(pki_mutex);
    if (fingerprint == server_ca_fp) return;

    const bool rotated = !local_ca_fp.empty() && fingerprint != local_ca_fp;
    server_ca_fp = fingerprint;
    if (rotated) {
        // The server restarted with a fresh CA: everything we hold is stale.
        std::cout << "Server certificate authority changed; re-enrolling."
                  << std::endl;
        forget_material();
    }
}
