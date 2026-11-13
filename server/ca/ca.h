// server/ca/ca.h
// Certificate Authority.
//
// The CA private key and certificate are generated on first startup and then
// persisted to ca.key / ca.crt next to the executable, so that issued server
// certificates keep validating across restarts (an in-memory-only CA rotated
// on every restart and surfaced as "invalid signature" to HTTPS clients).
// Certificates travel over the signaling channel as base64 PEM (CACERT: /
// CERT: lines), so clients never need a file either.
#ifndef ROOTLAYER_SERVER_CA_H
#define ROOTLAYER_SERVER_CA_H

#include <string>
#include <vector>

namespace ca {
// Generate the in-memory CA if it does not exist yet. exe_dir is only used to
// delete ca.key/ca.crt files left behind by versions that kept the CA on disk.
// Returns true on success.
bool ensure_ca(const std::string& exe_dir);

// Return the CA certificate PEM (empty if the CA could not be created).
std::string ca_cert_pem();

// First 16 hex characters of the SHA-256 fingerprint of the CA certificate.
// Sent to clients (CAFP:) so they can detect a CA rotation without asking.
std::string fingerprint();

// One line status of the CA for the server console:
// "OK CN=RootLayer CA valid until 2036-11-10 SHA256 ... issued 3"
std::string status();

// Sign a PEM-encoded CSR and return the PEM-encoded certificate ("" on
// failure). The whole requested subject (CN, O, L, S, C, E) is carried into the
// certificate. The subject CN is returned through cn_out when given. Issued
// certificates are remembered in memory so cert_status_for() can report them;
// `identity` (when given) is remembered as an alias, because a client's CN is
// the virtual IP the server assigned, not its identity.
std::string sign_csr(const std::string& csr_pem, std::string* cn_out = nullptr,
                     const std::string& identity = std::string());

// Certificate status of an identity for the connection log:
//   "VALID until <date>" | "EXPIRED" | "NOT ENROLLED" | "n/a (dynamic)"
std::string cert_status_for(const std::string& identity);

// Optional subject profile for a server certificate: the values the operator
// passes to `console cert issue` (E, O, L, S, C). They are NOT stored anywhere
// - no ini key, no database row - they only end up in the certificate that is
// written to disk. An empty field is left out of the subject, so a call without
// any of them produces exactly the certificate issued before.
//
// CN is always the DNS name (never an IP): TLS matches the name the client
// asked for against it.
struct CertificateProfile {
    std::string name;     // O - user name
    std::string email;    // E - user@mail.tld
    std::string city;     // L - city
    std::string state;    // S - state / country name
    std::string country;  // C - two letter country code
};

// Issue a TLS server certificate for the given DNS names: the first name goes
// into the subject CN, all of them into subjectAltName, and the certificate is
// marked CA:FALSE with keyUsage digitalSignature/keyEncipherment and
// extendedKeyUsage serverAuth. The key is generated here and returned as PEM
// through key_pem_out, so a service can serve HTTPS with a chain the clients
// already trust. Returns the certificate PEM, or "" on failure.
std::string issue_server_cert(const std::vector<std::string>& dns_names,
                              int validity_days,
                              std::string* key_pem_out,
                              const CertificateProfile& profile = CertificateProfile());

// Subject CNs of the certificates the current CA has signed (console listing).
std::vector<std::string> issued_subjects();

// Drops a certificate from the in-memory record so it is no longer listed or
// reported. The CA publishes no CRL, so a certificate already handed out stays
// valid until it expires; rotating the CA (a restart) is what really
// invalidates everything.
bool forget(const std::string& subject_cn);

// Base64 helpers.
std::string base64_encode(const std::string& in);
std::string base64_decode(const std::string& in);
}

#endif  // ROOTLAYER_SERVER_CA_H
