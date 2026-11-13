// client/net/auto_secure.h
//
// Automatic, headless client-side PKI bootstrap:
// - fetch and trust the platform CA certificate (over the signaling channel)
// - generate a local keypair + CSR and obtain a signed client certificate
// Everything stays in process memory: no ca.crt / client.key / client.crt
// file is written to disk (leftovers from older versions are removed on the
// first run). No user interaction; safe to call repeatedly.
#ifndef ROOTLAYER_AUTO_SECURE_H
#define ROOTLAYER_AUTO_SECURE_H

#include "core/win_headers.h"

// Ensures the CA is trusted locally and this client holds a key/certificate.
// Returns true when provisioned. Non-fatal: callers may continue without
// secure material if the server is unreachable.
bool ensure_client_auto_security();

// CA fingerprint (CAFP:) taken from the server's session response. When it
// differs from the CA this client enrolled against, the cached material is
// dropped so the next ensure_client_auto_security() call re-enrolls and
// refreshes the OS trust store (the server rotates its CA on restart).
void auto_secure_on_server_ca(const std::string& fingerprint);

#endif  // ROOTLAYER_AUTO_SECURE_H
