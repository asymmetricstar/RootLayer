// server/net/control.cpp - control channel request handling.
//
// handle_request() is the whole protocol minus the socket: it takes one
// complete request, answers with the bytes to send back and says whether the
// connection ends afterwards. The signaling loop (net/signaling.cpp) owns the
// sockets, the buffers and the timeouts, so nothing here blocks.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "core/utils.h"
#include "arpa/arpa.h"
#include "db/store.h"
#include "session/session.h"
#include "gateway/gateway.h"
#include "net/net.h"
#include "ca/ca.h"
#include "admin/admin.h"
#include "core/log.h"
#include "core/limits.h"
#include "federation/federation.h"

#include <algorithm>
#include <cctype>

namespace {

// A client's permanent hardware id in canonical aa:bb:cc:dd:ee:ff form. Anything
// else returns "" so a malformed request cannot inject text into the log.
std::string normalize_hw_id(const std::string& text) {
    if (text.size() != 17) {
        return "";
    }
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

// How a member appears in the server log: its hardware id, never the public
// address it connected from.
std::string session_label(const std::shared_ptr<Session>& session) {
    if (!session || session->hw_id.empty()) {
        return "hw:unknown";
    }
    return session->hw_id;
}

}  // namespace

// Gateway, mask and TLD list a client needs to configure itself. Shared by the
// registration response and the "STATE" answer on the control channel, so a
// moved gateway or a changed TLD list also reaches a client that is already
// connected.
std::string server_network_state_tokens(const Session* session) {
    // Bandwidth cap this client is running with, so the panel can show it.
    // Already in kbit/s per direction; 0 means unlimited.
    auto band_token = [](const Session* s) -> std::string {
        if (s == nullptr) {
            return "";
        }
        auto kbps = [](double bytes_per_sec) -> long long {
            return bytes_per_sec > 0.0 ? (long long)(bytes_per_sec * 8.0 / 1000.0 + 0.5) : 0;
        };
        return " BAND:" + std::to_string(kbps(s->upload.rate())) + ":" +
               std::to_string(kbps(s->download.rate()));
    };

    // MOTD from server.ini. The answer is a space-separated token line, so
    // spaces (and the escape character itself) are percent-encoded.
    auto motd_token = []() -> std::string {
        // Copied once: the admin console may replace it at any time.
        const std::string motd = server_motd_value();
        if (motd.empty()) {
            return "";
        }
        std::string out = " MOTD:";
        for (char c : motd) {
            if (c == '%') {
                out += "%25";
            } else if (c == ' ') {
                out += "%20";
            } else {
                out += c;
            }
        }
        return out;
    };

    // Live member count. It is part of the STATE answer so an already
    // connected client sees peers join and leave; the registration response
    // carries the same token, so the panel is correct from the first frame.
    const std::string members = " MEMBERS:" + std::to_string(online_member_count());

    std::string out = members;

    if (gateway_active.load()) {
        out += " GATEWAY:" + server_virtual_ip();
        out += " MASK:" + ip_to_string(virtual_ip_mask);

        // Virtual TLDs this server is authoritative for. The client turns them
        // into NRPT rules pointing at GATEWAY, so only these names are sent to
        // the tunnel DNS server; the address and the list both come from here,
        // never from a hardcoded client default.
        std::string tlds;
        for (const auto& suffix : arpa_suffixes) {
            if (suffix.empty()) continue;
            if (!tlds.empty()) tlds += ",";
            tlds += suffix;
        }
        if (!tlds.empty()) {
            out += " TLD:" + tlds;
        }
    }

    // Federation: the address blocks owned by the other servers. The client
    // installs one route per block through GATEWAY, so a packet for another
    // server's client enters the tunnel even though that block is not part of
    // its own subnet. No address, mask or configuration changes on the client;
    // when a new server joins with a new block, its block shows up here on the
    // next STATE answer and the route is added. Blocks already covered by the
    // client's own subnet are left out (they are on-link anyway).
    {
        std::string routes;
        std::set<std::string> seen;
        for (const auto& peer : fed::peers()) {
            if (peer.prefix.empty() || peer.prefix == fed::own_prefix()) continue;
            if (!seen.insert(peer.prefix).second) continue;
            if (!routes.empty()) routes += ",";
            routes += peer.prefix;
        }
        if (!routes.empty()) {
            out += " ROUTES:" + routes;
        }
    }

    return out + band_token(session) + motd_token();
}

void release_session(const std::shared_ptr<Session>& session) {
    if (!session) {
        return;
    }
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        unindex_session(session);
        auto entry = std::find(online.begin(), online.end(), session);
        if (entry != online.end()) {
            online.erase(entry);
            removed = true;
        }
        if (!session->retired) {
            active_ips.erase(session->virtual_ip);
        }
    }
    // A session that was already dropped by a takeover must not log a second
    // CLOSED line.
    if (removed) {
        // Remember the departure so the admin console can show "last seen"
        // for a client that is no longer online.
        note_client_seen(client_db_key(session->hw_id, session->identity));
        // Tell the federation this address is gone, so peers stop sending to it.
        fed::note_client_offline(session->virtual_ip);
        srvlog::event("CLOSED", session_label(session), session->virtual_ip, "session ended");
    }
}

std::string handle_request(const std::string& request, const sockaddr_in& peer_addr,
                           bool& closes, std::shared_ptr<Session>& session) {
    closes = true;
    session.reset();

    // The address a client connected from is never logged: a member is
    // identified by its hardware id and its virtual address only, so the
    // server console cannot leak where a client really is. (The session keeps
    // the public address in memory for relay endpoint matching, nothing more.)

    // Administrative requests come from console.exe, which runs on the server
    // machine: they are answered here and never over the tunnel or the LAN.
    // The source address is not logged either (accepted or rejected), so the
    // console never prints an address a connection came from.
    if (request.rfind("ADMIN", 0) == 0) {
        std::string response;
        if (!admin_peer_allowed(peer_addr)) {
            response = "ADMIN_ERR:local_only";
            std::cout << "Admin request REJECTED [admin: local_only]" << std::endl;
        } else {
            admin_request(trim(request), response);
            std::cout << "Admin from local console: "
                      << trim(request) << " -> " << response.substr(0, 60) << std::endl;
        }
        return response;
    }

    // CA one-shot requests. The signaling loop hands over the whole payload
    // (it waits for the client to fall silent), so no receive loop is needed.
    if (request.find("CSR:") != std::string::npos ||
        request.find("CA_CERT") != std::string::npos ||
        request.find("CA_CSR") != std::string::npos ||
        request.find("SRV_CERT") != std::string::npos) {
        // LINKED mode has one trust root: the primary's CA. The replica asks
        // the primary on the client's behalf, so a certificate issued for a
        // name on one server validates on every server. When the primary is
        // unreachable the local CA still answers, so DEGRADED mode keeps
        // working with the trust material clients already have.
        if (!fed::link_target.empty()) {
            std::string proxied;
            if (fed::certificate_proxy(request, proxied) && !proxied.empty()) {
                return proxied;
            }
        }

        if (request.find("CA_CERT") != std::string::npos) {
            std::string pem = ca::ca_cert_pem();
            if (!pem.empty()) {
                std::cout << "CA certificate sent to a client [cert: CA OK SHA256 "
                          << ca::fingerprint() << "]" << std::endl;
                return "CACERT:" + ca::base64_encode(pem);
            }
            std::cout << "CA certificate request REJECTED [cert: CA unavailable]"
                      << std::endl;
            return "CA_ERR:cert_unavailable";
        }

        if (request.find("SRV_CERT") != std::string::npos) {
            // TLS server certificate for a registered domain: the service that
            // serves e.g. root.name gets a certificate the clients already
            // trust. Only the identity that owns the domain record (or a
            // request from the server host itself) may obtain the key.
            const std::string name = token_value(request, "NAME");
            const std::string identity = token_value(request, "IDENTITY");
            std::string owner, info;
            const std::string ip = name.empty() ? std::string() : arpa_get(name, &owner, &info);
            const bool loopback = peer_addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK);

            if (name.empty() || ip.empty()) {
                std::cout << "Server certificate request REJECTED [cert: name_not_registered]"
                          << std::endl;
                return "SRV_ERR:name_not_registered";
            }
            if (!loopback && (identity.empty() || owner != identity)) {
                std::cout << "Server certificate request for " << name
                          << " REJECTED [cert: not_owner]" << std::endl;
                return "SRV_ERR:not_owner";
            }

            std::vector<std::string> names;
            names.push_back(name);
            if (name.rfind("www.", 0) != 0) names.push_back("www." + name);

            std::string key_pem;
            const std::string cert_pem = ca::issue_server_cert(names, 397, &key_pem);
            if (cert_pem.empty() || key_pem.empty()) {
                std::cout << "Server certificate request for " << name
                          << " FAILED [cert: sign_failed]" << std::endl;
                return "SRV_ERR:sign_failed";
            }

            std::string resp = "SRVCERT:" + ca::base64_encode(cert_pem);
            resp += "\nSRVKEY:" + ca::base64_encode(key_pem);
            const std::string ca_pem = ca::ca_cert_pem();
            if (!ca_pem.empty()) resp += "\nCACERT:" + ca::base64_encode(ca_pem);
            std::cout << "Server certificate issued for " << name
                      << " [cert: valid 397 days, SHA256 " << ca::fingerprint() << "]"
                      << std::endl;
            return resp;
        }

        // Extract base64 payload after "CSR:".
        size_t pos = request.find("CSR:");
        std::string b64;
        if (pos != std::string::npos) {
            b64 = request.substr(pos + 4);
            // trim leading whitespace
            size_t s = b64.find_first_not_of(" \t\r\n");
            if (s != std::string::npos) b64 = b64.substr(s);
            // The payload is a single token: anything after the first space or
            // newline is a separate field (IDENTITY:...).
            size_t e = b64.find_first_of(" \t\r\n");
            if (e != std::string::npos) b64 = b64.substr(0, e);
        }
        if (b64.empty()) {
            std::cout << "Certificate request REJECTED [cert: missing_csr]" << std::endl;
            return "CA_ERR:missing_csr";
        }
        std::string csr_pem = ca::base64_decode(b64);
        std::string cn;
        // The certificate CN is the assigned virtual IP, so the client names
        // itself here and the server remembers the alias.
        std::string csr_identity = token_value(request, "IDENTITY");
        if (csr_identity.size() > 64) csr_identity.clear();
        std::string cert = ca::sign_csr(csr_pem, &cn, csr_identity);
        if (cert.empty()) {
            std::cout << "Certificate request REJECTED [cert: sign_failed]" << std::endl;
            return "CA_ERR:sign_failed";
        }
        std::string ca_pem = ca::ca_cert_pem();
        std::string resp = "CERT:" + ca::base64_encode(cert);
        if (!ca_pem.empty()) resp += "\nCACERT:" + ca::base64_encode(ca_pem);
        std::cout << "Certificate issued for CN=" << (cn.empty() ? std::string("(none)") : cn)
                  << " [" << (cn.empty() ? std::string("ISSUED") : ca::cert_status_for(cn))
                  << "]" << std::endl;
        return resp;
    }

    // Early client: answer clearly and close, so it retries instead of
    // holding a half-configured session.
    if (!server_ready.load()) {
        std::cout << "Rejected client: server still starting" << std::endl;
        return "SERVER_STARTING Retry in a few seconds.";
    }

    // One-shot name query: resolve a name without joining the VPN. These
    // connections never become sessions, so they do not consume an address.
    std::string arpa_query = token_value(request, "ARPA_QUERY");
    if (!arpa_query.empty()) {
        std::string owner;
        std::string info;
        std::string ip = arpa_get(arpa_query, &owner, &info);
        if (!ip.empty()) {
            std::string resp = "ARPA_IP:" + arpa_query + " ADDR:" + ip;
            if (!info.empty()) {
                resp += " INFO:" + info;
            }
            return resp;
        }
        std::string normalized = arpa_normalize(arpa_query);
        if (normalized.empty()) {
            // root is the only name normalize() rejects
            std::string lowered = arpa_query;
            for (char& c : lowered) c = (char)tolower((unsigned char)c);
            size_t b = lowered.find_first_not_of(" \t\r\n");
            size_t e = lowered.find_last_not_of(" \t\r\n");
            std::string t = (b == std::string::npos) ? "" : lowered.substr(b, e - b + 1);
            if (t == "root" || t == "root." + arpa_suffix) {
                ip = arpa_get("root." + arpa_suffix, &owner, &info);
                if (!ip.empty()) {
                    std::string resp = "ARPA_IP:" + arpa_query + " ADDR:" + ip;
                    if (!info.empty()) {
                        resp += " INFO:" + info;
                    }
                    return resp;
                }
            }
        }
        // Federation: a replica asks its primary before answering not_found,
        // so a name registered on another server resolves here too.
        std::string remote_ip;
        std::string remote_owner;
        if (fed::lookup_name(arpa_query, remote_ip, &remote_owner) && !remote_ip.empty()) {
            return "ARPA_IP:" + arpa_query + " ADDR:" + remote_ip;
        }
        return "ARPA_ERR:" + arpa_query + " CODE:not_found";
    }

    std::string public_ip = inet_ntoa(peer_addr.sin_addr);

    int port = token_int(request, "UDP_PORT", 50000);
    uint16_t udp_port = (port > 0 && port <= 65535) ? (uint16_t)port : (uint16_t)50000;

    std::string identity = token_value(request, "IDENTITY");
    if (identity.size() < 8 || identity.size() > 64) {
        identity.clear();
    }

    // Random per-process id of the connecting client ("" for legacy clients
    // that do not send one). Used below to refuse a second live process that
    // claims an identity another process is already using.
    std::string instance = token_value(request, "INSTANCE");
    if (instance.size() > 64) {
        instance.clear();
    }

    // Permanent hardware id of this client. It is what identifies the member in
    // every server log line, instead of the address it connected from, and it
    // is the primary key for the address mapping in client.db.
    std::string hw_id = normalize_hw_id(token_value(request, "HWID"));
    // The single identity used for persistence and for the duplicate checks:
    // the hardware id whenever there is one, else the legacy static identity.
    const std::string db_key = client_db_key(hw_id, identity);

    // Incoming connection event, with the certificate status of the identity
    // that just showed up (issued by the current in-memory CA).
    srvlog::event("CONNECT", hw_id, "",
                  "cert " + ca::cert_status_for(identity) +
                      (instance.empty() ? "" : ", instance " + instance));

    size_t member_count = 0;

    auto new_session = std::make_shared<Session>();
    new_session->sock = INVALID_SOCKET;  // the signaling loop sets this
    new_session->identity = identity;
    new_session->instance = instance;
    new_session->hw_id = hw_id;
    new_session->public_ip = public_ip;
    new_session->udp_port = udp_port;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);

        // Double-connection guard: a live session with the same client key (the
        // hardware id) but a DIFFERENT process instance means a second
        // client.exe is running on that machine - refuse it instead of silently
        // taking the session over. A matching instance id is the same process
        // reconnecting, which keeps the takeover behavior below. Legacy
        // sessions without an instance id keep the old takeover behavior.
        if (!db_key.empty()) {
            for (const auto& other : online) {
                if (other == new_session || other->retired) {
                    continue;
                }
                if (client_db_key(other->hw_id, other->identity) != db_key) {
                    continue;
                }
                bool same_instance =
                    (!other->instance.empty() && other->instance == new_session->instance);
                bool both_legacy =
                    (other->instance.empty() && new_session->instance.empty());
                if (!same_instance && !both_legacy) {
                    srvlog::error("REFUSED", session_label(new_session), "",
                                  "duplicate client " + db_key +
                                      ", already " + session_label(other) + " (instance " +
                                      (new_session->instance.empty() ? "none"
                                                                     : new_session->instance) +
                                      " vs " +
                                      (other->instance.empty() ? "none" : other->instance) +
                                      ")");
                    return "ALREADY_CONNECTED";
                }
            }
        }

        // One-time migration: an address row left behind under this client's
        // old static identity is moved onto its hardware id, so the upgrade
        // does not cost the client its address. A no-op once it has run.
        if (!new_session->identity.empty() && !new_session->hw_id.empty() &&
            db_key != new_session->identity &&
            db_adopt_key(new_session->identity, db_key)) {
            srvlog::event("MIGRATE", session_label(new_session), "",
                          "address row moved " + new_session->identity + " -> " + db_key);
        }

        // A client that reconnects while its old session is still open must
        // keep the SAME address (the row is keyed by the hardware id). Drop the
        // stale session instead of handing out a different (drifting) IP.
        if (!db_key.empty()) {
            std::string existing = db_lookup_ip(db_key);
            if (!existing.empty()) {
                for (const auto& other : online) {
                    if (other != new_session && other->virtual_ip == existing) {
                        other->retired = true;
                        if (other->sock != INVALID_SOCKET) {
                            closesocket(other->sock);
                        }
                    }
                }
                for (auto it = online.begin(); it != online.end();) {
                    if (*it != new_session && (*it)->retired) {
                        unindex_session(*it);
                        it = online.erase(it);
                    } else {
                        ++it;
                    }
                }
                // free the address if no other session still holds it
                bool still_used = false;
                for (const auto& other : online) {
                    if (other != new_session && other->virtual_ip == existing) {
                        still_used = true;
                        break;
                    }
                }
                if (!still_used) {
                    active_ips.erase(existing);
                }
            }
        }

        new_session->virtual_ip = assign_virtual_ip(db_key, "");
        if (new_session->virtual_ip.empty() ||
            new_session->virtual_ip == server_virtual_ip()) {
            srvlog::error("NO ADDR", session_label(new_session), "", "client pool exhausted");
            return "NO_ADDRESS";
        }

        // Final invariant: one address, one session. assign_virtual_ip() has
        // already screened live sessions and database mappings; if this claim
        // still fails, refusing the connection beats running two sessions on
        // one address.
        if (!claim_active_ip(new_session->virtual_ip)) {
            srvlog::error("COLLISION", session_label(new_session), new_session->virtual_ip,
                          "address already held by a live session");
            return "NO_ADDRESS";
        }

        // Bandwidth cap for this client: server.ini default, or the override
        // an admin set for this address / hardware id.
        limits::apply(*new_session);

        online.push_back(new_session);
        // Relay lookups: virtual IP -> session (directed) and endpoint -> session
        // (filled on the first frame).
        index_session(new_session);
        member_count = online.size();
    }

    std::string response = "YOUR_IP:" + new_session->virtual_ip +
                           " RELAY_PORT:" + std::to_string(relay_port);
    response += server_network_state_tokens(new_session.get());
    // CA fingerprint: lets the client notice a rotated (restarted) CA without
    // an extra round trip, so it can re-enroll and refresh its trust store.
    std::string ca_fp = ca::fingerprint();
    if (!ca_fp.empty()) {
        response += " CAFP:" + ca_fp;
    }

    // What kind of assignment this was: an explicit static identity, an address
    // remembered by hardware id (every current client), or a one-off dynamic
    // address for a client that sends neither.
    std::string kind = "dynamic";
    if (!new_session->hw_id.empty()) {
        kind = "kept by hw id";
    } else if (!new_session->identity.empty()) {
        kind = "static " + new_session->identity;
    }
    srvlog::event("ASSIGN", session_label(new_session), new_session->virtual_ip,
                  kind + ", members " + std::to_string(member_count));
    note_client_seen(db_key);
    // Publish the address in the federation location table (replicas forward
    // it to the primary, which tells the other servers).
    fed::note_client_online(new_session->virtual_ip, db_key);

    session = new_session;
    closes = false;  // the connection now carries the session keepalive
    return response;
}
