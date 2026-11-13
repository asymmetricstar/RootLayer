// server/net/net.cpp - UDP relay thread + TCP signaling handler.
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

// Relay thread: receive a frame from one client, hand it to every other client
// and to the gateway adapter.
void relay_thread() {
    char buffer[65535];

    while (relay_running) {
        sockaddr_in sender;
        int sender_len = sizeof(sender);
        int len = recvfrom(relay_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_len);

        if (len <= 0) {
            if (!relay_running) {
                break;
            }
            Sleep(1);
            continue;
        }

        // Anything that reaches the relay during startup is dropped: there is
        // no gateway or session table to hand it to yet.
        if (!server_ready.load()) continue;

        std::shared_ptr<Session> source;
        std::vector<sockaddr_in> targets;
        bool do_gateway_write = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);

            // Learn the real source endpoint: NAT may rewrite the UDP port that
            // the client announced over the control channel, so the declared port
            // alone is not enough. Fall back to the virtual-IP octet embedded in
            // the HELLO probe, and finally to the only session sharing the
            // sender's public address.
            for (const auto& session : online) {
                if (session->endpoint_known &&
                    session->endpoint.sin_addr.s_addr == sender.sin_addr.s_addr &&
                    session->endpoint.sin_port == sender.sin_port) {
                    source = session;
                    break;
                }
            }

            if (!source) {
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                uint16_t sender_port = ntohs(sender.sin_port);
                for (const auto& session : online) {
                    if (session->public_ip == sender_ip && session->udp_port == sender_port) {
                        source = session;
                        break;
                    }
                }
            }

            // HELLO probe carries the sender's virtual-IP last octet so NAT
            // rewrites do not break endpoint learning.
            if (!source && len >= 7 && (unsigned char)buffer[0] == 0x01 &&
                memcmp(buffer + 1, "HELLO", 5) == 0) {
                unsigned char octet = (unsigned char)buffer[6];
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                std::vector<std::shared_ptr<Session>> candidates;
                for (const auto& session : online) {
                    if (session->public_ip != sender_ip) continue;
                    size_t last_dot = session->virtual_ip.find_last_of('.');
                    if (last_dot == std::string::npos) continue;
                    int vo = std::atoi(session->virtual_ip.c_str() + last_dot + 1);
                    if (vo >= 0 && vo <= 255 && (unsigned char)vo == octet) {
                        candidates.push_back(session);
                    }
                }
                if (candidates.size() == 1) {
                    source = candidates.front();
                }
            }

            if (!source) {
                std::string sender_ip = inet_ntoa(sender.sin_addr);
                std::vector<std::shared_ptr<Session>> matching;
                for (const auto& session : online) {
                    if (session->public_ip == sender_ip) matching.push_back(session);
                }
                if (matching.size() == 1) {
                    source = matching.front();
                }
            }

            if (!source) {
                continue;  // not a registered member, drop the frame
            }

            if (!source->endpoint_known) {
                source->endpoint = sender;
                source->endpoint_known = true;
                std::cout << "Relay endpoint learned for " << source->virtual_ip
                          << ": " << inet_ntoa(sender.sin_addr) << ":" << ntohs(sender.sin_port) << std::endl;
            }

            // Anything shorter than an Ethernet header is a registration probe
            // sent right after connecting: it only teaches us the endpoint.
            if (len < 14) {
                continue;
            }

            for (const auto& session : online) {
                if (!session->endpoint_known || session == source) {
                    continue;
                }
                targets.push_back(session->endpoint);
            }

            do_gateway_write = (gateway_tap != INVALID_HANDLE_VALUE);
        }

        for (const auto& target : targets) {
            sendto(relay_sock, buffer, len, 0, (sockaddr*)&target, sizeof(target));
        }

        if (do_gateway_write) {
            queue_tap_frame(buffer, len);
        }
    }
}
// Gateway, mask and TLD list a client needs to configure itself. Shared by the
// registration response and the "STATE" answer on the control channel, so a
// moved gateway or a changed TLD list also reaches a client that is already
// connected.
static std::string server_network_state_tokens() {
    if (gateway_tap == INVALID_HANDLE_VALUE) {
        return "";
    }

    std::string out = " GATEWAY:" + server_virtual_ip();
    out += " MASK:" + ip_to_string(virtual_ip_mask);

    // Virtual TLDs this server is authoritative for. The client turns them into
    // NRPT rules pointing at GATEWAY, so only these names are sent to the
    // tunnel DNS server; the address and the list both come from here, never
    // from a hardcoded client default.
    std::string tlds;
    for (const auto& suffix : arpa_suffixes) {
        if (suffix.empty()) continue;
        if (!tlds.empty()) tlds += ",";
        tlds += suffix;
    }
    if (!tlds.empty()) {
        out += " TLD:" + tlds;
    }
    return out;
}

void handle_client(SOCKET client_sock, sockaddr_in client_addr) {
    // Read the first chunk (the normal signaling request fits in here).
    char buf[8192];
    ZeroMemory(buf, sizeof(buf));
    int len = recv(client_sock, buf, sizeof(buf) - 1, 0);
    std::string request = (len > 0) ? std::string(buf, len) : std::string();

    // Administrative requests come from console.exe, which runs on the server
    // machine: they are answered here and never over the tunnel or the LAN.
    if (request.rfind("ADMIN", 0) == 0) {
        std::string response;
        if (!admin_peer_allowed(client_addr)) {
            response = "ADMIN_ERR:local_only";
            std::cout << "Admin request from " << inet_ntoa(client_addr.sin_addr)
                      << " REJECTED [admin: local_only]" << std::endl;
        } else {
            admin_request(trim(request), response);
            std::cout << "Admin from " << inet_ntoa(client_addr.sin_addr) << ": "
                      << trim(request) << " -> " << response.substr(0, 60) << std::endl;
        }
        send_line(client_sock, response);
        closesocket(client_sock);
        return;
    }

    // CA one-shot requests: accumulate the rest of the payload (CSRs can be
    // larger than one recv).
    if (request.find("CSR:") != std::string::npos ||
        request.find("CA_CERT") != std::string::npos ||
        request.find("CA_CSR") != std::string::npos ||
        request.find("SRV_CERT") != std::string::npos) {
        // Give the client time to finish sending.
        DWORD t = 3000;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
        for (;;) {
            int r = recv(client_sock, buf, sizeof(buf) - 1, 0);
            if (r <= 0) break;
            buf[r] = 0;
            request.append(buf, r);
            if (request.size() > 1 << 20) break;  // safety cap
        }

        std::string peer = std::string(inet_ntoa(client_addr.sin_addr)) + ":" +
                           std::to_string(ntohs(client_addr.sin_port));

        if (request.find("CA_CERT") != std::string::npos) {
            std::string pem = ca::ca_cert_pem();
            if (!pem.empty()) {
                send_line(client_sock, "CACERT:" + ca::base64_encode(pem));
                std::cout << "CA certificate sent to " << peer
                          << " [cert: CA OK SHA256 " << ca::fingerprint() << "]" << std::endl;
            } else {
                send_line(client_sock, "CA_ERR:cert_unavailable");
                std::cout << "CA certificate request from " << peer
                          << " REJECTED [cert: CA unavailable]" << std::endl;
            }
            closesocket(client_sock);
            return;
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
            const bool loopback = client_addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK);

            if (name.empty() || ip.empty()) {
                send_line(client_sock, "SRV_ERR:name_not_registered");
                std::cout << "Server certificate request from " << peer
                          << " REJECTED [cert: name_not_registered]" << std::endl;
            } else if (!loopback && (identity.empty() || owner != identity)) {
                send_line(client_sock, "SRV_ERR:not_owner");
                std::cout << "Server certificate request for " << name << " from " << peer
                          << " REJECTED [cert: not_owner]" << std::endl;
            } else {
                std::vector<std::string> names;
                names.push_back(name);
                if (name.rfind("www.", 0) != 0) names.push_back("www." + name);

                std::string key_pem;
                const std::string cert_pem = ca::issue_server_cert(names, 397, &key_pem);
                if (cert_pem.empty() || key_pem.empty()) {
                    send_line(client_sock, "SRV_ERR:sign_failed");
                    std::cout << "Server certificate request for " << name << " from " << peer
                              << " FAILED [cert: sign_failed]" << std::endl;
                } else {
                    std::string resp = "SRVCERT:" + ca::base64_encode(cert_pem);
                    resp += "\nSRVKEY:" + ca::base64_encode(key_pem);
                    const std::string ca_pem = ca::ca_cert_pem();
                    if (!ca_pem.empty()) resp += "\nCACERT:" + ca::base64_encode(ca_pem);
                    send_line(client_sock, resp);
                    std::cout << "Server certificate issued for " << name << " (" << peer << ")"
                              << " [cert: valid 397 days, SHA256 " << ca::fingerprint() << "]"
                              << std::endl;
                }
            }
            closesocket(client_sock);
            return;
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
            send_line(client_sock, "CA_ERR:missing_csr");
            std::cout << "Certificate request from " << peer
                      << " REJECTED [cert: missing_csr]" << std::endl;
            closesocket(client_sock);
            return;
        }
        std::string csr_pem = ca::base64_decode(b64);
        std::string cn;
        // The certificate CN is the assigned virtual IP, so the client names
        // itself here and the server remembers the alias.
        std::string csr_identity = token_value(request, "IDENTITY");
        if (csr_identity.size() > 64) csr_identity.clear();
        std::string cert = ca::sign_csr(csr_pem, &cn, csr_identity);
        if (cert.empty()) {
            send_line(client_sock, "CA_ERR:sign_failed");
            std::cout << "Certificate request from " << peer
                      << " REJECTED [cert: sign_failed]" << std::endl;
            closesocket(client_sock);
            return;
        }
        std::string ca_pem = ca::ca_cert_pem();
        std::string resp = "CERT:" + ca::base64_encode(cert);
        if (!ca_pem.empty()) resp += "\nCACERT:" + ca::base64_encode(ca_pem);
        send_line(client_sock, resp);
        std::cout << "Certificate issued for CN=" << (cn.empty() ? std::string("(none)") : cn)
                  << " to " << peer
                  << " [" << (cn.empty() ? std::string("ISSUED") : ca::cert_status_for(cn))
                  << "]" << std::endl;
        closesocket(client_sock);
        return;
    }

    // Early client: answer clearly and close, so it retries instead of
    // holding a half-configured session.
    if (!server_ready.load()) {
        send_line(client_sock, "SERVER_STARTING Retry in a few seconds.");
        closesocket(client_sock);
        std::cout << "Rejected client " << inet_ntoa(client_addr.sin_addr)
                  << ": server still starting" << std::endl;
        return;
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
            send_line(client_sock, resp);
        } else {
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
                        send_line(client_sock, resp);
                        closesocket(client_sock);
                        return;
                    }
                }
            }
            send_line(client_sock, "ARPA_ERR:" + arpa_query + " CODE:not_found");
        }
        closesocket(client_sock);
        return;
    }
    std::string public_ip = inet_ntoa(client_addr.sin_addr);

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

    // Incoming connection log, with the certificate status of the identity
    // that just showed up (issued by the current in-memory CA).
    std::cout << "Client connected from " << public_ip << ":" << ntohs(client_addr.sin_port)
              << " (" << trim(request) << ")"
              << " [cert: " << ca::cert_status_for(identity) << "]" << std::endl;

    size_t member_count = 0;

    auto session = std::make_shared<Session>();
    session->sock = client_sock;
    session->identity = identity;
    session->instance = instance;
    session->public_ip = public_ip;
    session->udp_port = udp_port;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);

        // Double-connection guard: a live session with the same identity but
        // a DIFFERENT process instance means a second client.exe is running
        // (or another machine reuses this identity) - refuse it instead of
        // silently taking the session over. A matching instance id is the
        // same process reconnecting, which keeps the takeover behavior below.
        // Two legacy sessions without an instance id cannot be told apart,
        // so they keep the old takeover behavior.
        if (!session->identity.empty()) {
            for (const auto& other : online) {
                if (other == session || other->retired || other->identity != session->identity) {
                    continue;
                }
                bool same_instance = (!other->instance.empty() && other->instance == session->instance);
                bool both_legacy = (other->instance.empty() && session->instance.empty());
                if (!same_instance && !both_legacy) {
                    std::cerr << "Duplicate connection refused: " << public_ip << ":" << udp_port
                              << " identity " << session->identity
                              << " already connected from " << other->public_ip << ":" << other->udp_port
                              << " (instance " << (session->instance.empty() ? "none" : session->instance)
                              << " vs " << (other->instance.empty() ? "none" : other->instance) << ")"
                              << std::endl;
                    send_line(client_sock, "ALREADY_CONNECTED");
                    closesocket(client_sock);
                    return;
                }
            }
        }

        // A static client that reconnects while its old session is still open
        // must keep the SAME address. Drop the stale session instead of handing
        // out a different (drifting) IP.
        if (!session->identity.empty()) {
            std::string existing = db_lookup_ip(session->identity);
            if (!existing.empty()) {
                for (const auto& other : online) {
                    if (other != session && other->virtual_ip == existing) {
                        other->retired = true;
                        closesocket(other->sock);
                    }
                }
                online.erase(std::remove_if(online.begin(), online.end(),
                    [session](const std::shared_ptr<Session>& s) {
                        return s != session && s->retired;
                    }), online.end());
                // free the address if no other session still holds it
                bool still_used = false;
                for (const auto& other : online) {
                    if (other != session && other->virtual_ip == existing) { still_used = true; break; }
                }
                if (!still_used) {
                    active_ips.erase(existing);
                }
            }
        }

        session->virtual_ip = assign_virtual_ip(session->identity, "");
        if (session->virtual_ip.empty() || session->virtual_ip == server_virtual_ip()) {
            std::cerr << "No free virtual address left for " << public_ip << ":" << udp_port << std::endl;
            send_line(client_sock, "NO_ADDRESS");
            closesocket(client_sock);
            return;
        }

        // Final invariant: one address, one session. assign_virtual_ip() has
        // already screened live sessions and database mappings; if this claim
        // still fails, refusing the connection beats running two sessions on
        // one address.
        if (!claim_active_ip(session->virtual_ip)) {
            std::cerr << "IP collision blocked: " << session->virtual_ip
                      << " is already held by a live session; refusing "
                      << public_ip << ":" << udp_port << std::endl;
            send_line(client_sock, "NO_ADDRESS");
            closesocket(client_sock);
            return;
        }
        online.push_back(session);
        member_count = online.size();
    }

    std::string response = "YOUR_IP:" + session->virtual_ip +
                           " RELAY_PORT:" + std::to_string(relay_port) +
                           " MEMBERS:" + std::to_string(member_count);
    response += server_network_state_tokens();
    // CA fingerprint: lets the client notice a rotated (restarted) CA without
    // an extra round trip, so it can re-enroll and refresh its trust store.
    std::string ca_fp = ca::fingerprint();
    if (!ca_fp.empty()) {
        response += " CAFP:" + ca_fp;
    }

    // Name registrations are server-side only (admin adds names to domain.db).
    // Clients do not register names over the control channel.

    send_line(client_sock, response);

    std::cout << "Assigned " << session->virtual_ip
              << (session->identity.empty() ? " (dynamic)" : " (static " + session->identity + ")")
              << " to client " << session->public_ip << ":" << session->udp_port
              << " [" << online.size() << " member(s)]" << std::endl;

    // Clients send a keepalive every 5 seconds; give them plenty of slack
    // before declaring the session dead.
    DWORD monitor_timeout = 60000;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&monitor_timeout, sizeof(monitor_timeout));

    char keepalive[128];
    for (;;) {
        int received = recv(client_sock, keepalive, sizeof(keepalive) - 1, 0);
        if (received > 0) {
            keepalive[received] = '\0';
            // "PING STATE" asks for the current network state: answer with the
            // same fields the registration response carries, so a client can
            // follow a moved gateway or a changed TLD list without dropping the
            // session. Legacy clients only send "PING" and get no answer.
            if (strstr(keepalive, "STATE") != NULL) {
                send_line(client_sock, "STATE" + server_network_state_tokens());
            }
            continue;  // keepalive
        }
        break;         // closed or timed out
    }

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        online.erase(std::remove(online.begin(), online.end(), session), online.end());
        if (!session->retired) {
            active_ips.erase(session->virtual_ip);
        }
    }

    closesocket(client_sock);

    std::cout << "Session closed for " << session->public_ip << ":" << session->udp_port
              << " (" << session->virtual_ip << ")" << std::endl;
}
