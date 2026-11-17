// server/net/net.cpp - UDP relay thread.
//
// The control channel lives in net/control.cpp (protocol) and net/signaling.cpp
// (poll loop); this file only forwards frames.
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/utils.h"
#include "session/session.h"
#include "gateway/gateway.h"
#include "net/net.h"
#include "core/guard.h"
#include "core/log.h"
#include "core/limits.h"
#include "federation/federation.h"

#include <cctype>

namespace {

// How a member appears in the server log: its hardware id, never the public
// address it connected from.
std::string session_label(const std::shared_ptr<Session>& session) {
    if (!session || session->hw_id.empty()) {
        return "hw:unknown";
    }
    return session->hw_id;
}

}  // namespace

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

        // Shield: malformed, over-budget and unfair sources are dropped here,
        // before the (much more expensive) session lookup below.
        if (!guard::allow_datagram((uint32_t)ntohl(sender.sin_addr.s_addr), len)) {
            continue;
        }

        std::shared_ptr<Session> source;
        // Sessions, not plain endpoints: each target's download bucket is
        // charged while the frame is being handed out.
        std::vector<std::shared_ptr<Session>> targets;
        bool do_gateway_write = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);

            // Steady state: the endpoint was learned on the first frame, so the
            // sender resolves with one hash lookup instead of a scan over every
            // member. This is the path every forwarded packet takes.
            auto known = sessions_by_endpoint.find(endpoint_key(sender));
            if (known != sessions_by_endpoint.end()) {
                source = known->second;
            }

            // First frame of a session: NAT may rewrite the UDP port that the
            // client announced over the control channel, so the declared port
            // alone is not enough. Fall back to the virtual-IP octet embedded in
            // the HELLO probe, and finally to the only session sharing the
            // sender's public address.
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

            // Per-client upload cap (client -> segment). A client over its band
            // simply does not get its frame forwarded; the bucket refills while
            // it stays quiet.
            if (!source->upload.allow((size_t)len)) {
                continue;
            }

            if (!source->endpoint_known) {
                source->endpoint = sender;
                source->endpoint_known = true;
                index_session(source);
                srvlog::event("RELAY", session_label(source), source->virtual_ip,
                              "endpoint learned");
            }

            // The tunnel carries bare IP packets (Wintun is a layer-3 device),
            // so anything that is not an IPv4/IPv6 header is a registration
            // probe sent right after connecting: it only teaches the endpoint.
            const bool ipv4 = len >= 20 && ((unsigned char)buffer[0] >> 4) == 4;
            const bool ipv6 = len >= 40 && ((unsigned char)buffer[0] >> 4) == 6;
            if (!ipv4 && !ipv6) {
                continue;
            }

            // A packet addressed to a known member goes only to that member.
            // Broadcast/multicast and unknown destinations still reach the
            // whole segment, exactly like the unconditional flood did.
            std::string destination;
            bool directed = false;
            if (ipv4) {
                in_addr dst;
                memcpy(&dst.s_addr, buffer + 16, sizeof(dst.s_addr));
                destination = inet_ntoa(dst);
                const size_t last_dot = destination.find_last_of('.');
                const int first_octet = std::atoi(destination.c_str());
                const int last_octet = last_dot == std::string::npos
                                           ? -1
                                           : std::atoi(destination.c_str() + last_dot + 1);
                const bool multicast = first_octet >= 224 && first_octet <= 239;
                directed = !multicast && last_octet != 255;
            }

            if (directed) {
                // One hash lookup for the destination instead of a scan.
                auto hit = sessions_by_ip.find(destination);
                if (hit != sessions_by_ip.end()) {
                    const std::shared_ptr<Session>& target = hit->second;
                    if (target != source && target->endpoint_known &&
                        target->download.allow((size_t)len)) {
                        targets.push_back(target);
                    }
                }
            }

            // Federation data plane: a directed packet for another server's
            // address block is wrapped and sent straight to that server. The
            // primary is not a hub, so this happens server to server only.
            // Broadcast/multicast never crosses the link (rule 9), and local
            // destinations are decided above, never through the link.
            bool federated = false;
            if (targets.empty() && directed) {
                federated = fed::forward_packet(buffer, len);
            }

            if (targets.empty() && !federated) {
                for (const auto& session : online) {
                    if (!session->endpoint_known || session == source) {
                        continue;
                    }
                    // Per-client download cap (segment -> client). Charged here,
                    // under sessions_mutex, so the bucket is never touched from
                    // two threads.
                    if (!session->download.allow((size_t)len)) {
                        continue;
                    }
                    targets.push_back(session);
                }
                // Nothing on the segment matched (the gateway address itself,
                // a broadcast, or an internet destination): let the host stack
                // route it. A packet that was handed to a client or to a peer
                // above is not written to the gateway as well, which would
                // loop it back.
                do_gateway_write = gateway_active.load();
            }
        }

        for (const auto& target : targets) {
            sendto(relay_sock, buffer, len, 0, (sockaddr*)&target->endpoint,
                   sizeof(target->endpoint));
        }

        if (do_gateway_write) {
            queue_tap_frame(buffer, len);
        }
    }
}
