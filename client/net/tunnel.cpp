// client/net/tunnel.cpp - tunnel device (Wintun) <-> UDP packet pumps.
//
// The tunnel carries bare IPv4/IPv6 packets: Wintun is a TUN device, so no
// Ethernet header is added or stripped and no MAC/ARP handling exists.
#include "core/win_headers.h"
#include "core/state.h"
#include "core/json.h"
#include "net/tunnel.h"
#include "netdev/wintun.h"

void tap_to_udp_thread() {
    char buffer[65535];
    int consecutive_timeouts = 0;

    while (netdev::is_open() && udp_sock != INVALID_SOCKET) {
        // 500 ms timeout so a shutdown is noticed while the ring is idle.
        int bytes_read = netdev::read_packet(buffer, sizeof(buffer), 500);

        if (bytes_read < 0) {
            if (g_shutdown || udp_sock == INVALID_SOCKET) {
                break;
            }
            json_event("error", std::string("\"code\":\"tun_read_failed\",") +
                                    json_string_field("detail", netdev::error_text()));
            break;
        }

        if (bytes_read == 0) {
            if (++consecutive_timeouts == 20 && !g_shutdown) {
                json_event("warning", "\"code\":\"tun_read_idle\"");
            }
            continue;
        }

        consecutive_timeouts = 0;

        sockaddr_in target;
        {
            std::lock_guard<std::mutex> lock(tunnel_mutex);
            if (!peer_valid) {
                if (fallback_target_valid) {
                    target = fallback_target;  // probe the relay until peer is known
                } else {
                    continue;  // no target at all, drop the packet
                }
            } else {
                target = peer_addr;
            }
        }
        sendto(udp_sock, buffer, bytes_read, 0, (sockaddr*)&target, sizeof(target));
        frames_from_tap++;
    }
}

void udp_to_tap_thread() {
    char buffer[65535];
    sockaddr_in sender_addr;
    int sender_addr_len = sizeof(sender_addr);

    while (netdev::is_open() && udp_sock != INVALID_SOCKET) {
        sender_addr_len = sizeof(sender_addr);
        int bytes_received = recvfrom(udp_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender_addr, &sender_addr_len);
        if (bytes_received > 0) {
            // The relay is the only sender on this socket. Follow its source
            // address in case a NAT rewrote the port.
            {
                std::lock_guard<std::mutex> lock(tunnel_mutex);
                peer_addr = sender_addr;
                peer_valid = true;
            }

            if (!netdev::write_packet(buffer, bytes_received)) {
                json_event("error", std::string("\"code\":\"tun_write_failed\",") +
                                        json_string_field("detail", netdev::error_text()));
                break;
            }
            frames_to_tap++;
        } else {
            if (g_shutdown || udp_sock == INVALID_SOCKET) {
                break;
            }
            // A UDP socket can report transient errors (for example
            // WSAECONNRESET after an ICMP port unreachable); keep listening.
            Sleep(10);
        }
    }
}
