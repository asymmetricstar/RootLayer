
// client/net/tunnel.h
//
// The two data path threads moving frames between the TAP handle and UDP.
#ifndef ROOTLAYER_TUNNEL_H
#define ROOTLAYER_TUNNEL_H

void tap_to_udp_thread();
void udp_to_tap_thread();

#endif  // ROOTLAYER_TUNNEL_H
