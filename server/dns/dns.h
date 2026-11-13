// server/dns/dns.h
//
// Minimal DNS server on port 53 (UDP + TCP) answering .p2p (and other TLD)
// queries from domain.db. UDP answers are truncated with TC when they do not
// fit; the client then retries over TCP.
#ifndef ROOTLAYER_SERVER_DNS_H
#define ROOTLAYER_SERVER_DNS_H

#include "core/win_headers.h"

std::string dns_lookup_name(const std::string& name, int& out_ttl,
                            std::string* out_info = NULL);
int build_dns_response(const unsigned char* query, int qlen,
                       unsigned char* out, int out_size,
                       const std::string& answer_ip, int ttl);
// Build a DNS TXT record answer. Returns response length or -1 on error.
int build_txt_response(const unsigned char* query, int qlen,
                       unsigned char* out, int out_size,
                       const std::string& txt_data, int ttl);
std::string dns_parse_qname(const unsigned char* query, int qlen, int& offset);

// UDP responder; answers are truncated with TC when they exceed the size the
// client announced.
void dns_thread();

// TCP responder on the same port: length-prefixed queries and answers, no
// truncation.
void dns_tcp_thread();

#endif  // ROOTLAYER_SERVER_DNS_H
