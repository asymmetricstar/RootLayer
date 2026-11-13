// server/dns/dns.cpp - minimal DNS server on port 53 (UDP + TCP).
#include "core/win_headers.h"
#include "core/globals.h"
#include "core/config.h"
#include "arpa/arpa.h"
#include "dns/dns.h"

#include <map>

namespace {

// One UDP attempt to a delegated name server. A LAN round trip is a
// millisecond away, so a short wait plus a retransmit recovers from a lost
// first packet (cold neighbour entry) far faster than a single long timeout:
// the retry lands right after the MAC lookup completes, instead of the client
// waiting out the whole timeout and starting over.
const int kForwardTimeoutMs = 250;
const int kForwardAttempts = 6;

// TCP adds the handshake, so it gets its own, more generous budget.
const int kForwardTcpTimeoutMs = 1000;

// No DNS message can be longer than its 16-bit TCP length prefix.
const int kMaxDnsMessage = 65535;

// Largest UDP payload a client is told to expect. Anything bigger is answered
// with TC=1 so the resolver retries over TCP.
const int kMaxUdpPayload = 4096;

// Copies the question with an empty answer section; `rcode` 0 is NODATA,
// 2 SERVFAIL, 3 NXDOMAIN.
int build_status_response(const unsigned char* query, int qlen,
                          unsigned char* out, int out_size, int rcode) {
    int len = build_dns_response(query, qlen, out, out_size, "", 60);
    if (len > 0) out[3] = (unsigned char)((out[3] & 0xF0) | (rcode & 0x0F));
    return len;
}

// DNS over TCP frames every message behind a 2-byte length prefix, so reads
// and writes have to be completed by hand.
bool recv_exact(SOCKET sock, unsigned char* dst, int len) {
    int done = 0;
    while (done < len) {
        int got = recv(sock, (char*)dst + done, len - done, 0);
        if (got <= 0) return false;
        done += got;
    }
    return true;
}

bool send_exact(SOCKET sock, const unsigned char* src, int len) {
    int done = 0;
    while (done < len) {
        int sent = send(sock, (const char*)src + done, len - done, 0);
        if (sent <= 0) return false;
        done += sent;
    }
    return true;
}

// Walks the parent chain of `name` (www.root.name -> root.name -> name) and
// returns the address of the closest registered domain there, which is the
// name server owning that domain's subdomains. Empty when no ancestor is
// registered here - the name then really does not exist.
std::string delegated_parent_ip(const std::string& name) {
    std::string current = name;
    for (char& c : current) c = (char)tolower((unsigned char)c);
    if (!current.empty() && current.back() == '.') current.pop_back();

    for (;;) {
        size_t dot = current.find('.');
        if (dot == std::string::npos || dot + 1 >= current.size()) return "";
        current = current.substr(dot + 1);

        int ttl = 60;
        std::string ip = arpa_lookup(current, &ttl, NULL);
        if (!ip.empty()) {
            // A domain pointing back at this server would be forwarded to
            // itself; treat it as owned here instead of looping.
            if (ip == server_virtual_ip() || ip == "127.0.0.1") return "";
            return ip;
        }
    }
}

// Same query, same name server, over TCP. Needed when the name server truncates
// its own UDP reply because the record set does not fit.
int forward_to_nameserver_tcp(const unsigned char* query, int qlen,
                              const std::string& upstream_ip,
                              unsigned char* out, int out_size) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return -1;

    DWORD timeout = kForwardTcpTimeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(upstream_ip.c_str());

    int result = -1;
    std::vector<unsigned char> reply(kMaxDnsMessage);
    const unsigned char prefix[2] = { (unsigned char)((qlen >> 8) & 0xFF),
                                      (unsigned char)(qlen & 0xFF) };

    if (addr.sin_addr.s_addr != INADDR_NONE &&
        connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0 &&
        send_exact(sock, prefix, 2) &&
        send_exact(sock, query, qlen) &&
        recv_exact(sock, reply.data(), 2)) {
        const int rlen = (reply[0] << 8) | reply[1];
        if (rlen > 12 && rlen <= out_size && recv_exact(sock, out, rlen)) {
            result = rlen;
        }
    }

    shutdown(sock, SD_BOTH);
    closesocket(sock);
    return result;
}

// Offset just past the question section, or -1 when the packet is malformed.
int question_end(const unsigned char* msg, int len) {
    int pos = 12;
    while (pos < len) {
        const unsigned char label = msg[pos];
        if (label == 0) {
            const int end = pos + 1 + 4;  // + QTYPE + QCLASS
            return end <= len ? end : -1;
        }
        if (label & 0xC0) return -1;  // a question never uses compression
        pos += 1 + label;
    }
    return -1;
}

// With one long-lived upstream socket, a late answer to an earlier query could
// otherwise be handed to the wrong client: ID and question must both match.
bool reply_matches(const unsigned char* query, int qlen,
                   const unsigned char* reply, int reply_len) {
    if (reply_len < 12 || query[0] != reply[0] || query[1] != reply[1]) return false;
    const int q_end = question_end(query, qlen);
    if (q_end < 0 || q_end > reply_len) return false;
    return memcmp(query + 12, reply + 12, (size_t)(q_end - 12)) == 0;
}

// Upstream sockets stay open. Creating one per query means the first datagram
// to the name server is lost while its MAC address is still being resolved,
// which is what turned the first answer into a multi-second wait.
std::mutex g_upstream_mutex;
std::map<std::string, SOCKET> g_upstream_sockets;

// Assumes g_upstream_mutex is held.
SOCKET upstream_socket(const std::string& ip) {
    auto existing = g_upstream_sockets.find(ip);
    if (existing != g_upstream_sockets.end()) return existing->second;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    if (addr.sin_addr.s_addr == INADDR_NONE ||
        connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    g_upstream_sockets[ip] = sock;
    return sock;
}

// A connected UDP socket reports ICMP errors on the next call, so a socket
// that failed is dropped and the next attempt builds a fresh one.
void drop_upstream_socket(const std::string& ip) {
    auto existing = g_upstream_sockets.find(ip);
    if (existing == g_upstream_sockets.end()) return;
    closesocket(existing->second);
    g_upstream_sockets.erase(existing);
}

// Relays the raw query to `upstream_ip`:53 and copies the reply verbatim, so
// flags, EDNS options, RCODE and TTLs survive the hop. The query is
// retransmitted because the very first datagram to the name server can be lost
// while its MAC address is being resolved. -1 when it stays silent.
int forward_to_nameserver(const unsigned char* query, int qlen,
                          const std::string& upstream_ip,
                          unsigned char* out, int out_size) {
    const auto started = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_upstream_mutex);

    for (int attempt = 0; attempt < kForwardAttempts; ++attempt) {
        SOCKET up = upstream_socket(upstream_ip);
        if (up == INVALID_SOCKET) return -1;

        if (send(up, (const char*)query, qlen, 0) != qlen) {
            drop_upstream_socket(upstream_ip);
            continue;
        }

        for (;;) {
            fd_set readers;
            FD_ZERO(&readers);
            FD_SET(up, &readers);
            timeval timeout;
            timeout.tv_sec = kForwardTimeoutMs / 1000;
            timeout.tv_usec = (kForwardTimeoutMs % 1000) * 1000;
            if (select(0, &readers, NULL, NULL, &timeout) <= 0) break;  // retransmit

            int reply_len = recv(up, (char*)out, out_size, 0);
            if (reply_len <= 12) {
                drop_upstream_socket(upstream_ip);
                break;
            }
            if (!reply_matches(query, qlen, out, reply_len)) continue;  // stale

            if ((out[2] & 0x02) != 0) {
                // The name server truncated its UDP answer: fetch the complete
                // record set over TCP before passing it on.
                const int tcp_len = forward_to_nameserver_tcp(query, qlen, upstream_ip,
                                                              out, out_size);
                if (tcp_len > 12) return tcp_len;
                break;
            }

            const long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::steady_clock::now() - started).count();
            if (elapsed >= 200) {
                std::cerr << "DNS forward to " << upstream_ip << " answered in "
                          << elapsed << " ms (attempt " << (attempt + 1) << ")" << std::endl;
            }
            return reply_len;
        }
    }

    const long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - started).count();
    std::cerr << "DNS forward to " << upstream_ip << " gave no answer after "
              << elapsed << " ms (" << kForwardAttempts << " attempts)" << std::endl;
    return -1;
}

// The UDP payload the client announced: 512 bytes unless its EDNS0 OPT record
// advertises more. Malformed packets fall back to the classic limit.
int udp_payload_limit(const unsigned char* query, int qlen) {
    if (qlen < 12) return 512;

    const int qd = (query[4] << 8) | query[5];
    const int an = (query[6] << 8) | query[7];
    const int ns = (query[8] << 8) | query[9];
    const int ar = (query[10] << 8) | query[11];

    int offset = 12;

    auto skip_name = [&](int& pos) {
        while (pos < qlen) {
            const unsigned char label = query[pos];
            if (label == 0) { ++pos; return true; }
            if ((label & 0xC0) == 0xC0) { pos += 2; return pos <= qlen; }
            if (label & 0xC0) return false;  // reserved label type
            pos += 1 + label;
        }
        return false;
    };

    for (int i = 0; i < qd; ++i) {
        if (!skip_name(offset) || offset + 4 > qlen) return 512;
        offset += 4;
    }
    // Answer and authority sections hold no OPT record; skip them so the
    // additional section below starts on the right byte.
    for (int i = 0; i < an + ns; ++i) {
        if (!skip_name(offset) || offset + 10 > qlen) return 512;
        const int rdlength = (query[offset + 8] << 8) | query[offset + 9];
        offset += 10 + rdlength;
        if (offset > qlen) return 512;
    }
    for (int i = 0; i < ar; ++i) {
        if (!skip_name(offset) || offset + 10 > qlen) return 512;
        const int type = (query[offset] << 8) | query[offset + 1];
        const int opt_size = (query[offset + 2] << 8) | query[offset + 3];  // OPT CLASS
        const int rdlength = (query[offset + 8] << 8) | query[offset + 9];
        offset += 10 + rdlength;
        if (offset > qlen) return 512;
        if (type == 41) {  // OPT: its CLASS field carries the UDP payload size
            if (opt_size < 512) return 512;
            return opt_size > kMaxUdpPayload ? kMaxUdpPayload : opt_size;
        }
    }
    return 512;
}

// Header + question with TC set: the answer did not fit into the client's UDP
// buffer, so it has to retry over TCP instead of caching a partial reply.
int truncate_response(const unsigned char* query, int qlen,
                      unsigned char* out, int out_size) {
    int len = build_status_response(query, qlen, out, out_size, 0);
    if (len <= 0) return -1;
    out[2] = (unsigned char)(out[2] | 0x02);  // TC
    return len;
}

// Builds the reply for one query: our own records first, the domain's name
// server for subdomains, NXDOMAIN for everything else. -1 when the packet
// cannot be answered at all.
int build_answer(const unsigned char* query, int qlen,
                 unsigned char* out, int out_size) {
    if (qlen < 12) return -1;
    if ((query[2] & 0x80) != 0) return -1;  // QR must be 0
    if ((query[2] & 0x78) != 0) return -1;  // OPCODE must be 0

    int qoffset = 12;
    std::string qname = dns_parse_qname(query, qlen, qoffset);
    if (qname.empty()) return -1;

    // Parse QTYPE (2 bytes right after the QNAME null terminator).
    if (qoffset + 4 > qlen) return -1;
    const uint16_t qtype = ((uint16_t)query[qoffset] << 8) | (uint16_t)query[qoffset + 1];

    // A single lookup decides whether this service owns the name: the address,
    // the TXT description and the TTL all come from the same read.
    int dns_ttl = 60;
    std::string txt_info;
    std::string answer_ip = dns_lookup_name(qname, dns_ttl, &txt_info);

    const bool is_txt = (qtype == 0x0010);
    const bool is_a = (qtype == 0x0001);

    if (!answer_ip.empty()) {
        if (is_txt) {
            // TXT answers carry domain_info; a registered name without one is
            // NODATA, not NXDOMAIN.
            return txt_info.empty()
                       ? build_status_response(query, qlen, out, out_size, 0)
                       : build_txt_response(query, qlen, out, out_size, txt_info, dns_ttl);
        }
        if (is_a) {
            return build_dns_response(query, qlen, out, out_size, answer_ip, dns_ttl);
        }
        // AAAA/MX/NS...: only IPv4 records live here, so report NODATA instead
        // of answering an A record to a foreign question type.
        return build_status_response(query, qlen, out, out_size, 0);
    }

    std::string name_server = delegated_parent_ip(qname);
    if (!name_server.empty()) {
        // A subdomain of a registered domain: that domain's name server holds
        // these records, so relay the query there. Answering our own NXDOMAIN
        // would make the client cache the failure and never ask at all.
        int rlen = forward_to_nameserver(query, qlen, name_server, out, out_size);
        if (rlen > 0) return rlen;
        // Silent name server: SERVFAIL so the resolver retries instead of
        // remembering a negative answer.
        return build_status_response(query, qlen, out, out_size, 2);
    }

    return is_txt ? build_txt_response(query, qlen, out, out_size, "", dns_ttl)
                  : build_dns_response(query, qlen, out, out_size, "", dns_ttl);
}

// Concurrent TCP clients; a resolver owns a few connections, not hundreds.
std::atomic<int> g_tcp_clients(0);
const int kMaxTcpClients = 64;

// One TCP client: length-prefixed queries, length-prefixed answers. The
// connection stays open so a resolver can pipeline its questions.
void serve_tcp_client(SOCKET sock) {
    DWORD timeout = 10000;  // a stalled client must not pin a thread forever
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    std::vector<unsigned char> query(kMaxDnsMessage);
    std::vector<unsigned char> response(kMaxDnsMessage);

    while (relay_running) {
        unsigned char length_bytes[2];
        if (!recv_exact(sock, length_bytes, 2)) break;
        const int qlen = (length_bytes[0] << 8) | length_bytes[1];
        if (qlen < 12) break;
        if (!recv_exact(sock, query.data(), qlen)) break;

        // TCP has no size limit to work around: the answer is never truncated.
        int rlen = build_answer(query.data(), qlen, response.data(), (int)response.size());
        if (rlen <= 0) break;

        const unsigned char prefix[2] = { (unsigned char)((rlen >> 8) & 0xFF),
                                          (unsigned char)(rlen & 0xFF) };
        if (!send_exact(sock, prefix, 2)) break;
        if (!send_exact(sock, response.data(), rlen)) break;
    }

    shutdown(sock, SD_SEND);
    closesocket(sock);
    g_tcp_clients.fetch_sub(1);
}

}  // namespace

std::string dns_lookup_name(const std::string& name, int& out_ttl,
                            std::string* out_info) {
    out_ttl = 60;
    // normalize: lowercase, strip trailing dot
    std::string n = name;
    for (char& c : n) c = (char)tolower((unsigned char)c);
    if (!n.empty() && n.back() == '.') n.pop_back();

    // must end with one of our suffixes (only our own TLDs, nothing else)
    bool has_suffix = false;
    for (const auto& suf : arpa_suffixes) {
        std::string sfx_dot = "." + suf;
        if (n.size() >= sfx_dot.size() + 1 &&
            n.compare(n.size() - sfx_dot.size(), sfx_dot.size(), sfx_dot) == 0) {
            has_suffix = true;
            break;
        }
    }
    if (!has_suffix) return "";
    if (arpa_db == NULL) return "";

    // The name service answers from its write buffer first, so a record is
    // resolvable the moment it is registered - before the disk commit.
    return arpa_lookup(n, &out_ttl, out_info);
}
int build_dns_response(const unsigned char* query, int qlen,
                       unsigned char* out, int out_size,
                       const std::string& answer_ip, int ttl) {
    if (qlen < 12 || out_size < 12) return -1;

    memcpy(out, query, 12);

    // Flags: set QR (response), AA (authoritative), RA (recursion available)
    unsigned char* flags = out + 2;
    flags[0] = 0x84;  // QR=1, OPCODE=0, AA=1, TC=0, RD=0
    flags[1] = 0x00;  // RA=0, Z=0, RCODE=0

    // QDCOUNT stays as-is.
    // ANCOUNT: 1 if answer, 0 if NXDOMAIN
    unsigned char* ancount = out + 6;
    if (!answer_ip.empty()) {
        ancount[0] = 0x00;
        ancount[1] = 0x01;
        // RCODE = 0 (no error)
        out[3] = (out[3] & 0xF0) | 0x00;
    } else {
        ancount[0] = 0x00;
        ancount[1] = 0x00;
        // RCODE = 3 (NXDOMAIN)
        out[3] = (out[3] & 0xF0) | 0x03;
    }

    // NSCOUNT and ARCOUNT stay 0.
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    int offset = 12;

    // Copy the question section verbatim from the query.
    // QNAME is length-prefixed labels, then QTYPE (2), QCLASS (2).
    int qname_end = 12;
    while (qname_end < qlen && query[qname_end] != 0) {
        qname_end += 1 + (unsigned char)query[qname_end];
    }
    qname_end += 1;  // null terminator
    int qtype_qclass = qname_end + 4;  // +2 QTYPE +2 QCLASS
    if (qtype_qclass > qlen) return -1;

    int qsection_len = qtype_qclass - 12;
    if (offset + qsection_len > out_size) return -1;
    memcpy(out + offset, query + 12, qsection_len);
    offset += qsection_len;

    if (answer_ip.empty()) {
        return offset;  // NXDOMAIN, no answer section
    }

    // Answer section: NAME pointer to question, TYPE=A, CLASS=IN, TTL,
    // RDLENGTH=4, RDATA=4 bytes. Use a local ans_offset so we don't confuse
    // it with the out-buffer offset.
    int ans_offset = offset;

    out[ans_offset] = 0xC0; out[ans_offset + 1] = 0x0C;  // pointer to QNAME (12)
    ans_offset += 2;

    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x01;  // TYPE A
    ans_offset += 2;
    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x01;  // CLASS IN
    ans_offset += 2;
    out[ans_offset] = (unsigned char)((ttl >> 24) & 0xFF);
    out[ans_offset + 1] = (unsigned char)((ttl >> 16) & 0xFF);
    out[ans_offset + 2] = (unsigned char)((ttl >> 8) & 0xFF);
    out[ans_offset + 3] = (unsigned char)(ttl & 0xFF);
    ans_offset += 4;
    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x04;  // RDLENGTH 4
    ans_offset += 2;

    // Parse answer IP into 4 bytes.
    unsigned char ipbytes[4] = {0, 0, 0, 0};
    int parsed = 0;
    const char* p = answer_ip.c_str();
    for (int i = 0; i < 4 && p != NULL; ++i) {
        ipbytes[i] = (unsigned char)atoi(p);
        p = strchr(p, '.');
        if (p) ++p;
        parsed++;
    }
    if (parsed != 4) return -1;

    out[ans_offset] = ipbytes[0];
    out[ans_offset + 1] = ipbytes[1];
    out[ans_offset + 2] = ipbytes[2];
    out[ans_offset + 3] = ipbytes[3];
    ans_offset += 4;

    return ans_offset;
}

// Build a DNS TXT record answer. TXT RDATA is one or more character-strings;
// each is a length byte followed by that many text bytes. We use a single
// character-string (truncated to 255 bytes for simplicity).
int build_txt_response(const unsigned char* query, int qlen,
                       unsigned char* out, int out_size,
                       const std::string& txt_data, int ttl) {
    if (qlen < 12 || out_size < 12) return -1;

    memcpy(out, query, 12);

    // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=0, RA=0, Z=0, RCODE=0
    unsigned char* flags = out + 2;
    flags[0] = 0x84;
    flags[1] = 0x00;

    // ANCOUNT: 1 if answer, 0 if NXDOMAIN
    unsigned char* ancount = out + 6;
    if (!txt_data.empty()) {
        ancount[0] = 0x00;
        ancount[1] = 0x01;
        out[3] = (out[3] & 0xF0) | 0x00;
    } else {
        ancount[0] = 0x00;
        ancount[1] = 0x00;
        out[3] = (out[3] & 0xF0) | 0x03;
    }

    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    int offset = 12;

    // Copy the question section verbatim from the query.
    int qname_end = 12;
    while (qname_end < qlen && query[qname_end] != 0) {
        qname_end += 1 + (unsigned char)query[qname_end];
    }
    qname_end += 1;  // null terminator
    int qtype_qclass = qname_end + 4;  // +2 QTYPE +2 QCLASS
    if (qtype_qclass > qlen) return -1;

    int qsection_len = qtype_qclass - 12;
    if (offset + qsection_len > out_size) return -1;
    memcpy(out + offset, query + 12, qsection_len);
    offset += qsection_len;

    if (txt_data.empty()) {
        return offset;  // NXDOMAIN, no answer section
    }

    // Answer section: NAME pointer to question, TYPE=TXT, CLASS=IN, TTL,
    // RDLENGTH, RDATA=length byte + text bytes.
    int ans_offset = offset;

    out[ans_offset] = 0xC0; out[ans_offset + 1] = 0x0C;  // pointer to QNAME (12)
    ans_offset += 2;

    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x10;  // TYPE TXT
    ans_offset += 2;
    out[ans_offset] = 0x00; out[ans_offset + 1] = 0x01;  // CLASS IN
    ans_offset += 2;
    out[ans_offset] = (unsigned char)((ttl >> 24) & 0xFF);
    out[ans_offset + 1] = (unsigned char)((ttl >> 16) & 0xFF);
    out[ans_offset + 2] = (unsigned char)((ttl >> 8) & 0xFF);
    out[ans_offset + 3] = (unsigned char)(ttl & 0xFF);
    ans_offset += 4;

    // RDLENGTH placeholder (filled in after we know the rdata length).
    int rdlength_pos = ans_offset;
    ans_offset += 2;

    // RDATA: one character-string = length byte + text.
    std::string data = txt_data;
    if (data.size() > 255) {
        data.resize(255);
    }
    out[ans_offset] = (unsigned char)data.size();
    ans_offset += 1;
    memcpy(out + ans_offset, data.c_str(), data.size());
    ans_offset += (int)data.size();

    // Fill in RDLENGTH.
    int rdlength = ans_offset - rdlength_pos - 2;
    out[rdlength_pos] = (unsigned char)((rdlength >> 8) & 0xFF);
    out[rdlength_pos + 1] = (unsigned char)(rdlength & 0xFF);

    return ans_offset;
}
std::string dns_parse_qname(const unsigned char* query, int qlen, int& offset) {
    std::string name;
    bool first = true;
    while (offset < qlen) {
        unsigned char len = query[offset++];
        if (len == 0) break;
        if (len & 0xC0) {  // pointer
            offset += 1;
            break;
        }
        if (!first) name += '.';
        first = false;
        if (offset + len > qlen) return "";
        name.append(reinterpret_cast<const char*>(query + offset), len);
        offset += len;
    }
    return name;
}
void dns_thread() {
    SOCKET dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_sock == INVALID_SOCKET) {
        std::cerr << "DNS socket creation failed: " << WSAGetLastError() << std::endl;
        return;
    }

    int reuse = 1;
    setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in dns_addr;
    ZeroMemory(&dns_addr, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_addr.s_addr = INADDR_ANY;  // answer on all interfaces incl. TAP

    if (bind(dns_sock, (sockaddr*)&dns_addr, sizeof(dns_addr)) == SOCKET_ERROR) {
        std::cerr << "DNS bind failed on port 53: " << WSAGetLastError()
                  << " (another DNS server may be running)." << std::endl;
        closesocket(dns_sock);
        return;
    }

    // A DNS message is at most 65535 bytes and TCP answers are never
    // truncated, so both buffers cover the whole range. The thread owns them.
    static char query_buf[65535];
    static char resp_buf[65535];

    while (relay_running) {
        sockaddr_in sender;
        int sender_len = sizeof(sender);
        int qlen = recvfrom(dns_sock, query_buf, sizeof(query_buf), 0,
                            (sockaddr*)&sender, &sender_len);
        if (qlen <= 0) {
            if (!relay_running) break;
            Sleep(1);
            continue;
        }

        const auto started = std::chrono::steady_clock::now();
        int rlen = build_answer((const unsigned char*)query_buf, qlen,
                                (unsigned char*)resp_buf, (int)sizeof(resp_buf));
        if (rlen <= 0) continue;

        // Anything this slow is worth a line in the log: it points straight at
        // the stage that lost the time (own records, forward, or timeout).
        const long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - started).count();
        if (elapsed >= 500) {
            int qoffset = 12;
            const std::string slow_name =
                dns_parse_qname((const unsigned char*)query_buf, qlen, qoffset);
            std::cerr << "DNS slow query: " << slow_name << " took " << elapsed
                      << " ms" << std::endl;
        }

        // A UDP client only receives what it announced it can take; anything
        // larger is answered with TC so it retries over TCP.
        const int limit = udp_payload_limit((const unsigned char*)query_buf, qlen);
        if (rlen > limit) {
            rlen = truncate_response((const unsigned char*)query_buf, qlen,
                                     (unsigned char*)resp_buf, (int)sizeof(resp_buf));
        }

        if (rlen > 0) {
            sendto(dns_sock, resp_buf, rlen, 0,
                   (sockaddr*)&sender, sender_len);
        }
    }

    closesocket(dns_sock);
}

void dns_tcp_thread() {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "DNS TCP socket creation failed: " << WSAGetLastError() << std::endl;
        return;
    }

    BOOL reuse = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in dns_addr;
    ZeroMemory(&dns_addr, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (sockaddr*)&dns_addr, sizeof(dns_addr)) == SOCKET_ERROR) {
        std::cerr << "DNS TCP bind failed on port 53: " << WSAGetLastError()
                  << " (another DNS server may be running)." << std::endl;
        closesocket(listen_sock);
        return;
    }
    if (listen(listen_sock, 16) == SOCKET_ERROR) {
        std::cerr << "DNS TCP listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listen_sock);
        return;
    }

    while (relay_running) {
        fd_set readers;
        FD_ZERO(&readers);
        FD_SET(listen_sock, &readers);
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 500 * 1000;
        if (select(0, &readers, NULL, NULL, &timeout) <= 0) continue;

        sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client = accept(listen_sock, (sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCKET) continue;

        if (g_tcp_clients.load() >= kMaxTcpClients) {
            closesocket(client);
            continue;
        }
        g_tcp_clients.fetch_add(1);
        std::thread(serve_tcp_client, client).detach();
    }

    closesocket(listen_sock);
}
