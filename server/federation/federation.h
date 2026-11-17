// server/federation/federation.h
//
// RootLayer federation: server-to-server peering, so the clients of several
// servers behave as one virtual network without any client change.
//
//   link = <primary ip>   -> LINKED mode (replica, control to that primary)
//   link = false / empty  -> SINGLE mode (independent server; also acts as the
//                            primary that replicas may link to)
//
// Control plane: TCP link_port (default 40002), authenticated handshake,
// heartbeat, location and name synchronisation.
// Data plane: UDP link_data_port (default 40003), one-hop envelopes between the
// servers only. The primary never carries traffic it is not part of.
#ifndef ROOTLAYER_SERVER_FEDERATION_H
#define ROOTLAYER_SERVER_FEDERATION_H

#include "core/win_headers.h"

namespace fed {

// SINGLE      independent server (role PRIMARY), own database is authoritative
// LINKING     link is being established, writes are held back
// LINKED      control link up; global reads come from the primary
// DEGRADED    control link lost; reads from cache, writes disabled
// UNLINKING   link is being closed
enum class Mode { Single, Linking, Linked, Degraded, Unlinking };

struct PeerInfo {
    std::string id;
    std::string ip;
    int data_port = 0;
    std::string prefix;      // "10.10.2.0/24" - the addresses this server owns
    bool primary = false;
    long long last_seen = 0;
};

// ---- server.ini settings (loaded by core/config.cpp) ---------------------
extern std::string link_target;   // empty = SINGLE mode
extern int link_port;             // local TCP peering control port
extern int link_primary_port;     // TCP port of the primary (default: link_port)
extern int link_data_port;        // UDP federation data port
extern std::string link_id;       // this server's federation identity
extern std::string link_secret;   // shared secret for the handshake
extern int cache_ttl_sec;         // remote name/location cache lifetime

void load_settings(const std::string& ini_path);

// ---- mode / role ---------------------------------------------------------
bool is_primary();
Mode mode();
std::string mode_name();

// The address block this server owns: the smallest prefix covering the client
// pool (a /24 pool inside a /16 segment announces only that /24).
std::string own_prefix();

// ---- lifecycle -----------------------------------------------------------
bool start();
void stop();

// ---- diagnostics ---------------------------------------------------------
std::string status_tokens();              // "MODE:.. ROLE:.. PEERS:.."
std::vector<PeerInfo> peers();
std::string peers_csv();                  // id|ip|data|prefix|role|state|age

// ---- data plane ----------------------------------------------------------
// Encapsulates an IPv4 packet for the server that owns its destination.
// Returns false when the destination belongs to no peer (local or unknown), so
// the caller keeps its normal local behaviour.
bool forward_packet(const char* packet, int len);

// ---- client registration (location table) --------------------------------
void note_client_online(const std::string& virtual_ip, const std::string& client_key);
void note_client_offline(const std::string& virtual_ip);

// ---- federated names -----------------------------------------------------
// Remote lookup used when the local database has no such record. Returns false
// when the name is unknown or no primary is reachable.
bool lookup_name(const std::string& name, std::string& ip, std::string* owner = NULL);

// Global writes: on a replica they are forwarded to the primary and only count
// once the primary accepts them. `error` carries the primary's error code.
bool name_add(const std::string& name, const std::string& ip, int ttl,
              const std::string& owner, std::string& error,
              std::string* canonical = NULL, const std::string& info = "");
bool name_del(const std::string& name, std::string& error);

// Primary side: pushes a name change to every linked replica. Called after a
// successful local write on the primary (console or forwarded request).
void announce_name(const std::string& name, const std::string& ip, int ttl,
                   const std::string& owner, const std::string& info = "");
void announce_name_delete(const std::string& name);

// ---- single trust root ---------------------------------------------------
// A replica has no CA of its own in linked mode: certificate requests are
// forwarded to the primary, so every client of the federation trusts the same
// root. Returns false when the primary is unreachable.
bool certificate_proxy(const std::string& request, std::string& response);

// ---- runtime link control (console) --------------------------------------
bool link_connect(const std::string& ip, int port, std::string& error);
bool link_disconnect(std::string& error);

}  // namespace fed

#endif  // ROOTLAYER_SERVER_FEDERATION_H
