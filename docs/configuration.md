# Configuration and Runtime Data

## Configuration, files, and runtime data

### Server files (executable directory)
- **`server.ini`**: main server configuration file (auto-created with defaults if missing). Loaded on startup; some settings can be changed live via admin/console and some require restart.
- **`cert.db`**: server CA and certificate persistence/store.
- **`domain.db`**: private name/TLD/domain records and name-service data (used by RootLayer naming/DNS services).
- **Client identity database/store** (SQLite-backed): persists client identity to virtual IP assignments and related identity state used for stable/dynamic-static allocation behavior.
- **Service log (when service-managed):** `<ServiceName>-service.log` in the executable directory (for example `RootLayerServer-service.log`, `RootLayerClient-service.log`).

### Client files (executable directory)
- **`client.ini`**: client configuration/state file (including stable client hardware/hwid identity handling).
- **Service log (when service-managed):** `RootLayerClient-service.log` (in the executable directory).

## Server configuration (`server.ini`) keys

> Defaults shown below reflect the generated default configuration. Some settings can be applied live through the admin/console; network-binding/topology settings typically require restart.

### Network ports and binding
- `listening_port` (default `40000`): signaling/control TCP port.
- `relay_port` (default `40001`): relay/data UDP port.
- `local_ip` (default empty): local interface IP to bind/listen on (`empty` = all interfaces / `0.0.0.0`). Also accepts legacy aliases in code paths (`server_ip`, `listen_ip`) when present.

### Gateway and NAT
- `tap_gateway` (default `1`): enable/disable acting as gateway on the virtual network interface.
- `nat` (default `0`): enable/disable NAT for the virtual network (requires appropriate privileges/support).

### Virtual network addressing and pool
- `gateway_ip` (default `10.0.0.1`): server's own virtual address inside the overlay subnet.
- `virtual_ip_prefix` (default `24`): CIDR prefix length for the virtual subnet (supported range typically `/8` to `/30`; takes precedence over `virtual_ip_mask` if both are set).
- `virtual_ip_mask` (optional, commented by default): dotted subnet mask alternative.
- `pool_start` (optional): first client address in the allocation pool (must be a usable host in the subnet).
- `pool_end` (optional): last client address in the allocation pool (must be a usable host in the subnet).

If pool bounds are not explicitly set, the server derives a usable client pool from the subnet/gateway (skipping network/broadcast/gateway addresses, with internal safety limits unless explicitly bounded).

### Message of the day
- `motd` (default empty): one-line message sent to clients on connect/registration and shown in the client panel/UI.

### Federation (server to server peer)
- `link` (default empty): empty/`false` runs this server on its own (`SINGLE`, it can be the primary others link to); an IPv4 address makes it a replica of that primary (`LINKED`).
- `link_port` (default `40002`): local TCP peering control port.
- `link_primary_port` (default `link_port`): TCP control port of the primary, when it differs (NAT / port forward).
- `link_data_port` (default `40003`): UDP port that carries the federation envelopes between servers.
- `link_id` (default `srv-<gateway ip>`): this server's federation identity.
- `link_secret` (default empty): shared secret for the HMAC-SHA256 handshake; set the same value on every server.
- `link_cache_ttl_sec` (default `60`): lifetime of remote name/location cache entries.

See [Federation](federation.md) for the address plan, protocol, and `link` / `federation` console commands.

### Per-client bandwidth defaults
- `client_upload_kbps` (default `0`): default upload cap in kbit/s (`0` = unlimited) for clients without per-client override.
- `client_download_kbps` (default `0`): default download cap in kbit/s (`0` = unlimited) for clients without per-client override.

Per-client overrides can be managed at runtime via the admin console and apply immediately (runtime-managed).

### Load/DoS guard settings
- `guard_max_connections` (default `128`): concurrent signaling connection limit (excess clients are rejected with a busy response/retry behavior).
- `guard_max_pps` (default `20000`): initial/target relay packet budget (packets/second), adaptively managed.
- `guard_min_pps` (default `5000`): lower bound for adaptive relay packet budget.
- `guard_max_budget_pps` (default `200000`): upper bound for adaptive relay packet budget.
- `guard_per_ip_pps` (default `4000`): per-sender fair-share ceiling (packets/second).
- `guard_connect_limit` (default `10`): new connections allowed per client IP per window.
- `guard_connect_window_sec` (default `10`): connection-rate window in seconds.
- `guard_source_table` (default `4096`): tracked sender table size (memory bound).
- `guard_source_idle_sec` (default `30`): idle timeout for tracked sender entries.
- `guard_log_interval_sec` (default `30`): minimum interval between guard log lines.

## Networking and protocol/port summary

| Purpose | Protocol | Default port | Notes |
| --- | --- | --- | --- |
| Signaling / control channel | TCP | `40000` (`listening_port`) | Client-server control, registration/session coordination, admin protocol (local-only). |
| Relay / data transport | UDP | `40001` (`relay_port`) | Carries virtual network frames/traffic through the overlay relay path. |
| Private DNS/name service (server) | UDP + TCP | `53` | Serves RootLayer-managed private names/TLD zone data when name service is active (backed by domain records). |
| Federation control (server to server) | TCP | `40002` (`link_port`) | Handshake, registrations, name/location sync, heartbeat between RootLayer servers. |
| Federation data (server to server) | UDP | `40003` (`link_data_port`) | One-hop envelopes carrying client IP packets between the servers only. |

> Actual ports/behavior depend on `server.ini` and runtime configuration. Administrative commands are accepted only from the server host (loopback/bound local interface).
