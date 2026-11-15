# RootLayer

RootLayer is a Windows-focused, software-defined networking (SDN) project that provides a **virtual internet infrastructure**: a private, managed overlay network for physically separated machines. It combines a TAP/based overlay network with a private root/TLD name space, so connected nodes can communicate using virtual IP addresses and private hostnames as if they were part of the same local network.

<img width="444" height="368" alt="screenshot-2026-11-15_16-38-10" src="https://github.com/user-attachments/assets/941e32d3-c968-49ef-89ea-751fdd83f30f" />

## Download Release 1.0.5
### 💾 [win-x64-Server](https://github.com/asymmetricstar/RootLayer/releases/download/v1.0.5/build-server-1.0.5-x64-win.zip)
### 💾 [win-x64-Client](https://github.com/asymmetricstar/RootLayer/releases/download/v1.0.5/build-client-1.0.5-x64-win.zip)
---

## Overview

RootLayer is built around a **root server** that acts as the central authority for the virtual network. It coordinates identity, virtual addressing, private naming (TLDs/hostnames), certificate/trust services, and runtime policy, while clients join the overlay and exchange traffic through the shared virtual transport.

### Core purpose

- **Virtual internet infrastructure:** a managed private network environment with its own addressing, naming, and trust model.
- **Private L2/L3 connectivity:** connect distributed machines into one virtual LAN without exposing them as a flat public network.
- **Private naming system:** custom TLDs and hostnames that exist only inside the RootLayer network.
- **Centralized coordination with shared transport:** signaling, registration, addressing, and name/TLD coordination are server-managed; client traffic flows over the virtual overlay/relay.
- **Non-disruptive networking:** the overlay runs alongside the normal internet connection without replacing the system default gateway or rerouting public traffic.
- **Full root-server management:** the root server can manage core infrastructure aspects end to end (addressing, naming/namespace, trust/certificates, client policies, and runtime configuration).

## Key Characteristics

### Dual-stack networking (no public internet interruption)
- Public internet traffic continues to use the machine's normal network path and default gateway.
- Virtual-network traffic and private name resolution are handled by the RootLayer overlay.
- Public domain lookups remain on the system's usual DNS path, while RootLayer-managed private TLD queries are resolved by RootLayer services.

### Hybrid overlay architecture
- A central server coordinates signaling, identity/IP assignment, TLD state, name records, CA/certificate services, and gateway/relay behavior.
- Clients participate in a shared virtual LAN over a tunnel/relay transport rather than requiring point-to-point links between every pair of machines.
- The server provides the control plane and shared transport services for the segment.

## Core Features

### Virtual network and connectivity
- **Automated virtual adapter management:** sets up and manages the required TAP/Wintun-based virtual adapter for client and server gateway roles, including creation/enabling flows needed to bring the interface up.
- **Automatic network provisioning:** configures virtual IP addressing, subnet/prefix, routes, and related interface settings for the overlay network.
- **MTU and tunnel-aware operation:** adjusts networking parameters to account for encapsulation/tunneling overhead.
- **Dynamic and static virtual IP addressing:**
  - By default, clients receive a **dynamic** virtual IP from the server's configured address pool when they join.
  - A specific client (identified by its hardware/hwid identity) can be assigned a **fixed/static** virtual IP, so it receives the same address on every reconnect and after server restarts.
  - If a static assignment is removed, the client returns to **dynamic allocation** and receives a free address from the pool on its next connection.
- **Gateway and NAT support:** server-side gateway configuration on the virtual interface and optional NAT of the virtual network (subject to configuration, privileges, and platform support).
- **Multi-interface isolation:** supports isolated virtual network scenarios without leaking routes to the public default path.

### Private root and name system
- **Private TLD/name space:** operates custom top-level domains (for example `.p2p`, `.any`, `.mesh`) that exist only within the RootLayer network.
- **Flat virtual hostname registry:** registers and resolves names in `<hostname>.<tld>` form to virtual IP addresses.
- **OS/application usability:** resolved private names can be used by applications on participating machines (such as browsers, ping, and other network tools) through the virtual network/name resolution integration.
- **Hybrid DNS behavior:** RootLayer handles queries for its managed TLDs/names and leaves public DNS resolution to the system/default resolvers.
- **Server-side DNS services for private zone:** when the name service is active, the server runs DNS services for managed names (UDP and TCP on port `53`) backed by its domain records/database.
- **Control-channel name resolution:** clients can perform private name resolution through the server/control mechanisms (including one-shot resolve workflows).

### Certificate authority and TLS for the private network
- **Built-in Certificate Authority (CA):** the server generates and persists a local CA (stored in `cert.db`) so the trust root survives restarts.
- **Server certificate issuance for private names:** TLS server certificates can be issued for registered/private hostnames (including appropriate SANs such as a `www.` variant where applicable) and signed by the RootLayer CA.
- **Automatic trust distribution/bootstrap:** clients can obtain/install trust material as part of joining/using the private network so RootLayer-issued certificates can be trusted by local applications/browsers on participating Windows machines.
- **Persistent certificate records:** issued certificates and CA material are stored/persisted by the server; CA rotation is performed by regenerating CA material (for example, replacing `cert.db` and restarting the server).

### Administration and control (root-server management)

RootLayer is designed so the root server can manage the virtual infrastructure end to end. Through the running server's administration interface (local admin protocol, used by `console.exe`), an operator can control:

- **IP addressing:** view/manage virtual address assignments, dynamic pool allocation behavior, and static IP pinning/clearing for specific client identities (hardware/hwid).
- **Naming and namespace:** manage virtual hostname records and private TLDs served by the network.
- **Certificates and trust:** issue, list, and remove/manage TLS certificate records for private names under the network CA.
- **Client policies:** apply per-client controls such as static IP pinning and bandwidth/rate limits (upload/download caps).
- **Server state and runtime configuration:** inspect server status and adjust supported live/runtime settings, with network-binding/topology-related settings applied on restart where required.

Administrative details:
- **Dedicated admin console (`console.exe`)**: separate management tool for a running server over the local admin protocol (does not modify server databases directly). See `RootLayer Console Document` for full command reference and examples.
- **Local-only administration:** admin operations are restricted to the server host (loopback/bound local interface); remote peers cannot issue admin commands.

### Client and server operation modes
- **Server interactive/foreground run:** starts the full server stack (configuration, databases/state, CA, networking, gateway/relay, signaling, DNS workers, guard/housekeeping).
- **Client graphical mode:** desktop UI/panel and tray integration for connection state, assigned address, DNS/name-related status, and network activity.
- **Client headless/automation mode:** run without GUI and emit machine-readable (JSON-oriented) events/output for scripting and integration.
- **Single-step name resolution mode (client):** resolve a private name in one command for diagnostics/automation.
- **Windows service mode (server and client):** install, run, query, and remove automatic-start Windows services using the same executables.

### Security and isolation
- **Zero Trust access model within the overlay:** participation, addressing, and private name resolution are limited to clients joined/authenticated within the specific virtual network context.
- **No route leak to the public internet:** the overlay interface does not replace the system default gateway; external traffic remains on the native link.
- **Privacy-conscious operator surfaces:** administrative/logging views are oriented around virtual identities/addresses (hardware ID and virtual IP) rather than exposing a client's real underlying/public address in normal operator output.
- **Isolated trust domain:** the RootLayer CA/certificates are intended for a specific private deployment; manage trust material per network/environment.

## Components

- **Server (`server.exe`)**: root server/control point for signaling, virtual gateway, relay, name/TLD/DNS services, IP allocation, CA/certificate services, and runtime coordination/policy.
- **Client (`client.exe`)**: joins the virtual network, provisions/manages the local virtual interface, maintains tunnel/signaling sessions, integrates private name resolution, and handles trust/bootstrap behavior.
- **Console (`console.exe`)**: standalone server administration tool for a running server (documented in [`console/readme.md`](console/readme.md)).
- **Service integration (`service/`)**: shared Windows service wrapper used by server and client executables.
- **Netdev / TAP-Wintun resources (`netdev/`, `resources/`)**: low-level virtual network device integration and bundled runtime/driver resources.

## Executables and Command-Line Reference

> **Administrator privileges required:** server/client/service operations interact with network drivers/adapters, routing, firewall/NAT, and system trust stores. Run with Administrator rights.

### Server (`server.exe`)

The server executable runs the RootLayer root server. It loads `server.ini` from the executable directory, initializes databases/state and CA material, brings up networking/gateway/relay/signaling/DNS components (as configured/available), and runs until stopped.

#### Server command-line options

| Command | Description |
| --- | --- |
| `server.exe` | Start the server normally (foreground process). |
| `server.exe --service start` | Install the Windows service for automatic start at boot and start it (service: `RootLayerServer`). |
| `server.exe --service stop` | Stop the Windows service and delete it. |
| `server.exe --service status` | Print the current Windows service state. |
| `server.exe --service run` | Internal entry point used by the Windows Service Control Manager (SCM); not intended for manual normal use. |

**Notes**
- `--service start`/`stop` typically require elevation/SCM access (the executable is intended to run with administrator privileges).
- When running as a service, the server runs under the service context (configured as `LocalSystem` by the wrapper) and uses the executable directory for its files/configuration.

### Client (`client.exe`)

The client executable joins the RootLayer virtual network, provisions the local virtual adapter, maintains the signaling/tunnel session, and integrates private networking/name resolution.

#### Client command-line options

| Command | Description |
| --- | --- |
| `client.exe` | Start the client in GUI mode (desktop UI/panel/tray integration), unless running as a service. |
| `client.exe --headless` | Start in headless mode (no GUI/tray/Qt panel), suitable for automation and machine-readable output. |
| `client.exe --resolve <name>` | Perform a one-shot private name resolution for `<name>` and exit with JSON result/output; implies headless behavior. Can be used while another client instance is running. |
| `client.exe --resolve=<name>` | Same as `--resolve <name>` using `--resolve=` form. |
| `client.exe --service start` | Install the Windows service for automatic start at boot and start it (service: `RootLayerClient`). |
| `client.exe --service stop` | Stop the Windows service and delete it. |
| `client.exe --service status` | Print the current Windows service state. |
| `client.exe --service run` | Internal entry point used by the Windows Service Control Manager (SCM); not intended for manual normal use. |

**Client behavior details**
- **Single-instance guard:** only one normal client instance is allowed per machine (to avoid duplicate adapter/session/identity conflicts). The `--resolve` mode is exempt so diagnostics can run while a client is active.
- **Headless/service behavior:** `--headless` disables GUI components; when started by SCM as a service, the client runs headless (no desktop UI).
- **Configuration:** loads/uses `client.ini` in the executable directory and ensures a stable client hardware/hwid identity is available.

## Configuration, Files, and Runtime Data

### Server files (executable directory)
- **`server.ini`**: main server configuration file (auto-created with defaults if missing). Loaded on startup; some settings can be changed live via admin/console and some require restart.
- **`cert.db`**: server CA and certificate persistence/store.
- **`domain.db`**: private name/TLD/domain records and name-service data (used by RootLayer naming/DNS services).
- **Client identity database/store** (SQLite-backed): persists client identity to virtual IP assignments and related identity state used for stable/dynamic-static allocation behavior.
- **Service log (when service-managed):** `<ServiceName>-service.log` in the executable directory (for example `RootLayerServer-service.log`, `RootLayerClient-service.log`).

### Client files (executable directory)
- **`client.ini`**: client configuration/state file (including stable client hardware/hwid identity handling).
- **Service log (when service-managed):** `RootLayerClient-service.log` (in the executable directory).

### Server configuration (`server.ini`) keys

> Defaults shown below reflect the generated default configuration. Some settings can be applied live through the admin/console; network-binding/topology settings typically require restart.

#### Network ports and binding
- `listening_port` (default `40000`): signaling/control TCP port.
- `relay_port` (default `40001`): relay/data UDP port.
- `local_ip` (default empty): local interface IP to bind/listen on (`empty` = all interfaces / `0.0.0.0`). Also accepts legacy aliases in code paths (`server_ip`, `listen_ip`) when present.

#### Gateway and NAT
- `tap_gateway` (default `1`): enable/disable acting as gateway on the virtual network interface.
- `nat` (default `0`): enable/disable NAT for the virtual network (requires appropriate privileges/support).

#### Virtual network addressing and pool
- `gateway_ip` (default `10.0.0.1`): server's own virtual address inside the overlay subnet.
- `virtual_ip_prefix` (default `24`): CIDR prefix length for the virtual subnet (supported range typically `/8` to `/30`; takes precedence over `virtual_ip_mask` if both are set).
- `virtual_ip_mask` (optional, commented by default): dotted subnet mask alternative.
- `pool_start` (optional): first client address in the allocation pool (must be a usable host in the subnet).
- `pool_end` (optional): last client address in the allocation pool (must be a usable host in the subnet).

If pool bounds are not explicitly set, the server derives a usable client pool from the subnet/gateway (skipping network/broadcast/gateway addresses, with internal safety limits unless explicitly bounded).

#### Message of the day
- `motd` (default empty): one-line message sent to clients on connect/registration and shown in the client panel/UI.

#### Per-client bandwidth defaults
- `client_upload_kbps` (default `0`): default upload cap in kbit/s (`0` = unlimited) for clients without per-client override.
- `client_download_kbps` (default `0`): default download cap in kbit/s (`0` = unlimited) for clients without per-client override.

Per-client overrides can be managed at runtime via the admin console and apply immediately (runtime-managed).

#### Load/DoS guard settings
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

## Networking and Protocol/Port Summary

| Purpose | Protocol | Default port | Notes |
| --- | --- | --- | --- |
| Signaling / control channel | TCP | `40000` (`listening_port`) | Client-server control, registration/session coordination, admin protocol (local-only). |
| Relay / data transport | UDP | `40001` (`relay_port`) | Carries virtual network frames/traffic through the overlay relay path. |
| Private DNS/name service (server) | UDP + TCP | `53` | Serves RootLayer-managed private names/TLD zone data when name service is active (backed by domain records). |

> Actual ports/behavior depend on `server.ini` and runtime configuration. Administrative commands are accepted only from the server host (loopback/bound local interface).

## IP Addressing Model (Dynamic and Static)

RootLayer manages virtual IP assignment through the root server:

- **Dynamic allocation (default):** a joining client receives a free virtual IP from the configured pool.
- **Stable identity-based behavior:** client identity (hardware/hwid) is used to track/persist assignments so clients can retain consistent addressing behavior across reconnects and restarts.
- **Static pinning (admin-controlled):** an administrator can pin a specific virtual IP to a specific client hardware/hwid identity. The server then hands out that exact IP to that client on future connections (including after server restarts).
- **Clearing a static pin:** removing the pinned assignment returns the client to dynamic allocation; on next connection it receives a free address from the pool.
- **Pool and subnet control:** the virtual subnet and client pool are configured in `server.ini` (`gateway_ip`, prefix/mask, optional `pool_start`/`pool_end`).
- **Operational safeguards:** static assignments must be valid for the pool/subnet and respect server-side constraints (for example, gateway/reserved/in-use/taken conditions as enforced by the server).

## Name Resolution and Private Namespace

- RootLayer provides a **private namespace** (custom TLDs and flat `<hostname>.<tld>` records) managed by the root server.
- Managed TLDs/names are resolved inside the virtual network context; public internet DNS remains on the system/default resolver path.
- The server persists name/TLD data (for example in `domain.db`) and can serve private DNS on port `53` (UDP/TCP) for managed names when active.
- Clients can query/resolve private names through RootLayer mechanisms, including one-shot CLI resolution (`client.exe --resolve <name>`).

## Certificates and Trust

- The server maintains a RootLayer CA (persisted in `cert.db`) used to sign TLS certificates for private names.
- Issued certificates are associated with private hostnames in the RootLayer namespace and can include appropriate SANs (such as `www.` variants when applicable).
- Clients obtain/install trust material needed to trust RootLayer-issued certificates within the private deployment.
- CA/certificate lifecycle is deployment-specific; rotating the CA (regenerating CA material) invalidates previously trusted chains tied to the old CA.

## Administration (Console)

`console.exe` is the dedicated administration tool for a **running** RootLayer server. It communicates with the server's local admin protocol and is used to manage:

- server information/status
- virtual name records (`name ...`)
- private TLDs (`tld ...`)
- certificates (`cert ...`)
- static/dynamic IP assignment controls (`ip ...`)
- per-client bandwidth limits (`limit ...`)
- server configuration settings (`config ...`)

## Running and Operations (Practical Notes)

- **Start server first:** run `server.exe` on the machine acting as the root server/gateway.
- **Join with clients:** run `client.exe` on participating machines to provision the virtual adapter and connect to the server.
- **Administer locally:** run `console.exe` on the server host to manage the network (names, TLDs, IPs, certs, limits, config).
- **Service deployment:** use `--service start|stop|status` on server/client executables to manage automatic-start Windows services.
- **Headless automation:** use `client.exe --headless` for non-GUI operation and `client.exe --resolve <name>` for one-shot private name resolution.
- **Privileges and environment:** networking, adapter, firewall/NAT, and trust-store operations require Administrator privileges and appropriate Windows driver/runtime support.

---

# RootLayer Console Document (`console.exe`)

`console.exe` is the server management helper for **RootLayer** (a separate project, not built by the root Makefile). It manages virtual names, TLDs, certificates, static IP addresses, bandwidth caps, and `server.ini` settings of a **running** server.

It is a standalone program that links only against Winsock—it does not link the server codebase. All operations are executed through the running server's admin protocol on the signaling port, keeping the server's write-behind buffer, live TLD set, in-memory CA, and configuration authoritative. Because of this, `console.exe` never opens `domain.db`, `client.db`, or `server.ini` directly behind the server's back.

The executable is written next to the server binary: `../console.exe`.

## Usage & Options

```text
console.exe [options] <command> [arguments]
```

Options must come **before** the command; everything after the command belongs to the command itself (for example, `--ttl 120`). On the server machine, no options are needed at all—`console.exe` automatically picks the address and port from the `server.ini` located next to it.

| Option | Meaning |
| --- | --- |
| `--server IP` | Server address. Default: `local_ip` from `server.ini` next to `console.exe`, else `127.0.0.1`. |
| `--port N` | Signaling port. Default: `listening_port` from the same `server.ini`, else `40000`. |
| `--timeout MS` | Connect/read timeout in milliseconds (`100..60000`, default `5000`). |
| `--help`, `-h` | Print the command list built into this binary. |
| `--version`, `-v` | Print the console version. |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | The server accepted the command. |
| `1` | Usage error (bad arguments, cannot write files). |
| `2` | The server refused the command (`ADMIN_ERR:<code>`). |
| `3` | The server could not be reached or returned no response. |

## Notes

- **Local-only administration:** admin commands are accepted only on the server machine itself (loopback or its bound local interface). Remote peers receive `ADMIN_ERR:local_only`.
- **Text fields:** values containing spaces (for example `--info "files for the lab"` or `config set motd Hello world`) are carried base64-encoded in the request and decoded by the server. Stored record fields cannot contain spaces or `|` / `;` delimiters; the server replaces them with `_`.
- **Certificate files:** keep `.key` files generated by `cert issue` private.

## Command Categories

| Category | Commands | Purpose |
| --- | --- | --- |
| Server information | `info` | Inspect server status and core service details. |
| Name records | `name add`, `name list`, `name del` | Manage virtual hostname records (`<hostname>.<tld>` → virtual IP). |
| TLD management | `tld add`, `tld list`, `tld del` | Manage private TLD suffixes served by the root server. |
| Certificates | `cert issue`, `cert list`, `cert del` | Issue and manage TLS server certificates signed by the server CA. |
| IP addressing | `ip list`, `ip set`, `ip clear` | Manage dynamic/static virtual IP assignments for client hardware IDs. |
| Bandwidth limits | `limit set`, `limit list`, `limit clear` | Manage per-client upload/download bandwidth caps. |
| Server configuration | `config list`, `config set` | View and change `server.ini` settings (live or on restart). |

---

## 1. Server Information

### `info`
**What it does:** shows a one-screen summary of the running server, including address, domain count, active TLDs, gateway IP, certificate count, and CA fingerprint.


**Example**
```text
console.exe info
```
**Example explanation:** connects to the running server and prints its current status summary so you can quickly verify that the server is reachable and see core state (domains, TLDs, gateway, certificates, and CA identity).

**Example output**
```text
FIELD            VALUE
server           127.0.0.1:40000
domains          3
tlds             p2p,mesh
gateway          10.0.0.1
certificates     2
ca fingerprint   2D8D6072AFBCB954
```

---

## 2. Name Records

RootLayer uses a flat virtual name registry in `<hostname>.<tld>` form (not a hierarchical public DNS). Registered names resolve through the tunnel to their target virtual IPs.

### `name add`
**What it does:** creates or updates a virtual hostname record that maps `<hostname>.<tld>` to a virtual IP address. Optional flags set TTL, owner identity, and informational text.

**Syntax**
```text
console.exe name add <hostname>.<tld> <ip> [--ttl N] [--identity ID] [--info TEXT]
```
- `--ttl N`: record lifetime in seconds (`1..86400`, default `60`).
- `--identity ID`: owner recorded with the name (default `admin.server`).
- `--info TEXT`: free text shown in `name list` (spaces are stored as `_`).

**Example**
```text
console.exe name add web.p2p 10.0.0.20 --ttl 120 --info "web server"
```
**Example explanation:** registers `web.p2p` to point to virtual IP `10.0.0.20` for 120 seconds, records it as an admin-managed entry, and stores `web server` as informational text (shown with spaces replaced by underscores).

**Example output**
```text
ok: web.p2p -> 10.0.0.20 (ttl 120, owner admin.server, info web_server)
```

### `name list`
**What it does:** lists registered virtual name records, including name, IP, TTL, owner, and info. An optional limit caps the number of rows returned.

**Syntax**
```text
console.exe name list [--limit N]
```

**Example**
```text
console.exe name list --limit 50
```
**Example explanation:** requests up to 50 name records from the server and prints them in a table so you can review current hostname-to-IP mappings.

**Example output**
```text
NAME       IP         TTL  OWNER         INFO
web.p2p    10.0.0.20  120  admin.server  web_server
root.p2p   10.0.0.21   60  admin.server  files

2 name record(s)
```

### `name del`
**What it does:** deletes a virtual hostname record from the server.

**Syntax**
```text
console.exe name del <hostname>.<tld>
```

**Example**
```text
console.exe name del web.p2p
```
**Example explanation:** removes the `web.p2p` record; after deletion, that virtual name is no longer resolved by the server.

**Example output**
```text
ok: deleted web.p2p
```

---

## 3. TLD Management

A TLD is a private suffix the root server is authoritative for (for example `p2p`, `mesh`). Clients route only these managed virtual namespaces to the server.

### `tld add`
**What it does:** adds a new private TLD suffix to the server's authoritative TLD set.

**Syntax**
```text
console.exe tld add <tld>
```

**Example**
```text
console.exe tld add mesh
```
**Example explanation:** registers `mesh` as a managed virtual TLD, allowing the server to answer names under `.mesh` (for example `node1.mesh`) once corresponding name records exist.

**Example output**
```text
ok: added tld mesh
```

### `tld list`
**What it does:** lists the TLD suffixes currently served by the running server.

**Syntax**
```text
console.exe tld list
```

**Example**
```text
console.exe tld list
```
**Example explanation:** prints the active private TLDs so you can confirm which virtual namespaces are currently enabled.

**Example output**
```text
TLD
p2p
mesh

2 tld(s)
```

### `tld del`
**What it does:** removes a private TLD suffix from the server, unless it is the last remaining suffix.

**Syntax**
```text
console.exe tld del <tld>
```

**Example**
```text
console.exe tld del mesh
```
**Example explanation:** removes `mesh` from the managed TLD set. The server refuses to remove the final remaining TLD because it must always serve at least one.

**Example output**
```text
ok: removed tld mesh
```

---

## 4. Certificates

The server runs an internal Certificate Authority (CA). Certificate commands let you issue and manage TLS server certificates for private names.

### `cert issue`
**What it does:** issues a TLS server certificate for a name, signs it with the server CA, stores/persists it on the server side as applicable, and writes certificate files to an output directory.

**Syntax**
```text
console.exe cert issue <name> [--out DIR] [--days N]
           [--name "Full Name"] [--mail user@mail.tld]
           [--city City] [--country Country] [--cc TR]
```
- `--out DIR`: output directory (default: current directory).
- `--days N`: validity in days (`1..3650`, default `397`).
- `--name`, `--mail`, `--city`, `--country`, `--cc`: optional subject fields embedded in the certificate (not stored by the server).

**Example**
```text
console.exe cert issue root.p2p --out C:\files\certs --days 365 --name "Root Admin" --mail admin@root.p2p --cc TR
```
**Example explanation:** creates and signs a certificate for `root.p2p` (including a `www.` SAN when applicable), valid for 365 days, embeds the provided subject details, and writes `<name>.crt`, `<name>.key`, and `rootlayer-ca.crt` to `C:\files\certs`.

**Example output**
```text
ok: issued certificate for root.p2p
  wrote C:\files\certs\root.p2p.crt
  wrote C:\files\certs\root.p2p.key
  wrote C:\files\certs\rootlayer-ca.crt
```

### `cert list`
**What it does:** lists certificates known/issued by the server.

**Syntax**
```text
console.exe cert list
```

**Example**
```text
console.exe cert list
```
**Example explanation:** displays the server's certificate records so you can see which private names currently have issued certificates.

**Example output**
```text
NAME       NOT AFTER
root.p2p   2027-05-10
api.mesh   2027-05-10

2 certificate(s)
```

### `cert del`
**What it does:** removes a certificate record from the server.

**Syntax**
```text
console.exe cert del <name>
```

**Example**
```text
console.exe cert del root.p2p
```
**Example explanation:** deletes the server-side record for `root.p2p`. Any already-distributed certificate copy remains valid until it expires because the CA does not maintain a CRL.

**Example output**
```text
ok: removed certificate root.p2p
```

---

## 5. IP Addressing

IP commands manage virtual address assignment for clients identified by hardware ID (HW ID). By default clients can receive dynamic addresses from the pool; administrators can pin static addresses to specific hardware IDs.

### `ip list`
**What it does:** lists pinned (static) virtual IP assignments, showing hardware ID, virtual IP, online/offline state, and last-seen information.

**Syntax**
```text
console.exe ip list
```

**Example**
```text
console.exe ip list
```
**Example explanation:** prints all hardware IDs with pinned virtual addresses and their current state (`online` with `LAST SEEN now`, or offline with a relative/unknown last-seen value).

**Example output**
```text
HW ID              VIRTUAL IP  STATE    LAST SEEN
02-cc-3e-5c-96-14  10.0.0.50   online   now
02-cc-3e-5c-96-98  10.0.0.9    offline  5m ago

2 pinned address(es)
```

### `ip set`
**What it does:** pins a static virtual IP to a client hardware ID so the server hands out that exact address to that client on future connections (including after restarts).

**Syntax**
```text
console.exe ip set <hardware-id> <static-virtual-ip>
```

**Example**
```text
console.exe ip set 02-cc-3e-5c-96-14 10.0.0.50
```
**Example explanation:** assigns static virtual IP `10.0.0.50` to hardware ID `02-cc-3e-5c-96-14`. If that client is currently online, its session is dropped so it reconnects with the newly pinned address. The address must be valid for the client pool and not already taken/in use as restricted by the server.

**Example output**
```text
ok: 10.0.0.50 pinned to 02-cc-3e-5c-96-14
info: the client was online; its session was dropped so it reconnects with the new address
```

### `ip clear`
**What it does:** removes a static IP pin for a hardware ID, returning that client to dynamic allocation from the pool on its next connection.

**Syntax**
```text
console.exe ip clear <hardware-id>
```

**Example**
```text
console.exe ip clear 02-cc-3e-5c-96-14
```
**Example explanation:** clears the pinned address for hardware ID `02-cc-3e-5c-96-14`. The client will receive a free dynamic virtual IP from the pool next time it connects (active sessions are dropped to apply the change).

**Example output**
```text
ok: cleared pinned address for 02-cc-3e-5c-96-14
```

---

## 6. Bandwidth Limits

Bandwidth limit commands control per-client relay throughput in both directions. Rates are specified in **kbit/s** (`0` means unlimited for that direction).

### `limit set`
**What it does:** sets upload and download bandwidth caps for a client virtual IP. The override applies to live sessions immediately and is kept in runtime memory for future connections of that address/hardware ID.

**Syntax**
```text
console.exe limit set <virtual-ip> <up-kbps> <down-kbps>
```

**Example**
```text
console.exe limit set 10.0.0.50 1024 4096
```
**Example explanation:** limits client `10.0.0.50` to 1024 kbit/s upload and 4096 kbit/s download for traffic forwarded by the relay.

**Example output**
```text
ok: limit set for 10.0.0.50 (up 1024 kbit/s, down 4096 kbit/s)
```

### `limit list`
**What it does:** lists active per-client bandwidth overrides. Clients without an override use the default `client_upload_kbps` and `client_download_kbps` values from `server.ini`.

**Syntax**
```text
console.exe limit list
```

**Example**
```text
console.exe limit list
```
**Example explanation:** shows all currently configured per-client bandwidth overrides so you can audit which virtual IPs have custom caps.

**Example output**
```text
VIRTUAL IP  UP (kbit/s)  DOWN (kbit/s)
10.0.0.50   1024         4096
10.0.0.51   512          2048

2 override(s)
```

### `limit clear`
**What it does:** removes the bandwidth override for a client virtual IP, returning it to the server's default bandwidth settings.

**Syntax**
```text
console.exe limit clear <virtual-ip>
```

**Example**
```text
console.exe limit clear 10.0.0.50
```
**Example explanation:** deletes the custom limit for `10.0.0.50`; future and current behavior falls back to the configured default upload/download limits.

**Example output**
```text
ok: cleared limit for 10.0.0.50
```

---

## 7. Server Configuration

Configuration commands manage settings stored in `server.ini`. `config set` writes changes to disk and applies them immediately when the setting supports live updates.

### `config list`
**What it does:** lists available/configured server settings, their current values, and whether each setting applies live or requires a restart.

**Syntax**
```text
console.exe config list
```

**Example**
```text
console.exe config list
```
**Example explanation:** prints the server's configuration keys and values (for example `motd`, bandwidth defaults, guard settings, ports, gateway/pool settings) along with `APPLIES` status (`live` or `restart`).

**Example output**
```text
KEY                       VALUE                 APPLIES
motd                      Welcome to RootLayer  live
client_upload_kbps        0                     live
client_download_kbps      1000                  live
listening_port            40000                 restart
relay_port                40001                 restart
gateway_ip                10.0.0.1              restart
virtual_ip_prefix         16                    restart

23 setting(s) from C:\RootLayer\Server\server.ini
```

### `config set`
**What it does:** updates a `server.ini` setting on the running server. Live settings take effect immediately where supported; restart-required settings are saved and applied on the next server start.

**Syntax**
```text
console.exe config set <key> <value>
```

**Example**
```text
console.exe config set motd "Welcome to RootLayer"
```
**Example explanation:** sets the server MOTD to `Welcome to RootLayer`, writes it to `server.ini`, and applies it immediately because `motd` is a live-applied setting.

**Example output**
```text
ok: motd = Welcome to RootLayer (applies live)
```

**Apply behavior (common keys)**
| Applies | Keys | Behavior |
| --- | --- | --- |
| `live` | `motd`, `client_upload_kbps`, `client_download_kbps`, all `guard_*` keys | Takes effect immediately for new registrations/sessions and traffic shield behavior as applicable. |
| `restart` | `listening_port`, `relay_port`, `local_ip`, `gateway_ip`, `virtual_ip_prefix`, `virtual_ip_mask`, `pool_start`, `pool_end`, `tap_gateway`, `nat` | Saved to `server.ini`; applied on next server start. |

---

## Security & Privacy

- **Local-only administration:** the server processes admin commands only from the host machine itself (loopback or bound local interface).
- **Zero real-IP logging:** server/operator views identify clients by hardware ID and virtual IP, not by a client's real public/underlying IP.
- **Private keys:** keep `.key` files generated by `cert issue` private.






## License

This project is licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE) for details.
