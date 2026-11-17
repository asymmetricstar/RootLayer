# Overview

RootLayer is a Windows & Linux focused, software-defined networking (SDN) project that provides a **virtual internet infrastructure**: a private, managed overlay network for physically separated machines. It combines a TAP-based overlay network with a private root/TLD name space, so connected nodes can communicate using virtual IP addresses and private hostnames as if they were part of the same local network.

<img width="444" height="368" alt="screenshot-2026-11-15_16-38-10" src="https://github.com/user-attachments/assets/941e32d3-c968-49ef-89ea-751fdd83f30f" />

## Core purpose

- **Virtual internet infrastructure:** a managed private network environment with its own addressing, naming, and trust model.
- **Private L2/L3 connectivity:** connect distributed machines into one virtual LAN without exposing them as a flat public network.
- **Private naming system:** custom TLDs and hostnames that exist only inside the RootLayer network.
- **Centralized coordination with shared transport:** signaling, registration, addressing, and name/TLD coordination are server-managed; client traffic flows over the virtual overlay/relay.
- **Non-disruptive networking:** the overlay runs alongside the normal internet connection without replacing the system default gateway or rerouting public traffic.
- **Full root-server management:** the root server can manage core infrastructure aspects end to end (addressing, naming/namespace, trust/certificates, client policies, and runtime configuration).

## Key characteristics

### Dual-stack networking (no public internet interruption)
- Public internet traffic continues to use the machine's normal network path and default gateway.
- Virtual-network traffic and private name resolution are handled by the RootLayer overlay.
- Public domain lookups remain on the system's usual DNS path, while RootLayer-managed private TLD queries are resolved by RootLayer services.

### Hybrid overlay architecture
- A central server coordinates signaling, identity/IP assignment, TLD state, name records, CA/certificate services, and gateway/relay behavior.
- Clients participate in a shared virtual LAN over a tunnel/relay transport rather than requiring point-to-point links between every pair of machines.
- The server provides the control plane and shared transport services for the segment.

## Core features

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
- **Dedicated admin console (`console.exe`)**: separate management tool for a running server over the local admin protocol (does not modify server databases directly). See [Console](console.md) for the full command reference.
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
- **Console (`console.exe`)**: standalone server administration tool for a running server. See [Console](console.md).
- **Service integration (`service/`)**: shared Windows service wrapper used by server and client executables.
- **Netdev / TAP-Wintun resources (`netdev/`, `resources/`)**: low-level virtual network device integration and bundled runtime/driver resources.

## IP addressing model (dynamic and static)

RootLayer manages virtual IP assignment through the root server:

- **Dynamic allocation (default):** a joining client receives a free virtual IP from the configured pool.
- **Stable identity-based behavior:** client identity (hardware/hwid) is used to track/persist assignments so clients can retain consistent addressing behavior across reconnects and restarts.
- **Static pinning (admin-controlled):** an administrator can pin a specific virtual IP to a specific client hardware/hwid identity. The server then hands out that exact IP to that client on future connections (including after server restarts).
- **Clearing a static pin:** removing the pinned assignment returns the client to dynamic allocation; on next connection it receives a free address from the pool.
- **Pool and subnet control:** the virtual subnet and client pool are configured in `server.ini` (`gateway_ip`, prefix/mask, optional `pool_start`/`pool_end`).
- **Operational safeguards:** static assignments must be valid for the pool/subnet and respect server-side constraints (for example, gateway/reserved/in-use/taken conditions as enforced by the server).

## Name resolution and private namespace

- RootLayer provides a **private namespace** (custom TLDs and flat `<hostname>.<tld>` records) managed by the root server.
- Managed TLDs/names are resolved inside the virtual network context; public internet DNS remains on the system/default resolver path.
- The server persists name/TLD data (for example in `domain.db`) and can serve private DNS on port `53` (UDP/TCP) for managed names when active.
- Clients can query/resolve private names through RootLayer mechanisms, including one-shot CLI resolution (`client.exe --resolve <name>`).

## Certificates and trust

- The server maintains a RootLayer CA (persisted in `cert.db`) used to sign TLS certificates for private names.
- Issued certificates are associated with private hostnames in the RootLayer namespace and can include appropriate SANs (such as `www.` variants when applicable).
- Clients obtain/install trust material needed to trust RootLayer-issued certificates within the private deployment.
- CA/certificate lifecycle is deployment-specific; rotating the CA (regenerating CA material) invalidates previously trusted chains tied to the old CA.
