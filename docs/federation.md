# RootLayer Federation (Server-to-Server Peering)

Status: **implemented (v1.0).** The decisions in this file
describes the code and how to use it.

Goal: clients of multiple RootLayer servers such as A, B, and C should work as a
single virtual network **without any changes to the clients**. A client still
connects to its own server and receives its own virtual IP. The servers
communicate with each other.

## 1. Mode distinction

Single key: `link` in `server.ini`.

| `link` value | Mode | Role |
| --- | --- | --- |
| empty / `false` / `0` / `off` | `SINGLE` | `PRIMARY` (other servers can link to it) |
| an IPv4 address (e.g. `192.168.1.100`) | `LINKED` | `REPLICA` |

If a replica loses the connection, it enters `DEGRADED` mode: reads continue
from the synchronized copy, global writes are rejected, and reconnection is
retried in the background. It does **not** automatically return to `SINGLE`
mode; an administrator must issue `link disconnect`.

All mode transitions are logged (`[link] SINGLE -> LINKED: ...`) and visible via
`link status`. There are no silent mode changes.

## 2. Roles and rules

- **PRIMARY** is the single owner of the global name space, location table, and
  CA. It also serves its own clients.
- **REPLICA** serves its own clients locally (IP allocation, relay, DNS) and
  uses the primary for global reads/writes.
- The primary server is not a data hub: traffic between B and C does not pass
  through A. A enters the data path only when its own client is involved.
- Local traffic (source and destination on the same server) never leaves over the
  link.
- Broadcast/multicast is not carried over the link (ARP/discovery is not
  propagated).
- Every envelope is single-hop (`TTL = 1`); a received envelope is never
  forwarded again.
- Only one PRIMARY at a time: if a second primary tries to connect, it announces
  its region and the prefix conflict is rejected. There is no automatic
  promotion.

## 3. Addressing

Each server limits its own client pool to **its own slice** with `pool_start` /
`pool_end`. The server announces the smallest prefix covering its pool
(`own_prefix`) to the federation; remote servers route based on this prefix.

Example: three servers in a single `/16` segment:

| Server | gateway_ip | virtual_ip_prefix | pool_start - pool_end | Announced prefix | Role |
| --- | --- | --- | --- | --- | --- |
| A | 10.10.1.1 | 16 | 10.10.1.10 - 10.10.1.200 | 10.10.1.0/24 | PRIMARY |
| B | 10.10.2.1 | 16 | 10.10.2.10 - 10.10.2.200 | 10.10.2.0/24 | REPLICA |
| C | 10.10.3.1 | 16 | 10.10.3.10 - 10.10.3.200 | 10.10.3.0/24 | REPLICA |

**Client side:** the client receives the mask and peer blocks from the server
(`MASK:` and `ROUTES:` fields). There are two options:

1. **Common `/16` segment (recommended):** use `virtual_ip_prefix=16` on all
   servers and give each server a `/24` pool slice. The client treats the entire
   `10.10.0.0/16` network as local, packets already enter the tunnel, and no
   extra route is needed.
2. **Separate `/24` pools:** the client mask becomes `/24` and the remote block
   is not on-link. The server sends the other servers' prefixes in the
   registration response and in every `STATE` response as
   `ROUTES:10.10.2.0/24,...`; the client installs a route for these blocks
   through the tunnel gateway. When the server list changes, the route is added
   or removed with the next `STATE`.

In both cases, packets enter the tunnel and the server forwards them to the
owner of the destination slice. `ROUTES` is only needed for blocks outside the
client's own mask.

## 4. Ports

| Purpose | Protocol | Key | Default |
| --- | --- | --- | --- |
| Peering control (HELLO/HEARTBEAT/SYNC) | TCP | `link_port` | 40002 |
| Federation data envelopes | UDP | `link_data_port` | 40003 |
| Control port used to reach the primary | TCP | `link_primary_port` | `link_port` |

`link_port` is the **local listen** port (each server listens on its own port).
`link_primary_port` differs only in cases such as NAT/port forwarding.

## 5. server.ini

Common keys:

```ini
link=                  ; empty/false = SINGLE, IP = connect to this primary
link_port=40002
;link_primary_port=40002
link_data_port=40003
link_id=               ; empty = srv-<gateway ip>
link_secret=           ; must be the same on both sides; empty = unauthenticated
link_cache_ttl_sec=60
```

A (primary):

```ini
gateway_ip=10.10.1.1
virtual_ip_prefix=16
pool_start=10.10.1.10
pool_end=10.10.1.200
link=
link_id=srv-a
link_secret=change-this
```

B (replica):

```ini
gateway_ip=10.10.2.1
virtual_ip_prefix=16
pool_start=10.10.2.10
pool_end=10.10.2.200
link=192.168.1.100
link_id=srv-b
link_secret=change-this
```

If `link_secret` is empty, the handshake is not authenticated and the server
warns at startup. The same secret should be used on all servers.

## 6. Control plane

A line-based protocol (`TOKEN:value`) over TCP. The replica connects, the
primary verifies it with `HELLO`, and sends the full state:

| Message | Direction | Purpose |
| --- | --- | --- |
| `HELLO ID:.. NONCE:.. PROOF:.. DATA:.. PREFIX:..` | R → P | identity + HMAC-SHA256 proof + data port + prefix |
| `HELLO_OK ID:.. EPOCH:.. DATA:.. PREFIX:..` | P → R | acceptance, primary identity and epoch |
| `SYNC_PEERS` / `SYNC_LOC` / `SYNC_NAMES` / `SYNC_TLD` | P → R | full table copy |
| `REGISTER IP:.. KEY:..` / `UNREGISTER IP:..` | R → P | client location |
| `LOC_ADD` / `LOC_DEL` | P → other R | location change |
| `LOOKUP_NAME NAME:..` → `NAME IP:.. OWNER:..` | R ↔ P | global name resolution |
| `NAME_ADD` / `NAME_DEL` → `NAME_OK` / `NAME_ERR CODE:..` | R ↔ P | global write confirmation |
| `NAME_SET` / `NAME_DEL` | P → R | announcement of an accepted write |
| `STATE ... ROUTES:<prefix,...>` | P → client | peer blocks (also sent in the registration response) |
| `PING` / `PONG` | R ↔ P | 5-second heartbeat |
| `LINK_CLOSE` | R → P | controlled shutdown |

Requests prefixed with `RID:<n>` are matched with the same `RID` in responses
(synchronous request).

Epoch: the primary generates a new epoch on each startup; the replica receives it
with `HELLO_OK` and shows it in `link status`. If the heartbeat is missed for
15 seconds, the replica becomes `DEGRADED`.

## 7. Data plane

If the destination IP is not in the local pool and falls into a known peer
prefix / location record, the packet is wrapped in a 32-byte envelope and sent
directly to that server's `link_data_port` UDP port:

```
[magic RLNK][ver][ttl=1][len][src ip][dst ip][src server id hash][dst id hash]
[original IPv4 packet]
```

Checks on the receiving side:

- magic/version/length, `dst_id` is this server's identity, `ttl == 1`;
- the sending server must be a known and connected peer;
- the source IP must be inside the sender's announced prefix (**anti-spoof**;
  the packet is dropped and logged on violation);
- the destination IP must be inside the local address space;
- delivery: to the client via `sessions_by_ip`, or to TAP if it is the gateway
  address.

Packets are not broadcast for unknown destinations; they are dropped (internet
destinations still go through the gateway/NAT path as before). Per-client
download limits are also applied to packets arriving from peers.

## 8. Name federation

- Read: local `domain.db` → if missing, `LOOKUP_NAME` to the primary (the
  response is cached for `link_cache_ttl_sec`; a missing name is cached briefly).
- Write: on a replica, `name add` / `name del` is forwarded to the primary; the
  primary writes with `arpa_set` and announces `NAME_SET` to all replicas. If a
  second owner requests the same name, the primary returns `taken`.
- On the initial connection, the primary sends the full name table
  (`SYNC_NAMES`, up to 500 records) and the TLD list (`SYNC_TLD`).

## 9. Certificate / trust

In LINKED mode, the single trust root of the federation is the primary's CA. The
replica forwards `CA_CERT`, `CSR:`, and `SRV_CERT` requests coming from a client
to the primary's signaling port and returns the response as-is; this allows a
certificate issued on A to be verified on B as well. If the primary is
unreachable (DEGRADED), the replica answers with its own CA so the network can
continue operating.

## 10. Console commands

Run only on the server machine (like other admin commands):

```text
console.exe link status
console.exe link connect 192.168.1.100 [--port 40002]
console.exe link disconnect
console.exe federation status
console.exe federation peers
```

`link connect` / `link disconnect` are applied immediately to the running server
and also update the `link` key in `server.ini` (persisted across restarts).
`config set link ...` has the same effect.

## 11. Testing

`test/python/federation_test.py` starts two servers (gateway disabled, a test
binary that does not require elevation) and verifies: link establishment,
peer/location table, bidirectional client traffic, local traffic not leaving over
the link, broadcast not passing, replica name write, name synchronization, name
conflict, and DEGRADED state with writes disabled when the primary is lost.

```bash
# test server that does not require elevation (without manifest)
g++ -Wall -Wextra -std=c++17 -I. -Iserver -o build/fedtest/server_test.exe \
    <server sources> build/obj/sqlite3.o -lws2_32 ... -lcrypto -lcrypt32
python test/python/federation_test.py
```

## 12. Troubleshooting

**Symptom:** `link status` shows `MODE:LINKED`, but clients of the two servers
cannot ping each other.

### 12.1 Disjoint subnets

If each server uses a different `/24` (`10.0.0.0/24` and `10.0.1.0/24`) and the
client mask is `/24`, the client does **not** see `10.0.1.23` as being on the
local network. The server announces the peer block as `ROUTES:10.0.1.0/24` and
the client installs a route for that block through the tunnel gateway; this is
how the packet enters the tunnel. The client updates this route in `STATE`
responses, so clients that connect after the link is established also learn it
within a few seconds.

The server logs the state when the link is established and shows it in
`link status`:

```text
[link] peer srv-2 owns 10.0.1.0/24 outside this client segment 10.0.0.0/24;
       announcing it as a client route through the tunnel gateway. ...

routing        client
```

`ROUTE:client` is normal and not a problem. Still, the simplest setup is to put
all servers in the same upper network; each server uses a slice of that segment.
Example (keeping the existing 10.0.0.x server):

A — 192.168.1.110 (primary):

```ini
gateway_ip=10.0.0.1
virtual_ip_prefix=16
pool_start=10.0.0.10
pool_end=10.0.0.200
link=
link_id=srv-1
```

B — 192.168.1.104 (replica):

```ini
gateway_ip=10.0.1.1
virtual_ip_prefix=16
pool_start=10.0.1.10
pool_end=10.0.1.200
link=192.168.1.110
link_id=srv-2
```

Client A becomes `10.0.0.19/16`, client B becomes `10.0.1.x/16`; since both
slices are on-link for the client, packets enter the tunnel. When client B
reconnects, it receives the new address and mask (`20.0.0.2` -> `10.0.1.x`).

> `pool_start` / `pool_end` are **required**: if not provided, a `/16` server
> announces the entire segment (10.0.0.0/16) as its own prefix, the prefixes of
> the two servers collide, and the link is rejected with
> `HELLO_ERR CODE:prefix_conflict`.

### 12.2 Windows Firewall

For peering, **TCP `link_port` (40002)** and **UDP `link_data_port` (40003)**
must be open to inbound traffic on both servers. If the server is running as
administrator, it creates the rules itself:

```text
[link] firewall: TCP 40002 and UDP 40003 open for peering
```

If they cannot be created (not running as administrator), add them manually:

```bat
netsh advfirewall firewall add rule name="RootLayer Federation TCP" dir=in action=allow protocol=TCP localport=40002
netsh advfirewall firewall add rule name="RootLayer Federation UDP" dir=in action=allow protocol=UDP localport=40003
```

### 12.3 Verification order

1. Primary: `console.exe link status` -> `MODE:SINGLE ROLE:PRIMARY PEERS:1`
2. Replica: `MODE:LINKED ...`, `federation peers` -> `srv-1 ... 10.0.0.0/24`
3. Clients reconnect on both sides (IP, mask, and `ROUTES` are obtained again).
4. On the client machine, verify with `route print` that the remote block
   (`10.0.1.0/24`) points to the tunnel gateway.
5. From client B: `ping 10.0.0.19`.

If you see `ROUTE:client`, peer blocks are being carried by client routes; if
you see `ROUTE:ok`, the blocks are inside the client's own mask. Both work. If a
common `/16` is used, the server host machine (gateway path) can also ping a
remote client: gateway traffic is handed to the link if the destination is in
another server's block. In separate `/24` pools this host route is not added to
the server; test from a client.

**Pinging from the server host machine is not a client test:** the server's own
host is a member of the segment (gateway address), but the client's TAP
interface and its traffic are only visible on the client machine. Run the ping
from the actual client VM.

### 12.4 Heartbeat / DEGRADED lines

```text
[link] heartbeat lost, primary did not answer for 15s
[link] LINKED -> DEGRADED ...
[link] DEGRADED -> LINKED: primary ... epoch ...
```

If the heartbeat is missed for 15 seconds, the replica becomes DEGRADED and
reconnects within a few seconds. If this repeats: check that TCP 40002 really
passes through, that the servers are not sleeping/suspended, and that text is
not left selected in the console window (Windows console pauses output while in
selection mode).

## 13. Limitations (intentionally not implemented)

- **No traffic encryption:** the handshake is authenticated with HMAC-SHA256,
  but control and data traffic are not encrypted. The link should run on a
  private network / over a VPN. (Design goal: TLS or an AES-GCM envelope.)
- **Single hop:** no multi-hop / chained routing.
- **No automatic promotion:** if the primary fails, an administrator assigns a
  new primary manually; the old epoch becomes invalid.
- **No live DB rollback selection:** `link disconnect` continues with the
  synchronized copy by default; a local database backup from before the link is
  not taken (Phase 4).
