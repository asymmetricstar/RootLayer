# Staging and infrastructure testing phase approaching source-code deployment.
### Source codes not include yet.
<img width="444" height="368" alt="screenshot-2026-11-11_12-30-24" src="https://github.com/user-attachments/assets/3f42c747-d217-4f9c-bc6b-d4214da97f38" />


#### The initial test version is now live. If you encounter any bugs during your evaluation or have feature suggestions, ```please submit an issue or share your feedback to help us improve. ```


# 🌐 RootLayer & SDN Engine
### TAP-Based P2P Virtual LAN, Root DNS (Root/TLD) & Private Network Management System

This system is a **Software-Defined Networking (SDN)** based virtual network and infrastructure ecosystem that brings physically separated machines together as if they were on the same local network (L2/L3 Virtual LAN), hosting its own independent and isolated **Private Root Name Space (Custom Root/TLD DNS)**.

> ### Core Differentiator (Dual-Stack Network & No Internet Interruption)
> Unlike conventional VPN technologies, this system **never interrupts, slows down, or manipulates the client computer's primary internet traffic or default gateway.**
> 
> Two independent network layers run **simultaneously** on the machine:
> * **Public Internet Layer:** Your normal internet traffic, browsers, and public domain resolutions (`google.com`, `github.com`, etc.) continue to flow uninterrupted and at full speed via your existing local network.
> * **Private Virtual LAN Layer:** Network traffic and private top-level domain resolutions specific to this network (`root.p2p`, `node.new`, etc.) are securely handled and routed through the secondary virtual network created in the background.

---

## 🛠 Core Architecture & Features

### 1. Software-Defined Virtual Network (SDN & Overlay Network)
* **Decentralized L2/L3 Communication:** Instead of point-to-point peering, clients forward incoming ethernet frames to a shared virtual transport layer; all connected machines behave as if they are plugged into a single virtual switch.
* **Automated TAP Interface Management:** Automatically installs the required TAP-Windows network adapter, recreates it if missing, or dynamically enables it if disabled.
* **Smart Routing & MTU Optimization:** Automatically provisions IP addresses, subnet masks, and local routes for the virtual network to prevent routing loops, while continuously optimizing MTU to balance tunneling overhead.
* **Persistent IP Allocation (Static DHCP):** Utilizing unique client identifiers (UUIDs), machines maintain the same virtual IP addresses even if the central server or VPS restarts.

### 2. Private Root & Top-Level Domain Name Server (Root & TLD Name Server)
* **Isolated Name Space (Private TLDs):** Operates as a completely private DNS Root and TLD server closed to the public internet. Only clients connected to this virtual network can resolve custom extensions like `.p2p`, `.new`, or `.name`.
* **Native Application Integration:** Resolved private domain names (e.g., root.p2p, storage.abc) are recognized at the operating system level, making them directly usable in web browsers (HTTP), ping commands, or remote desktop utilities.
* **Hybrid DNS Query Management (Fallback):** The server solely handles network-specific TLD queries and seamlessly passes public internet domain queries (google.com, etc.) to the operating system's default DNS servers.

### 3. VPS & Infrastructure Management Options
* **Desktop Control Panel (GUI):** A graphical dashboard displaying connection status, assigned IP addresses, DNS status, and real-time network throughput for end-users and administrators.
* **Headless (Automation) Mode:** Server and client components can be executed without a GUI (`--headless`). In this mode, system status, connected peers, and network metrics are exported natively in JSON format.
* **Microservices Integration:** Supports CLI flags (e.g., single-step name resolution via `--resolve`) for flawless integration with remote automation systems and VPS management panels.

---

## 🔒 Security & Isolation Policy

* **Zero Trust Network Access (ZTNA):** Network access and private name resolution are strictly confined to authenticated and authorized clients joined to this specific virtual network.
* **External Network Protection (No Route Leak):** The virtual network interface does not alter the client's default gateway; external internet traffic remains fully routed via the native physical link.
* **Multi-Tenancy Support:** Multiple isolated virtual network interfaces (different virtual LANs) can run concurrently on the same physical server or client machine without cross-traffic or IP block interference.

---


## 🚀 Quick Start Guide
*(Note: Because the system interacts with network drivers, appends system routes, and spawns virtual network adapters, both server and client components must be executed with **Administrator privileges**.)*


### 1. Server (Central VPS / Name Server) Setup
To initialize the central signaling and TLD routing, run the server application with administrator rights:
```bash
# Launch with Graphical User Interface
RootLayerServer.exe

# Launch in background (Headless) mode for VPS automation
RootLayerServer.exe --headless
```

### 2. Client (Node) Setup
To join the network and automatically provision the virtual TAP adapter:
```bash
# Launch with standard graphical interface
RootLayerClient.exe

# Query/resolve a specific private name in a single step:
RootLayerClient.exe --resolve node1.p2p
```

---

## 🔐 Certificate Authority & Server Certificates

RootLayer ships an in-process Certificate Authority (CA) that issues TLS server certificates for registered names, so that services running inside the virtual network (e.g. `https://<domain>.<tld>/`) can serve HTTPS with a chain the tunnel clients already trust.

* **CA persisted in cert.db:** The CA key and certificate are generated on first start and stored in `cert.db` (SQLite) next to the server executable. Issued certificates and the CA itself survive server restarts, so HTTPS endpoints keep validating without CA rotation.
* **Server certificate issuance:** A name (e.g. `root.name`) can be issued a TLS server certificate (CN + SAN incl. `www.` prefix) valid for up to 3650 days, signed by the RootLayer CA. No prior domain registration is required.
* **Automatic trust installation:** Clients fetch the CA over the signaling channel and install it into the Windows root trust store, so browsers and local applications trust RootLayer-issued certificates without manual steps.
* **No CRL:** Forgotten certificates stay valid until they expire; rotating the CA (a fresh `cert.db`) is what invalidates everything.

---

### Console (`console.exe`) Usage
*(Note: Because the system interacts with network drivers, appends system routes, and spawns virtual network adapters, both server and client components must be executed with **Administrator privileges**.)*


`console.exe` is the server administration tool. It drives the running server over its admin protocol (loopback only) and never opens the databases directly.

```bash
console.exe [--server IP] [--port N] [--timeout MS] <command> [arguments]
```

Common commands:

```bash
# Name records <domain>.<tld> <server_ip> e.g : (root.p2p -> 10.0.0.20)
console.exe name add <domain>.<tld> 10.0.0.1 --ttl 60 --info root
console.exe name list
console.exe name del <domain>.<tld>

# TLD management <tld> e.g : (new) -> (www.root.new) 
console.exe tld add <tld>
console.exe tld list

# Issue a TLS server certificate (CN + SAN, incl. www. prefix)
console.exe cert issue <domain>.<tld> --out C:\file-server\certs
console.exe cert issue <domain>.<tld> --name "Your Name" --mail YourName@<domain>.<tld> --city Istanbul --country Turkey --cc TR --days 397

# Issue a certificate for a www-prefixed name like a [https://www.root.p2p] (no domain registration required)
console.exe cert issue <sub>.<domain>.<tld> --out C:\file-server\certs --name "Your Name" --mail YourName@<domain>.<tld>

# List / remove issued certificates
console.exe cert list
console.exe cert del <domain>.<tld>

# Server info
console.exe info
```

Issued certificates are written as `root.name.crt`, `root.name.key` and `rootlayer-ca.crt` into the `--out` directory (default: current directory). The certificate is also persisted in `cert.db` on the server.

---

## 📄 LICENSE (Proprietary Source-Available License)

Copyright (c) 2026. All rights reserved.

1. **PROHIBITION OF MODIFICATION:** You may view and download the source code for personal, educational, or review purposes. However, you are strictly prohibited from modifying, altering, adapting, or creating derivative works based upon this software or its source code.
2. **PROHIBITION OF COMMERCIAL USE AND SALE:** This software and its source code cannot be sold, rented, leased, licensed, or used for any commercial purposes, directly or indirectly, without the express written permission of the copyright holder.
3. **DISTRIBUTION:** You may not redistribute this software or its source code on other platforms or package it as a commercial product.
