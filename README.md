# RootLayer

RootLayer is a Windows & Linux focused, software-defined networking (SDN) project that provides a **virtual internet infrastructure**: a private, managed overlay network for physically separated machines. It combines a TAP-based overlay network with a private root/TLD name space, so connected nodes can communicate using virtual IP addresses and private hostnames as if they were part of the same local network.

<img width="444" height="368" alt="screenshot-2026-11-15_16-38-10" src="https://github.com/user-attachments/assets/941e32d3-c968-49ef-89ea-751fdd83f30f" />

## Download Release 1.0.6

- 💾 [win-x64-Server](https://github.com/asymmetricstar/RootLayer/releases/download/v1.0.6/build-server-1.0.6-x64-win.zip)
- 💾 [win-x64-Client](https://github.com/asymmetricstar/RootLayer/releases/download/v1.0.6/build-client-1.0.6-x64-win.zip)


## Documentation

The documentation is organized in [`docs/`](docs/):

- [**Overview**](docs/overview.md) — core purpose, key characteristics, features, components, addressing model, private naming, certificates, and security.
- [**Server and Client Reference**](docs/server-client.md) — executables, command-line options, service modes, and operational notes.
- [**Configuration**](docs/configuration.md) — runtime files, `server.ini` keys, and networking/port summary.
- [**Console (`console.exe`)**](docs/console.md) — administration commands for names, TLDs, certificates, IP assignments, bandwidth limits, and server configuration.
- [**Federation**](docs/federation.md) — server-to-server peering, address planning, protocol details, console commands, verification, and troubleshooting.

## Quick start

1. **Start the server:** run `server.exe` with Administrator privileges on the machine acting as the root server/gateway.
2. **Join with clients:** run `client.exe` with Administrator privileges on participating machines to provision the virtual adapter and connect.
3. **Administer locally:** run `console.exe` on the server host to manage names, TLDs, IPs, certificates, limits, and configuration.

For detailed usage, configuration, and federation setup, see the documentation pages linked above.

## License

This project is licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE) for details.
