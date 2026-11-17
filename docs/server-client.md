# Server and Client Reference

> **Administrator privileges required:** server/client/service operations interact with network drivers/adapters, routing, firewall/NAT, and system trust stores. Run with Administrator rights.

## Server (`server.exe`)

The server executable runs the RootLayer root server. It loads `server.ini` from the executable directory, initializes databases/state and CA material, brings up networking/gateway/relay/signaling/DNS components (as configured/available), and runs until stopped.

### Server command-line options

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

## Client (`client.exe`)

The client executable joins the RootLayer virtual network, provisions the local virtual adapter, maintains the signaling/tunnel session, and integrates private networking/name resolution.

### Client command-line options

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

### Client behavior details
- **Single-instance guard:** only one normal client instance is allowed per machine (to avoid duplicate adapter/session/identity conflicts). The `--resolve` mode is exempt so diagnostics can run while a client is active.
- **Headless/service behavior:** `--headless` disables GUI components; when started by SCM as a service, the client runs headless (no desktop UI).
- **Configuration:** loads/uses `client.ini` in the executable directory and ensures a stable client hardware/hwid identity is available.

## Running and operations (practical notes)

- **Start server first:** run `server.exe` on the machine acting as the root server/gateway.
- **Join with clients:** run `client.exe` on participating machines to provision the virtual adapter and connect to the server.
- **Administer locally:** run `console.exe` on the server host to manage the network (names, TLDs, IPs, certs, limits, config). See [Console](console.md).
- **Service deployment:** use `--service start|stop|status` on server/client executables to manage automatic-start Windows services.
- **Headless automation:** use `client.exe --headless` for non-GUI operation and `client.exe --resolve <name>` for one-shot private name resolution.
- **Privileges and environment:** networking, adapter, firewall/NAT, and trust-store operations require Administrator privileges and appropriate Windows driver/runtime support.
