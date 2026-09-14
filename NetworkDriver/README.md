# NetworkDriver — Windows WFP filtering lab in C

A standalone portfolio project demonstrating a **WDM control driver**, **Windows Filtering Platform (WFP) callouts**, and a **C command-line controller**. The driver observes IPv4 TCP/UDP connection authorizations and can block one configured endpoint rule.

**Educational code, not a production firewall. Test kernel loading only in a disposable VM you own or are authorized to administer.** No installer, service start, certificate trust, firewall change, or test-signing change happens automatically.

## What it demonstrates

- WDM `DriverEntry`, dispatch routines, buffered IOCTLs, completion and unload.
- `IoCreateDeviceSecure` with a protected administrator/SYSTEM-only DACL.
- Runtime WFP callout registration versus management callouts and filters.
- Transactional installation into a dynamic WFP session; cleanup on partial failure.
- IPv4 endpoint extraction at `ALE_AUTH_CONNECT_V4` and `ALE_AUTH_RECV_ACCEPT_V4`.
- Safe arbitration: block only with `FWPS_RIGHT_ACTION_WRITE`; otherwise preserve the existing decision. Nonmatches return `CONTINUE`, never a blanket `PERMIT`.
- Nonpaged bounded event storage and short spin-lock critical sections for concurrent classify/IOCTL callbacks.
- Versioned pointer-free user/kernel structures, input validation, access-specific IOCTLs, and fully initialized output buffers.
- Pure-C policy tests and an independent TCP/UDP echo fixture.

## Layout

| Path | Purpose |
| --- | --- |
| `NetworkDriver.slnx` | Driver, controller and tests in one solution |
| `NetworkDriver.c` | Secure control device, WFP lifecycle, classification, event ring |
| `NetworkDriver.inf` | Demand-start primitive driver package metadata, BFE dependency |
| `Shared/NetworkDriverShared.h` | Names, IOCTL codes and versioned fixed-size ABI |
| `Shared/NetworkRule.h` | Rule validation and matching shared by driver/tests |
| `NetworkCtl/NetworkCtl.c` | Controller with strict argument parsing and event display |
| `Tests/NetworkDriverTests.c` | Driver-free checks, optional IOCTL checks and echo fixture |
| `docs/TESTING.md` | Build, signing, VM installation, test matrix and rollback |

All implementation files are `.c`/`.h`, explicitly compiled as C11. Project XML and Markdown are configuration/documentation, not C++ components. The internship project was a **read-only style reference**, not a runtime dependency.

## Build

Use Visual Studio 2026 with the MSVC v145 C/C++ tools, a compatible Windows SDK/WDK and WDK integration. This workspace has WDK `10.0.28000.0`. The driver uses `WindowsKernelModeDriver10.0`; user-mode projects use `v145`. Install the matching ARM64 tools if cross-building.

Open `NetworkDriver.slnx` (reload if it was already open). Build **Debug | x64** or **Release | x64**. ARM64 configurations are also included; their binaries must run on an ARM64 Windows VM.

From a VS Developer Command Prompt, in this directory, use the 64-bit MSBuild host:

```bat
"%VSINSTALLDIR%MSBuild\Current\Bin\amd64\MSBuild.exe" NetworkDriver.slnx /m /p:Configuration=Debug /p:Platform=x64
bin\x64\Debug\NetworkDriverTests.exe
```

Outputs go to `bin/<platform>/<configuration>/`; intermediate files go to `obj/`. WDK packaging may place the INF/CAT/SYS package in a child `NetworkDriver` directory. Driver signing is off by default (`SignMode=Off`); explicitly sign the binary for the isolated lab as documented. Compile success is not proof of kernel runtime safety. Follow the separate VM test guide before loading anything.

Validated locally: Debug/Release x64 builds, 45 rule/ABI checks per configuration, 13 CLI validation cases, and TCP/UDP loopback echo fixtures. ARM64 and live kernel behavior have not been validated; see the test guide for the exact boundaries.

## Controller

Use an elevated terminal in the prepared VM, with the driver running:

```bat
NetworkCtl monitor
NetworkCtl block out tcp 127.0.0.1 8080
NetworkCtl stats
NetworkCtl events
NetworkCtl watch
NetworkCtl monitor
```

Rule syntax:

```text
NetworkCtl block <in|out|any> <tcp|udp|any> <remote-ipv4|any> <service-port|any>
```

- One volatile rule; a new rule replaces the previous rule atomically.
- All specified fields are **ANDed**.
- Remote IP always means the other endpoint. Service port means **remote port outbound**, **local port inbound**.
- `any` is a wildcard. At least an IP or port is required; accidental block-all is rejected.
- Only dotted-decimal IPv4 is accepted; no DNS resolution, CIDR or IPv6. Numeric `0.0.0.0` and port `0` are rejected by the CLI because zero is reserved for wildcard in the ABI.
- `monitor` clears the rule but retains counters/events. Reloading the driver resets everything.
- `events` destructively reads up to 32 records; `watch` repeatedly drains the same global queue. Readers compete; there is no per-client subscription.
- Ctrl+C only stops the watcher. **It does not remove a block rule.** Closing the controller also leaves the rule active until `monitor` or unload.
- CLI exit codes: 0 success, 1 device/runtime error, 2 usage/validation error.

## Architecture and lifetime

1. Initialize the lock, zeroed counters and monitor-only rule.
2. Create a named control device with `D:P(A;;GA;;;SY)(A;;GA;;;BA)` and `FILE_DEVICE_SECURE_OPEN`.
3. Open a dynamic BFE session, begin a transaction and add a private sublayer.
4. Register two runtime callouts and corresponding management callouts. Add a TCP filter and UDP filter at each layer, then commit.
5. Expose the DOS symbolic link only after initialization succeeds.
6. For each authorization callback, copy WFP-supplied host-order endpoint metadata, take the state lock, evaluate the rule, update counters and append an event. Full rings overwrite the oldest event and increment `Overwritten`.
7. User mode drains buffered snapshots. No classify-path allocation, raw user pointers, packet payload capture, file writes, or per-event debug printing.
8. On unload/failure, remove the symbolic link, close the dynamic session to remove policy, unregister runtime callouts to drain callbacks, then delete the device. No flow contexts, pending IRPs or worker threads are retained.

BFE must already be running. If it is unavailable, startup fails rather than silently running without filters. If BFE restarts while the driver is loaded, restart the driver to recreate its dynamic session; this sample does not implement BFE state subscriptions or automatic recovery.

## Permissions and privacy

- Loading/unloading a kernel service requires administrator privileges and an acceptable driver signature.
- The device ACL permits only SYSTEM and elevated administrators to read metadata or change rules. The controller runs `asInvoker`: it never silently elevates itself.
- Write IOCTLs require a handle opened with `GENERIC_WRITE`; monitoring IOCTLs require `GENERIC_READ`. Kernel validation remains mandatory even when the caller is an administrator.
- Metadata includes UTC timestamp, sequence number, PID when WFP supplies it, direction, protocol, local/remote IPv4 and ports, and **this callout's** action. It can disclose browsing/service activity even without payload capture. Keep logs on the authorized lab machine and redact addresses/PIDs before publishing screenshots.
- No remote control interface, registry-persisted rules, packet injection or security-feature bypass is implemented.
- Rules affect system-wide IPv4 authorizations, not just traffic created by the controller. Use narrow lab rules; never block the VM management/RDP/SSH/DNS path.

## Exact scope and limitations

This is **connection-authorization filtering**, not a packet sniffer. ALE commonly classifies a new TCP connection or UDP endpoint authorization, not every packet. Reauthorization can generate additional events, so `Observed` is not a unique connection count. `Blocked` counts block decisions, not packets, bytes or confirmed application failures. `CONTINUE` means this driver did not block; another WFP provider may still reject the traffic. Callbacks without action-write rights are reported as `NO-RIGHT`.

Updating the in-memory rule does **not** request WFP reauthorization or terminate existing connections. Test with fresh sockets after every update. Process metadata can be absent (PID 0). IPv6, ICMP, Ethernet parsing, payload inspection, DNS names, process-path rules, allowlists, multi-rule ordering and persistent policy are intentionally out of scope. This is not a tamper-resistant security product.

The ring holds only 128 events and intentionally drops old data under load. Rule state and counters share one spin lock for clarity; no throughput or latency claims have been measured.

## Portfolio presentation

After building and completing the VM tests, a defensible CV bullet is:

> Developed a C-based Windows WFP callout driver and administrator-only CLI for IPv4 TCP/UDP connection monitoring and configurable endpoint blocking; implemented versioned buffered IOCTLs, bounded event logging, synchronized policy updates and transactional filter cleanup.

Include your own VM screenshots, build/test results, a short demo showing monitor → block → recover, and an explanation of ALE versus packet layers. Do not claim production readiness, packet capture, IPv6 coverage, performance numbers or kernel verification you have not measured. Review and understand the generated implementation before presenting it as your work.
