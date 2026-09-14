# Build and safe VM test guide

## 1. Validation boundaries

The default C tests and argument parsing checks do not require a driver or elevation. `--device`, filtering, unload, BFE lifecycle, Driver Verifier and ACL checks require a separately prepared Windows VM. Never interpret a build or pure-rule test pass as a pass for those kernel scenarios.

Use Windows 10 2004 or later / Windows 11, matching the binary architecture. Build on a compatible VS/WDK installation; the initial configuration uses VS 2026 v145 and WDK 10.0.28000.0. ARM64 requires matching compiler/WDK components and an ARM64 VM. A Debug controller may require the debug CRT on the VM; prefer Release user-mode binaries for a VM without Visual Studio, with the matching Visual C++ runtime installed.

## 2. Build and driver-free checks

In a VS Developer Command Prompt at the solution directory, use 64-bit MSBuild:

```bat
"%VSINSTALLDIR%MSBuild\Current\Bin\amd64\MSBuild.exe" NetworkDriver.slnx /m /p:Configuration=Debug /p:Platform=x64
bin\x64\Debug\NetworkDriverTests.exe
"%VSINSTALLDIR%MSBuild\Current\Bin\amd64\MSBuild.exe" NetworkDriver.slnx /m /p:Configuration=Release /p:Platform=x64
bin\x64\Release\NetworkDriverTests.exe
```

Checks cover ABI sizes/access bits, disabled mode, IP/port/protocol/direction matching, inbound service-port semantics, unsupported protocols, invalid versions/sizes/reserved fields, port boundaries and block-all rejection. Checks run in Release too (not `assert`). All projects select C11, including the anonymous structures used by WDK headers. If a 32-bit MSBuild invocation reports that `x86\InfVerif.dll` cannot be loaded, use the 64-bit command above; do not disable INF verification.

### Local validation recorded

With VS 2026 / WDK 10.0.28000.0 and the 64-bit MSBuild host:

- Full Debug x64 and Release x64 solution builds passed, including WDK INF/catalog checks, with no reported warnings or errors.
- The standalone tests reported **45 checks, 0 failures** in each configuration.
- Release controller passed **13 help/invalid-input exit-code checks**, without opening the driver.
- Release C TCP and UDP echo listener/probe pairs both passed over `127.0.0.1:49171`, without the driver loaded.
- No driver installation/loading, certificate trust, boot/security changes, ACL enforcement, blocking, unload, BFE recovery, or Driver Verifier testing was performed. ARM64 builds/runtime were not tested.

These are development-machine results only. The VM matrix below still needs to be executed and recorded before making kernel-runtime claims.

CLI validation examples, without the driver:

```bat
bin\x64\Release\NetworkCtl.exe --help
bin\x64\Release\NetworkCtl.exe block out tcp any any
bin\x64\Release\NetworkCtl.exe block out tcp 127.0.0.1 65536
bin\x64\Release\NetworkCtl.exe block out tcp 127.0.0.1 -1
bin\x64\Release\NetworkCtl.exe block out tcp ::1 8080
```

Help should exit 0; invalid rules should exit 2 before opening a device. The pure C executable is not a Test Explorer framework adapter; run it directly if Test Explorer reports no tests.

## 3. Prepare an isolated VM

1. Obtain permission to instrument the VM/network. Take a clean snapshot and retain hypervisor-console access.
2. Use a private/host-only network with no production traffic. Do not connect sensitive workloads or rely solely on RDP for recovery.
3. Use matching x64 or ARM64 binaries. Keep an elevated VM terminal open for recovery.
4. Configure a kernel debugger if available. Use a disposable test VM specifically configured for test-signed drivers according to Windows/WDK requirements. Do **not** change the development host's boot, Secure Boot, BitLocker or memory-integrity settings.
5. Ensure the VM is in test-signing mode before loading a test certificate. In an already suitable lab VM, an elevated `bcdedit /set testsigning on` followed by a reboot enables this. If boot/security policy rejects the change, stop and prepare a compatible lab VM rather than bypassing organizational controls. A signature is still required; test mode does not mean unsigned code is safe or permitted.
6. Keep Windows Firewall enabled. If a two-VM inbound test requires a firewall exception, permit only the fixture executable, private test interface, peer address and test port; remove that exception afterward.

## 4. Test signature and trust

The project sets `SignMode=Off`: ordinary builds produce unsigned driver artifacts and do not automatically create or trust a certificate. Signing is a deliberate step before VM deployment. Use only a certificate you control for this lab. Never distribute the private key, PFX/password, or a certificate trusted on production machines.

If no lab certificate is configured, these commands in PowerShell on the build machine create a **test-only code-signing certificate** and export only its public part:

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=NetworkDriver Lab Only' -CertStoreLocation Cert:\CurrentUser\My
Export-Certificate -Cert $cert -FilePath .\NetworkDriverLab.cer
$cert.Thumbprint
```

Use the displayed thumbprint in a WDK Developer Command Prompt to embed-sign the `.sys` used for the SCM lab route below:

```bat
signtool sign /v /fd SHA256 /s My /sha1 YOUR_LAB_CERT_THUMBPRINT bin\x64\Release\NetworkDriver.sys
signtool verify /v /pa bin\x64\Release\NetworkDriver.sys
```

Authenticode verification on the build host does not prove that the VM's kernel code-integrity policy will load it. The self-signed chain may report untrusted until the public certificate is trusted in the isolated VM. Inspect file signature details, VM Code Integrity logs and actual load results.

For catalog-based packaging, finish signing the SYS **before** regenerating the catalog with the WDK and signing that CAT. Modifying/signing the SYS after catalog generation invalidates that catalog's hash. The direct SCM lab route below uses the embedded SYS signature and does not install the INF/CAT package.

Copy the signed `.sys`, matching `NetworkCtl.exe`, `NetworkDriverTests.exe` and public `.cer` to `C:\DriverLab` in the VM. In an elevated **VM-only** terminal, trust that public lab certificate:

```bat
certutil -addstore Root C:\DriverLab\NetworkDriverLab.cer
certutil -addstore TrustedPublisher C:\DriverLab\NetworkDriverLab.cer
```

Do not add these certificates to the development host's machine trust stores. Production driver signing/distribution has additional Microsoft requirements and is not demonstrated here.

## 5. Explicit demand-start lab installation

This is a non-PnP WDM control driver; the following SCM procedure is the simple development route, not driver-store package deployment. First verify no unrelated service already uses `NetworkDriver` (`sc.exe query NetworkDriver`). Do not overwrite an existing service or loaded binary.

In the elevated VM terminal:

```bat
sc.exe query BFE
sc.exe create NetworkDriver type= kernel start= demand error= normal binPath= C:\DriverLab\NetworkDriver.sys depend= BFE
sc.exe start NetworkDriver
sc.exe query NetworkDriver
C:\DriverLab\NetworkCtl.exe stats
```

Spaces after the `=` signs are required. Use `sc.exe`, not PowerShell's `sc` alias. Expect monitor-only mode with no block rule. Startup failure must be diagnosed before proceeding: check architecture, signature, certificate trust, BFE, WDK runtime dependencies, Code Integrity/System event logs and the driver debugger message with the NTSTATUS.

`NetworkDriver.inf` separately describes a primitive, demand-start package with a driver-store-relative service binary and BFE dependency. A packaging exercise can use Windows primitive-driver installation APIs (`DiInstallDriver`/`DiUninstallDriver`) with a signed matching catalog; an installer is not included. Do not mix package installation and the direct SCM lab route for the same service. Never copy a SYS over a currently loaded binary.

## 6. Repeatable loopback TCP demo

Use two VM terminals. The fixture waits five seconds, so start the listener immediately before each probe; every invocation uses fresh sockets and the listener exits after one echo.

In an elevated controller terminal:

```bat
C:\DriverLab\NetworkCtl.exe monitor
```

Terminal A:

```bat
C:\DriverLab\NetworkDriverTests.exe listen tcp 127.0.0.1 8080
```

Terminal B, within five seconds:

```bat
C:\DriverLab\NetworkDriverTests.exe probe tcp 127.0.0.1 8080
```

Expect `Echo succeeded.` and exit code 0 on both. Then set a narrow rule:

```bat
C:\DriverLab\NetworkCtl.exe block out tcp 127.0.0.1 8080
```

Repeat the listener/probe with fresh processes. Expect probe failure (exit 1) and a corresponding **out/tcp/BLOCK** event, not just a timeout. View evidence:

```bat
C:\DriverLab\NetworkCtl.exe events
C:\DriverLab\NetworkCtl.exe stats
C:\DriverLab\NetworkCtl.exe monitor
```

Repeat the listener/probe again and expect recovery. Run a separate `NetworkCtl watch` while testing if background traffic could overwrite the event ring. A timeout alone never proves this driver caused a block: confirm the endpoint/action in events and compare the `Blocked` counter.

To test UDP, replace both fixture `tcp` arguments and the rule protocol with `udp`. A UDP send may succeed locally even when delivery is blocked; the echo reply timeout plus WFP event is the evidence. This is still ALE authorization, not per-datagram capture.

## 7. VM validation matrix

Keep a test-results log containing OS build, architecture, configuration, driver signature, command, exit code, relevant event and pass/fail. The following are procedures, not pre-claimed results.

| Case | Procedure and expected result |
| --- | --- |
| Startup | `stats` reports disabled rule; fresh TCP/UDP echo works absent another firewall block |
| Outbound IP+port | Narrow rule blocks only matching fresh outbound authorizations; confirm BLOCK metadata |
| Wildcards | Test IP-only (`127.0.0.1 any`) and port-only (`any 8080`) independently |
| Negative match | With a TCP/8080 rule, TCP/8081 and UDP/8080 continue and echo succeeds if otherwise allowed |
| Inbound | Prefer two authorized private-network VMs: listener on target VM private IPv4, peer probes it; `block in tcp <peer-ip> 8080` blocks inbound local port 8080, not peer ephemeral port |
| Bidirectional | `block any tcp <peer-ip> 8080`; test both direction semantics independently |
| Monitor recovery | `monitor`, then new sockets; no new matching BLOCK decisions |
| IPv6/ICMP | Out of scope; do not interpret their absence from events as filtering coverage |
| Normal-user ACL | Unelevated `NetworkCtl stats` and `monitor` both fail access denied (exit 1) |
| Device contract | Elevated `NetworkDriverTests --device`: all checks pass; no other controller may modify the rule during this test |
| Existing sockets | Rule changes do not intentionally disconnect established connections; do not use keep-alive reuse to test a new rule |
| Ring overflow | Stop readers; generate more than 128 fresh authorizations; Queued stays <=128, Overwritten increases, fresh sequence numbers remain ordered when drained |
| Multiple readers | Two watchers divide, rather than duplicate, queued events; each returned batch is internally valid |
| Concurrency | Change narrow rules while generating fresh connections and reading events; no corruption, deadlock or crash |
| Unload/reload | Close all controller/device handles; stop/start repeatedly; policy disappears on stop and returns monitor-only on start |
| BFE lifecycle | Only in a snapshot VM: if BFE/session state is lost, restart the driver; automatic recovery is intentionally absent |
| Cleanup failure paths | Use debugger/fault injection in a disposable VM to exercise failed device/link/WFP initialization; no residual callouts/filters/device should remain |

`--device` checks read-only-handle write denial, unsupported IOCTLs, undersized outputs, invalid input lengths, version mismatch, rejected broad rule and rejected out-of-range port. It verifies that rejected writes leave the rule unchanged and does not intentionally submit a valid rule or drain events. For malformed request fuzzing beyond these cases, keep a debugger and snapshot available.

For deeper checking, enable Driver Verifier **for NetworkDriver.sys only** in the disposable VM (`verifier /standard /driver NetworkDriver.sys`), reboot as requested, run the matrix, then disable it with `verifier /reset` and reboot. Verifier can intentionally bugcheck; prepare Safe Mode/snapshot recovery first. Do not select all host drivers. No Verifier result is implied by the source or build.

## 8. Rollback

In the VM, close watchers and any process holding the device, then:

```bat
C:\DriverLab\NetworkCtl.exe monitor
sc.exe stop NetworkDriver
sc.exe delete NetworkDriver
```

On unload, the dynamic WFP session removes this driver's objects. Verify connectivity with fresh sockets. A successful `sc.exe stop` should leave `NetworkCtl stats` unable to open the device. If stop reports an open-handle/in-use condition, close controller/tests and retry; do not force-unload a driver. Demand-start means it will not automatically load at boot.

If the VM becomes unstable, use hypervisor console/snapshot recovery rather than making more network policy changes. Remove any narrow fixture firewall exception and the **specific lab certificate thumbprint** from the VM's Root/TrustedPublisher stores. If test mode was enabled solely for this exercise, restore it (`bcdedit /set testsigning off`, reboot) after removing the test driver. Reset Driver Verifier if used. Never delete unrelated certificates or drivers.
