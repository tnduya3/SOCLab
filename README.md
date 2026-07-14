# SOC Home Lab 

##  Executive Summary
This project documents the simulation of a multi-stage intrusion in a segmented enterprise network, beginning with an SSRF-to-RCE foothold on an internet-facing web application and escalating through Havoc C2 tunneled over legitimate Microsoft infrastructure (devtunnel) to evade signature-based detection. The attack chain progresses from the DMZ into an Active Directory environment via a domain-trust misconfiguration, exercising lateral movement, privilege escalation, and persistence techniques. The objective is to evaluate detection coverage across network (IDS/IPS), host (Sysmon, providing granular process, network, and registry telemetry), and identity (AD) layers against each stage of the chain, centralized and correlated through Wazuh.

## Homelab Architecture Overview
The lab is built to emulate a small enterprise network with a realistic, exploitable trust boundary between an internet-facing service and an internal Active Directory environment. Rather than isolating each component for convenience, the topology intentionally reproduces a common real-world misconfiguration: **a domain-joined server sitting in the DMZ**. This creates a plausible path from external compromise to internal lateral movement, which is the core scenario the lab is designed to detect, not just prevent.
* **Infrastructure:** Virtualized lab on VMware Workstation using LAN Segments for VLAN-equivalent isolation, with pfSense as the central router/DHCP/firewall boundary across three zones (AD_Zone, DMZ, Client)
* **Defensive Stack:** Wazuh (agent-based host telemetry + centralized management via Wazuh Cloud), Sysmon (granular endpoint process/network/registry visibility), pfSense firewall rules (inter-zone access control)
* **Offensive Arsenal:** Havoc C2 framework, Microsoft dev tunnels (devtunnel) for C2 traffic tunneling over trusted infrastructure, Likeshop SSRF (CVE-2024-24028) as the initial-access exploit chain

![High-Level Topology Diagram](assets/topo/overview_system.png)

## Threat Emulation Scope
- **Initial Access & Execution:** Exploitation of a known SSRF vulnerability (CVE-2024-24028) in the Likeshop web application hosted on the DMZ-facing IIS server, chained toward remote code execution to establish an initial foothold.
- **Command & Control (C2):** Havoc C2 framework, with C2 traffic tunneled through Microsoft dev tunnels (devtunnel) to blend with legitimate Microsoft infrastructure and evade reputation/signature-based network detection.
- **Privilege Escalation:** UAC bypass via CMSTPLUA/CmstpElevatedCOM — Havoc invokes the CmstpElevatedCOM module, which loads an elevated CMLuaUtil COM object; `dllhost.exe` acts as the COM surrogate under SYSTEM logon and calls ShellExec to spawn the agent elevated.
- **Lateral Movement:** Access token manipulation to leverage the elevated SYSTEM context obtained above, followed by SMB named pipe pivoting and PsExec to move into AD_Zone.
* **Framework Alignment:** T1190, T1102, T1572, T1548.002, T1559.001, T1134.001, T1071.004, T1021.002, T1569.002

## Detection & Analysis Highlights

> [!NOTE]
> Still writing..., be patient!

## Documentation Directory
1. [Network Architecture & Environment Setup](./Network_Architecture/README.md)
2. [Attack Simulation: Red Team Operations](./Attack_Simulation/README.md)
3. [Analysis & Detection: Blue Team Operations](./Analysis&Detection/README.md)

---
*Documented by: Nhat Duy  | Date: July, 2026*