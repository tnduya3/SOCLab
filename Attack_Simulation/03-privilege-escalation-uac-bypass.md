# Stage 3: Privilege Escalation UAC Bypass
## Lab Setup

> **Malware:** [Havoc C2](https://github.com/HavocFramework/Havoc) 
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

![[UnderstandingUAC.png]]