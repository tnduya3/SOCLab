## Attack Chain Summary

| Stage | Tactic (ATT&CK) | Technique | Status |
|---|---|---|---|
| 1 | Initial Access | Exploit Public-Facing Application (T1190) — Likeshop SSRF (CVE-2024-24028) → RCE | RCE chain in progress |
| 2 | Command & Control | Protocol Tunneling (T1572) — Havoc C2 over Microsoft devtunnel | Implemented |
| 3 | Privilege Escalation | Bypass UAC (T1548.002) — CmstpElevatedCOM / CMLuaUtil COM elevation | Implemented |
| 4 | Privilege Escalation / Defense Evasion | Access Token Manipulation (T1134) — token impersonation | Implemented |
| 5 | Lateral Movement | Remote Services: SMB/Admin Shares (T1021.002) — SMB named pipe pivot + PsExec, authenticated via impersonated token | Implemented |
| 6 | Persistence | *TBD* | Not yet implemented |

## Execution Phases

## Attack Chain Execution Phases

### Stage 1: Initial Access
**Precondition:** Likeshop deployed and accessible from external/lab network  
**Action:** Exploit CVE-2024-24028 (SSRF vulnerability), chain toward RCE on IIS_Server  
**Result:** Code execution foothold on IIS_Server (DMZ)

### Stage 2: Command & Control
**Precondition:** Code execution on IIS_Server  
**Action:** Deploy Havoc C2 agent, tunnel C2 traffic through Microsoft devtunnel  
**Result:** Stable, interactive Havoc C2 session established over devtunnel

### Stage 3: Privilege Escalation (UAC Bypass)
**Precondition:** C2 session on IIS_Server running as standard/limited user  
**Action:** Invoke Havoc's CmstpElevatedCOM module; escalate via CMLuaUtil COM object elevation, dllhost.exe becomes COM surrogate under SYSTEM  
**Result:** SYSTEM-level access on IIS_Server

### Stage 4: Credential Access
**Precondition:** SYSTEM access on IIS_Server (domain-joined)  
**Action**: Perform Access Token Impersonate
**Action (Future):** Perform Kerberoasting attack — request TGS tickets for domain service accounts, extract and prepare for offline cracking  
**Result:** Valid domain admin credential

### Stage 5: Lateral Movement
**Precondition:** Valid domain credentials from Stage 4   
**Action:** Pivot from IIS_Server (DMZ) to AD_Zone via SMB named pipe + PsExec, authenticated with cracked credentials  
**Result:** Code execution with SYSTEM-level access on target host in AD_Zone

### Stage 6: Persistence
**Precondition:** Code execution in AD_Zone  
**Action:** *TBD — not yet implemented*  
**Result:** *TBD*


Each stage is documented in detail in its corresponding file:
- [01-initial-access](./Attack_Simulation/01-initial-access.md)
- [02-command-and-control](./Attack_Simulation/02-command-and-control.md)
- [03-privilege-escalation-uac-bypass](./Attack_Simulation/03-privilege-escalation-uac-bypass.md)
- [04-token-impersonation](./Attack_Simulation/04-token-impersonation.md)
- [05-lateral-movement](./Attack_Simulation/05-lateral-movement.md)


