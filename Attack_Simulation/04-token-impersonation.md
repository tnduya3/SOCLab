# Stage 4: Credential Access - Token Impersonate

> **Malware:** [Havoc C2](https://github.com/HavocFramework/Havoc) 
> **MITRE Tactics:** [TA0006 Credential Access](https://attack.mitre.org/tactics/TA0006/), [TA0004 Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) 
> **MITRE Techniques:** [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134/), [T1134.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/) 
> **Target Process:** winlogon.exe (SYSTEM)
> **Target Host/Victim/Agent:** 10.20.30.2 (Windows 10 Pro x64)
> **Reference:** [Manipulating Access Tokens: How Adversaries Leverage Windows Security Contexts](https://medium.com/@itzsanskarr/manipulating-access-tokens-how-adversaries-leverage-windows-security-contexts-2bf7ed38e55f)

**Precondition:** SYSTEM-level access, established in Stage 3 - Privilege Escalation.

**Action:** Invoke SeDebugPrivilege to open a handle to winlogon.exe, duplicate its access token, and impersonate the SYSTEM security context, granting the attacker token-based access to resources and contexts available to winlogon without requiring credential extraction.

**Result:** Impersonated SYSTEM token available for use within the C2 session; subsequent actions (lateral movement, file access, service interaction) can be executed under the stolen token's context without credential material being directly exposed in memory.

---
## Understanding Tokens and Login Sessions

Quick refresher before we dive into the fun stuff: Windows authentication revolves around **login sessions** and **access tokens**.

- A **login session** is basically “you’re in.” It starts after successful authentication and ends when you log off.
- Each session gets a **64-bit LUID** (logon ID), and each token has an **Authentication ID (AuthId)** linking it back to that session.

The **Local Security Authority (LSA)** handles this automatically, quietly doing all the heavy lifting. Think of the token as a backpack with all your security goodies in it.

Tokens include:

- User and group SIDs (your social circle in Windows terms)
- Assigned privileges (what you’re allowed to touch)
- Rights like SeDebugPrivilege (the “I can open anything” button)

### Types of Access Tokens

Windows has two main token types:

1. **Primary Tokens** — The “main” token you get when logging in interactively or remotely.
2. **Impersonation Tokens** — The “pretend to be someone else for a while” token.

Attackers often grab a token from one process and spin up another process using it.

### Local Administrator and Privilege Escalation

Open two command prompts: one normal, one with admin rights. The admin prompt shows **BUILTIN\Administrators** as the owner. That is your token waving its little flag saying “I can do everything.”

Attackers love this. Why? Because with two privileges, they can:

- Impersonate a client using SeImpersonatePrivilege
- Debug other processes using SeDebugPrivilege

SeDebugPrivilege is basically a “skeleton key.” You can open almost any door on the system, which is why token theft becomes very interesting.

---
## Execution

**Step 1: Enable SeDebugPrivilege**

SeDebugPrivilege is a privilege that allows a process to open handles to other processes and read/manipulate their memory. SYSTEM processes and administrators typically have this privilege available, but it must be explicitly enabled in the token before use.

```
token privs-get SeDebugPrivilege
```

![Output confirming SeDebugPrivilege is now enabled in the C2 session.](assets/UAC/sedebug.png)

![Validate sedebug](assets/UAC/debug.png)
**Step 2: Locate and open winlogon.exe**

With SeDebugPrivilege enabled, the attacker can open a handle to winlogon.exe with `PROCESS_QUERY_INFORMATION` and `PROCESS_DUP_HANDLE` access rights. winlogon.exe is chosen because it:

- Always runs as SYSTEM on an interactive desktop
- Has a predictable name and typically one instance per session
- Holds a valid, authenticated token for the interactive logon session

```
powershell ps winlogon
```

![Output showing winlogon.exe process details and PID.](assets/UAC/winlogon.png)

**Step 3: Duplicate and impersonate the token**

Once a handle to winlogon.exe is open, the attacker duplicates its access token and impersonates it, switching the C2 thread's security context to SYSTEM.

```
token steal <PID>
```

![Output confirming token impersonation successful, showing new security context as SYSTEM/winlogon.](assets/UAC/ad.png)

### Detection Considerations

_(To be expanded in the detection-engineering document — noting here as a placeholder for cross-reference.)_

- **Sysmon Event ID 8 (CreateRemoteThread):** abnormal attempts to inject into winlogon.exe or similar system processes from a less-privileged parent (e.g., dllhost.exe spawned by IIS).
- **Sysmon Event ID 10 (ProcessAccess):** `PROCESS_DUP_HANDLE` or `PROCESS_QUERY_INFORMATION` access to winlogon.exe from an unexpected source process.
- **Windows Security Event 4703:** SeDebugPrivilege enabled within a process that shouldn't routinely require it (e.g., a web server's C2 agent).
- **Behavioral:** correlation of SeDebugPrivilege enablement → ProcessAccess to winlogon.exe → rapid privilege context changes in short time window.

### Limitations & Implications

Token impersonation via local handle duplication is constrained to the _local machine_ — the stolen token cannot be used to authenticate to _remote_ services or lateral movement targets. To pivot to other hosts with this SYSTEM context, the attacker must use local execution primitives (like PsExec) that run commands on the remote host under a _separate_ security context (authenticated via credentials, not the token itself).

This is why Stage 4a (token impersonation) establishes local SYSTEM authority, but Stage 5 (lateral movement) still requires _additional_ credential material (obtained via a separate technique, or reused from elsewhere) to authenticate to remote systems.

---

