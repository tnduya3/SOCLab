# Detection Report — Stage 3: Privilege Escalation (UAC Bypass via CmstpElevatedCOM)

> **Cross-reference:** `03-privilege-escalation-uac-bypass.md` — attack execution detail 
> **Target Host/Victim/Agent:** 10.20.30.2 (Windows 10 Pro x64)
> **Log sources:** Sysmon (SwiftOnSecurity config), shipped via Wazuh agent → Wazuh Cloud 
> **Telemetry status:** Real captured events from an actual simulation run, not modeled — Stage 2's foothold was live before this stage executed.

---

## 1. What Actually Happened

The name "UAC bypass" is a little misleading here, and it's worth correcting before anything else: this technique does not skip `consent.exe`. `consent.exe` runs, exactly as Windows' elevation framework intends, it just never renders a visible prompt to a user, because the specific COM elevation moniker abused (`CLSID {3E5FC7F9-9A51-4367-9063-A120244FBEC7}`, the CMLuaUtil interface) is on Microsoft's auto-elevate allowlist. The attacker isn't breaking the elevation flow; they're walking through a door Windows already left open for a specific trusted COM object, and getting AppInfo to silently rubber-stamp it.

The mechanism, reconstructed from Havoc's own operator log plus Sysmon:

1. The Havoc module reads `explorer.exe`'s PEB - almost certainly to borrow its session/token context, so the COM elevation request resolves as if a logged-in interactive user made it, rather than a background service call that would be treated with more suspicion.
2. It instantiates the elevated CMLuaUtil COM object. This is what triggers AppInfo to spin up `consent.exe` under SYSTEM to process the elevation request silently, because of the allowlisted CLSID.
3. The module calls `ShellExec` directly on the elevated COM object, which results in `dllhost.exe` (the COM surrogate hosting CMLuaUtil) spawning the actual payload, now running at High integrity.

One correction to the original execution doc's stated outcome: the resulting process (`exec_AD.exe`) runs as **`SOCLab\Client`** (the machine account) at **High integrity**, not as `NT AUTHORITY\SYSTEM`. The COM surrogate (`dllhost.exe`) operates under a SYSTEM logon to perform the elevation, but the payload it launches inherits High integrity under the existing machine account context SYSTEM-level _capability_ was used to escalate the session, not SYSTEM identity itself carried forward into the payload.

---

## 2. The Event Chain - An Analyst's Walkthrough

This is the part that should sit uncomfortably with anyone relying purely on Sysmon: **the actual privilege-escalation mechanism, the PEB read against `explorer.exe` is invisible in this lab's current configuration.** Sysmon Event ID 10 (ProcessAccess), which would capture cross-process memory access like this, is not enabled. That means the step that _does the escalating_ leaves no trace. Everything below is downstream symptom, reconstructed after the fact, not the technique itself caught in the act.

**Event 1 - Sysmon Event ID 1 (Process Creation): `consent.exe`**

```
UtcTime:      2026-07-14 02:05:45.292
Image:        C:\Windows\System32\consent.exe
CommandLine:  consent.exe 1028 342 0000016C6C7BBC80
User:         NT AUTHORITY\SYSTEM
LogonId:      0x3E7
IntegrityLevel: System
ParentImage:  C:\Windows\System32\svchost.exe
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p
```

On its own, this event is almost unremarkable `svchost.exe -k netsvcs` spawning `consent.exe` under SYSTEM (LogonId `0x3E7` is the standard Windows service logon session, not itself anomalous) is exactly what the AppInfo service does for _any_ elevation request, legitimate or not. This is precisely why the technique works: nothing about this event alone screams attack. The only reason to flag it is context you don't have yet at this point in the timeline that no user was sitting at this host clicking "Run as Administrator."

**Event 2 - `dllhost.exe` launch under the elevated COM surrogate**

A `dllhost.exe` creation event was located in Wazuh corresponding to this window, hosting the CMLuaUtil COM surrogate (`/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`). This is the pivot point of the whole chain, the moment the elevated COM object comes into existence and becomes capable of executing `ShellExec` on the attacker's behalf.

**Event 3 - Sysmon Event ID 1 (Process Creation): payload, spawned from the COM surrogate**

```
UtcTime:      2026-07-14 02:05:45.715   (~423ms after consent.exe)
Image:        C:\Users\Public\Downloads\exec_AD.exe
CommandLine:  "C:\Users\Public\Downloads\exec_AD.exe"
User:         SOCLab\Client
LogonId:      0xD72B6
IntegrityLevel: High
ParentImage:  C:\Windows\System32\dllhost.exe
ParentCommandLine: C:\Windows\system32\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
```

This is the event that actually confirms escalation succeeded, a previously medium-integrity session now has a High-integrity process, launched through a COM surrogate rather than through any normal interactive elevation path. The ~423ms gap from `consent.exe`'s creation is tight enough to be a single automated operation, not a human clicking through anything. There's no interactive delay here, which is itself worth noting as a sub-second, non-human execution pattern.

The staging path is also worth calling out on its own: `C:\Users\Public\Downloads\` is not a normal execution location for anything on a production IIS server, and is a cheap, durable IOC independent of the COM elevation story entirely.

---

## 3. Detection Logic

**Primary rule - process lineage + CLSID:**

- Trigger: `dllhost.exe` launched with `CommandLine` containing `/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (the CMLuaUtil CLSID), where the resulting `dllhost.exe` process then spawns a child process from a non-standard path (`C:\Users\Public\...`, `C:\Windows\Temp\...`, or any path outside expected COM-surrogate child behavior).
- This CLSID is the single highest-confidence, lowest-noise indicator in this entire stage COM surrogates hosting this specific interface and then spawning arbitrary executables is not normal system behavior under any legitimate workflow.

**Supporting rule - timing + integrity jump:**

- Correlate a `consent.exe` creation event (SYSTEM, via `svchost.exe -k netsvcs`) with a subsequent process creation within a short window (seconds, not minutes) where the child's `IntegrityLevel` is High and its `ParentImage` is `dllhost.exe`. A sub-second-to-low-second gap between the two, with no corresponding interactive logon session on the console, is consistent with automated/scripted elevation rather than a real user approving a UAC prompt.

**Supporting rule - staging path:**

- Any process execution from `C:\Users\Public\Downloads\` or similar world-writable, non-standard staging directories on a server-role host, independent of the COM technique, and generically useful across other stages of this attack chain too.

---

## 4. Gaps and Blind Spots

- **The actual escalation mechanism is unobserved.** The PEB read against `explorer.exe` which is what makes the elevation moniker resolve as an interactive-user request rather than a service call, requires Sysmon Event ID 10 (ProcessAccess), which is not enabled in this lab. This is the single biggest gap in the stage: the technique itself is invisible; only its aftermath is logged. If this lab is meant to represent a realistic SOC posture, enabling Event ID 10 (with reasonable filtering to avoid volume overload. It is one of the noisiest Sysmon event types) should be a stated follow-up, not an afterthought.
- **No visible UAC prompt is not the same as "consent.exe was bypassed."** This report deliberately avoids that framing - the process ran, under SYSTEM, and auto-approved silently because of an allowlisted CLSID. Any write-up (or reader) that describes this as "skipping consent.exe" is describing the wrong mechanism, and could lead to defenders looking for the wrong absence (a missing `consent.exe` event) rather than the right presence (a `consent.exe` event with no corresponding interactive session).

