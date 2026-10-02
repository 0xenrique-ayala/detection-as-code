# T1560.001 Unauthorized Data Archiving via Utilities

**Status:** Experimental (lab)

**SIEM:** IBM QRadar (rule wizard)

**Related Sigma:** `detections/sigma/t1560_001_unauthorized_data_archiving_via_utility.yml`

**Related AQL:** `detections/impl/qradar/aql/t1560_001_unauthorized_data_archiving_via_utility.md`

**ATT&CK ID:** T1560.001 — Archive Collected Data/Archive via Utility

---

## Intent

Detect automated or bulk archiving activity that may indicate collection/staging of data prior to exfiltration or unauthorized backup-style packaging of sensitive content.

Lab framing: logic and naming are **examples** for adaptation. Map fields, paths, and thresholds to your environment before production use.

## High-Level Design

| Piece | Role |
| --- | --- |
| Building Blocks (3) | Reusable tests that identify archive tooling, sensitive targets, or automation context |
| Core Rule (1) | Correlates BBs + thresholds + responses when suspicious archive staging is present |

**Create order:** Building Blocks → Core Rule.

## Building Blocks

Create these **before** the core rule. Name them so intent is obvious.

### BB-1: `BB:Sysmon Archive via Zip Utilities`

| Field | Value | 
| --- | --- | 
| Purpose | Identify Sysmon-related events associated with archiving using Zip utilities. |
| Rule Type | Building Block |
| Rule Test Elements | Log Source Type, QID, Properties/Values |
| Log Source Types | Microsoft Windows Security Event Log |
| Uses Reference Sets | No | 
| Output | Matches archive-like process activity where Zip utilities are used. |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when the events were detected by one ore more of these log source types `Microsoft Windows Security Event Log` | 
| 2 | And when the event QID is one of the following QIDs `7400021` |
| 3 | And when the event matches search filter `Event ID = 1`, `Image contains any of 7z.dll or 7za.exe or WinRaR.exe or rar.exe or makecab.exe or compact.exe`, `CommandLine contains any of (space)-p or (space)-p or (space)-hp or (space)-pass` | 

### BB-2: `BB:Sysmon Archive via PowerShell Cmdlets`

| Field | Value | 
| --- | --- | 
| Purpose | Identify Sysmon-related events associated with archiving using PowerShell cmdlets. |
| Rule Type | Building Block |
| Rule Test Elements | Log Source Type, QID, Properties/Values, multi-part AQL |
| Log Source Types | Microsoft Windows Security Event Log |
| Uses Reference Sets | No | 
| Output | Matches archive-like process activity where PowerShell cmdlets are used. |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when the events were detected by one ore more of these log source types `Microsoft Windows Security Event Log` | 
| 2 | And when the event QID is one of the following QIDs `7400021` |
| 3 | And when the event matches search filter `Event ID = 1`, `"Image" contains any of powershell.exe or pwsh.exe or cmd.exe` | 
| 4 | And when the event matches this AQL filter query (see below) |

**AQL filter (Rule Test 4):**

```AQL
("CommandLine" ILIKE '%\Users\Public\%'
OR "CommandLine" ILIKE '%\AppData\Local\Temp\%'
OR "CommandLine" ILIKE '%C:\Windows\Temp\%'
OR "CommandLine" ILIKE '%\ProgramData\%')
AND "CommandLine" ILIKE '%Compress-Archive%'
AND NOT ("Image" ILIKE 'false-positive.exe'
AND "CommandLine" ILIKE '%\folder\subfolder\%')
```

### BB-3: `BB:Sysmon Archive via Tar Utilities`

| Field | Value | 
| --- | --- | 
| Purpose | Identify Sysmon-related events associated with archiving using Tar utilities. |
| Rule Type | Building Block |
| Rule Test Elements | Log Source Type, QID, Properties/Values |
| Log Source Types | Microsoft Windows Security Event Log |
| Uses Reference Sets | No | 
| Output | Matches archive-like process activity where Tar utilities are used. |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when the events were detected by one ore more of these log source types `Microsoft Windows Security Event Log` | 
| 2 | And when the event QID is one of the following QIDs `7400021` |
| 3 | And when the event matches search filter `Event ID = 1`, `Image contains any of tar.exe or tar.dll`, `CommandLine contains any of (space)cjf or (space)-cjf or (space)czf or (space)-czf` | 

## Core Rule

## CR: `Unauthorized Data Archiving via Utilities`

| Field | Value |
|---|---|
| Purpose | Fire when archive behavior occurs |
| Rule Type | Event rule |
| Rule Test Elements | Building Blocks, Properties/Values |
| Building Blocks Used | BB-1, BB-2, and BB-3 |
| Deploy Notes | Baseline first; expect FP tuning |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when an event matches any of the following building blocks `BB:Sysmon Archive via PowerShell Cmdlets` or `BB:Sysmon Archive via PowerShell Cmdlets` or `BB:Sysmon Archive via Tar Utilities` | 
| 2 | And Not when the event matches search filter `Username is any of ANONYMOUS LOGON or SYSTEM` |

**Example Rule Response**

| Field | Value |
|---|---|
| Dispatch New Event | Enabled |
| Event Name | Unauthorized Automated Data Archiving via Utilities |
| Severity | 7 |
| Credibility | 8 | 
| Relevance | 7 |
| High-Level Category | Suspicious Activity |
| Low-Level Category | Suspicious Pattern Detected |

**Example Rule Limiter**

| Field | Value |
|---|---|
| Response Limiter | Enabled |
| Values | `1` time per `60` `minutes` per `Source IP` | 

**Example MITRE ATT&CK for Enterprise Mapping**

| Field | Value |
|---|---|
| Tactic | TA0009 Collection |
| Technique | T1560 Archive Collected Data |
| Sub-Technique | T1560.001 Archive via Utility |
| Confidence | Medium |

## False Positive Risks

| Risk | Why | Action|
|---|---|---|
| Missing Events | Silent failure. | Health: ensure Sysmon is installed and Event ID 1 is collected. |
| Admin One-Off Packaging | Looks automated if scripted. | BB tuning for recurring; have user exception process ready. |
| Legitimate Utility Usage | Recurring trusted activity. | BB tuning; create BB:FalsePositive: building block; apply to core rule using And Not multi-part rule test. |
| Non-Utility Usage Noise | Over-scoped building blocks. | BB tuning using multi-part rule test. |

## Triage (when this fires)

**Initial Triage & Verification**

| Step | Response | Actions |
|---|---|---|
| 1 | Extract Archival Footprints | Open the active QRadar offense.  Extract the target workstation's `Source IP`, `Username`, `Image`, `ProcessID`, and the complete `CommandLine` text block. |
| 2 | Evaluate Target Assets | Inspect the full string patch inside the `CommandLine` to identify what data the process is compressing (look for arguments pointing to Documents, Desktop, share drives, or database export folders. |
| 3 | Check for Encryption Signatures | Verify if the command string includes password concealment markers (such as -p, -hp, or .zip encryption functions). If encryption flags are present alongside an unauthorized script, escalate the incident status to a true positive compromise. |

**Immediate Containment**

Containment actions must occur instantly upon validation to stop the adversary from executing an outbound data exfiltration transfer.

| Step | Response | Actions |
|---|---|---|
| 1 | Execute Host Isolation | Using available security tools, isolate the machine to block all lateral and outbound internet paths. |
| 2 | Emergency Identity Lock | Take the user profile string found in the `Username` column.  Open your Identity Provider interface (Active Directory, etc.) and disable the account instantly to invalidate the attacker's active Kerberos or OAuth session credentials across the corporate domain. |

**Eradication & Recovery Workflow**

Once the host network connectivity is severed and the identity profile is locked down, analysts must purge the staging folders and verify fleet hygiene.

| Step | Response | Actions |
|---|---|---|
| 1 | Terminate Active Process Streams | Use available security tools with access to the machine to force a process termination command against the specific `Image` file `ProcessID` caught executing the loop. |
| 2 | Shred Staged Archive Containers | Locate the exact target archive file created by the compression process (as shown in the triage `CommandLine` analysis). Use your security tools to permanently delete and wipe the staging package file off the hard drive disk directory to prevent potential recovery. |
| 3 | Run Full Endpoint Telemetry Sweeps | Prior to lifting isolation, initiate a full host behavioral memory scan via EDR or available security tools. Review the endpoint timeline 15 minutes before the archiving event to locate the primary malware dropper or remote acdess framework that spawned the utility. |
| 4 | Remove from Isolation | Once all malicious parent execution files are wiped, persistence registries are cleared, and a clean malware scan is retuned, remove from isolation to return the endpoint to the corporate domain. |
