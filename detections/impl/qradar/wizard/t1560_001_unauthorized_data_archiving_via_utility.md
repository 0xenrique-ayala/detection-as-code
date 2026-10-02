# T1560.001 Unauthorized Data Archiving via Utilities

**Status:** Experimental (lab)

**Validation:** Lab example — logic reviewed; not production-validated as a universal rule. Adapt and baseline locally.

**SIEM:** IBM QRadar (rule wizard)

**Related Sigma:** `detections/sigma/t1560_001_unauthorized_data_archiving_via_utility.yml`

**Related AQL:** `detections/impl/qradar/aql/t1560_001_unauthorized_data_archiving_via_utility.md`

**ATT&CK ID:** T1560.001 — Archive Collected Data/Archive via Utility

---

## Intent

Detect automated or bulk archiving activity that may indicate collection/staging of data prior to exfiltration or unauthorized backup-style packaging of sensitive content.

Lab framing: logic and naming are **examples** for adaptation. Map fields, paths, and thresholds to your environment before production use.

## Telemetry notes

In this lab pattern, Sysmon process-create activity is collected via **WinCollect** and appears in QRadar as log source type **Microsoft Windows Security Event Log**, Event ID **1**, QID **7400021**. Other environments may use a dedicated Sysmon DSM/log source type—map LST/QID/properties to local parsing.

## High-Level Design

| Piece | Role |
| --- | --- |
| Building Blocks (3) | Reusable tests that identify three utility paths under T1560.001. |
| Core Rule (1) | Correlates BBs and fires when suspicious archive staging is present. |

**Create order:** Building Blocks → Core Rule.

## Building Blocks

Create these **before** the core rule. Name them so intent is obvious.

### BB-1: `BB:Sysmon Archive via Zip Utilities`

| Field | Value | 
| --- | --- | 
| Purpose | Identify Sysmon-related events associated with archiving using Zip utilities especially when password/pack-style switches appear. |
| Rule Type | Building Block |
| Rule Test Elements | Log Source Type, QID, Properties/Values |
| Log Source Types | Microsoft Windows Security Event Log |
| Uses Reference Sets | No | 
| Output | Matches archive-like process activity where Zip utilities are used. |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when the events were detected by one or more of these log source types `Microsoft Windows Security Event Log` | 
| 2 | And when the event QID is one of the following QIDs `7400021` |
| 3 | And when the event matches search filter `Event ID = 1`, `Image contains any of 7z.dll or 7za.exe or WinRAR.exe or rar.exe or makecab.exe or compact.exe`, `CommandLine contains any of (space)-a or (space)-p or (space)-hp or (space)-pass` | 

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
| 1 | And when the events were detected by one or more of these log source types `Microsoft Windows Security Event Log` | 
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
| 1 | And when the events were detected by one or more of these log source types `Microsoft Windows Security Event Log` | 
| 2 | And when the event QID is one of the following QIDs `7400021` |
| 3 | And when the event matches search filter `Event ID = 1`, `Image contains any of tar.exe or tar.dll`, `CommandLine contains any of (space)cjf or (space)-cjf or (space)czf or (space)-czf` | 

## Core Rule

### CR: `Unauthorized Data Archiving via Utilities`

| Field | Value |
|---|---|
| Purpose | Fire when archive behavior occurs |
| Rule Type | Event rule |
| Rule Test Elements | Building Blocks, Properties/Values |
| Building Blocks Used | Any of BB-1, BB-2, BB-3 |
| Deploy Notes | Baseline first; expect FP tuning |

**Example Rule Conditions**

| Rule Test # (Top-Down) | Rule Test |
| --- | --- |
| 1 | And when an event matches any of the following building blocks `BB:Sysmon Archive via Zip Utilities` or `BB:Sysmon Archive via PowerShell Cmdlets` or `BB:Sysmon Archive via Tar Utilities` | 
| 2 | And Not when the event matches search filter `Username equals ANONYMOUS LOGON` |

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

## Example Triage (when the rule fires)

| # | Check | Actions |
|---|---|---|
| 1 | Offense details. | Pull the `Source IP`, `Username`, `Image`, `ProcessID`, and full `CommandLine`. |
| 2 | What was archived? | From the `CommandLine`, note paths (Documents, Desktop, share drives, or export folders). |
| 3 | Encryption flags? | Look for -p, -hp, or password-style options; if present with odd path/parent, treat as higher risk and escalate. |
| 4 | Benign or suspicious? | Known backup/script vs unexpected user/host/path; tune if noisy, escalate if suspicious. |

**Escalate to IR when:** unexpected account/host, sensitive paths, encryption flags, or odd parent process (with evidence above).
