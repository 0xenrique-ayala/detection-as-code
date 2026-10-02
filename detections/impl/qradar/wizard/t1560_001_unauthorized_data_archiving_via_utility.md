# T1560.001 Unauthorized Data Archiving via Utility

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

### BB-1: `Sysmon Archive via Zip Utilities`

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
| 3 | And when the event matches search filter `Event ID = 1`, `Image contains any of 7z.dll or 7za.exe or WinRaR.exe or rar.exe or tar.exe or makecab.exe or compact.exe or PowerShell.EXE`, `CommandLine contains any of (space)-p or (space)-hp or (space)-pass or Compress-Archive or (space)-a or (space)-cif or (space)czf or (space)-czf` | 

### BB-2: Sysmon Archive via PowerShell Cmdlets

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
| 4 | And when the event matches this AQL filter query ``` ("CommandLine" ILIKE '%\Users\Public\%' OR "CommandLine" ILIKE '%\AppData\Local\Temp\%' OR "CommandLine" ILIKE '%C:\Windows\Temp\%' OR "CommandLine" ILIKE '%\ProgramData\%') AND "ParentCommandLine" ILIKE '%Compress-Archive%' AND NOT ("Image" ILIKE 'false-positive.exe' AND "CommandLine" ILIKE ''%\folder\subfolder\%'' ```| 

## Core Rule

## CR: 
