# SPL — T1560.001 Unauthorized Data Archiving via Utilities (lab)

**Role:** Hunt / baseline / validate in Splunk.  
QRadar building blocks + core rule are documented in the **wizard** file.  
These searches approximate the same three utility paths for Splunk detection engineering practice.

**Related**
- Wizard: `detections/impl/qradar/wizard/t1560_001_unauthorized_data_archiving_via_utility.md`
- AQL: `detections/impl/qradar/aql/t1560_001_unauthorized_data_archiving_via_utility.md`
- Sigma: `detections/sigma/t1560_001_unauthorized_data_archiving_via_utility.yml`

**Telemetry (lab assumption):** Windows process-create style events (e.g. Sysmon EventCode 1 or equivalent CIM/`Endpoint` data).  
Map `Image` / `CommandLine` / `EventCode` to your sourcetype and field names (WinEventLog, Sysmon, CrowdStrike, etc.).

**Time range:** Default **last 24 hours** in the UI (or `earliest=-24h`).  
Widen deliberately for baselining; full-fleet wildcard command-line searches can be expensive.

**Validation:** Lab/example only — not production-validated as a universal correlation search.

---

## Field mapping notes

| Concept | Example Splunk fields (adapt) |
|---|---|
| Process image | `Image`, `process_name`, `process` |
| Command line | `CommandLine`, `process_command_line`, `Command_Line` |
| Process create | `EventCode=1` (Sysmon) or equivalent |
| User | `User`, `user`, `AccountName` |
| Host | `host`, `Computer`, `dest` |

Examples below use **Sysmon-like** `Image`, `CommandLine`, `EventCode`. Replace with your CIM/datamodel fields if you use `Endpoint.Processes`.

---

**Style:** Process names use `IN` + `*` wildcards (common Splunk practice).  
Space-bounded command switches use `match()` regex with `(?i)`, aligned to AQL `MATCHES`.  
Default time range: last 24 hours. Map `index` / `sourcetype` / field names to your environment.

## Hunt ≈ BB-1 (zip / rar utilities + pack/password-style switches)

```spl
index=* sourcetype=*sysmon* EventCode=1
Image IN ("*\\7z.exe", "*\\7za.exe", "*\\7zr.exe", "*\\rar.exe")
| where match(CommandLine, "(?i).*\\sa\\s.*") OR match(CommandLine, "(?i).*\\s-p\\S+\\s.*") OR match(CommandLine, "(?i).*\\s-hp\\S+\\s.*")
| table _time Image CommandLine
| sort -_time
```

---

## Hunt ≈ BB-2 (PowerShell / cmd + Compress-Archive + staging-ish paths)

```spl
index=* sourcetype=*sysmon* EventCode=1
Image IN ("*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe")
CommandLine="*Compress-Archive*"
(
  CommandLine="*\\Users\\Public\\*"
  OR CommandLine="*\\AppData\\Local\\Temp\\*"
  OR CommandLine="*C:\\Windows\\Temp\\*"
  OR CommandLine="*\\ProgramData\\*"
)
| table _time Image CommandLine
| sort -_time
```

---

## Hunt ≈ BB-3 (tar-style)

```spl
index=* sourcetype=*sysmon* EventCode=1
Image IN ("*\\tar.exe")
| where match(CommandLine, "(?i).*\\scjf\\s.*")
    OR match(CommandLine, "(?i).*\\s-cjf\\s.*")
    OR match(CommandLine, "(?i).*\\sczf\\s.*")
    OR match(CommandLine, "(?i).*\\s-czf\\s.*")
| table _time Image CommandLine
| sort -_time
```

---


