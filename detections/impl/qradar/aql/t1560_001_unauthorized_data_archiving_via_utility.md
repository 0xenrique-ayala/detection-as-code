# AQL — T1560.001 Unauthorized Data Archiving via Utilities (lab)

**Role:** Hunt / baseline / validate.  
Building blocks + core rule are built in **Rule Wizard** (see wizard doc).  
These queries approximate the same behaviors for investigation.
Wizard Doc: `detections/impl/qradar/wizard/t1560_001_unauthorized_data_archiving_via_utility.md`

**Telemetry:** Sysmon process-create via WinCollect → LST Microsoft Windows Security Event Log, Event ID 1, QID 74000021 (lab). Map properties locally.

**Time range:** Default `LAST 24 HOURS` for safe exploratory use.
For baselining, widen deliberately (e.g. 7 days) in a lab or off-peak window, and/or tighten filters first.

**AQL tip: spaces around command switches**

`ILIKE` with `%` does **not** treat `\s` as whitespace. For a **space before and after** a switch/token, use **`MATCHES`** (regex):

```aql
"CommandLine" MATCHES '.*\scjf\s.*'
```

**Core rule note**

The **core rule** is built in Rule Wizard (BB-1 / BB-2 / BB-3 + exclusions + response + limiter).  
It is **not** a single AQL rule. Use the three hunts below to validate each path; enable the wizard core for correlation/offense behavior.

---

## Hunt ≈ BB-1 (zip / rar utilities + pack/password-style switches)

```aql
SELECT sourceip, username, "Image", "CommandLine", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE devicetype = 12
AND qid = 74000021
AND "Event ID" = 1
AND ("Image" ILIKE '%7z.exe%' OR "Image" ILIKE '%7za.exe%' OR "Image" ILIKE '%7zr.exe%' OR "Image" ILIKE '%rar.exe%')
AND ("CommandLine" MATCHES '.*\sa\s.*' OR "CommandLine" MATCHES '.*\s-p\S+\s.*' OR "CommandLine" MATCHES '.*\s-hp\S+\s.*')
LAST 24 HOURS
```

---

## Hunt ≈ BB-2 (PowerShell / cmd + Compress-Archive + staging-ish paths)

```aql
SELECT sourceip, username, "Image", "CommandLine", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE devicetype = 12
AND qid = 74000021
AND "Event ID" = 1
AND ("Image" ILIKE '%powershell.exe%' OR "Image" ILIKE '%pwsh.exe%' OR "Image" ILIKE '%cmd.exe%')
AND ("CommandLine" ILIKE '%\Users\Public\%' OR "CommandLine" ILIKE '%\AppData\Local\Temp\%' OR "CommandLine" ILIKE '%C:\Windows\Temp\%' OR "CommandLine" ILIKE '%\ProgramData\%')
AND "CommandLine" ILIKE '%Compress-Archive%'
LAST 24 HOURS
```

---

## Hunt ≈ BB-3 (tar-style)

```aql
SELECT sourceip, username, "Image", "CommandLine", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE devicetype = 12
AND qid = 74000021
AND "Event ID" = 1
AND ("Image" ILIKE '%tar.exe%')
AND ("CommandLine" MATCHES '.*\scjf\s.*' OR "CommandLine" MATCHES '.*\s-cjf\s.*' OR "CommandLine" MATCHES '.*\sczf\s.*' OR "CommandLine" MATCHES '.*\s-czf\s.*')
LAST 24 HOURS
```
