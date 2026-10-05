# AQL — T1560.001 unauthorized data archiving via utilities (lab)

**Role:** Hunt / baseline / validate.  
Building blocks + core rule are built in **Rule Wizard** (see wizard doc).  
These queries approximate the same behaviors for investigation.

**Telemetry:** Sysmon process-create via WinCollect → LST Microsoft Windows Security Event Log, Event ID 1, QID 74000021 (lab). Map properties locally.

---

## Hunt ≈ BB-1 (zip / rar utilities + pack/password-style switches)

```aql
SELECT sourceip, username, "Image", "CommandLine", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE qid = 74000021
  AND "Event ID" = 1
  AND (
    "Image" ILIKE '%7za.exe%' OR "Image" ILIKE '%WinRAR.exe%'
    OR "Image" ILIKE '%rar.exe%' OR "Image" ILIKE '%makecab.exe%' OR "Image" ILIKE '%compact.exe%'
  )
  AND (
    "CommandLine" ILIKE '% -a %' OR "CommandLine" ILIKE '% -p%'
    OR "CommandLine" ILIKE '% -hp%' OR "CommandLine" ILIKE '% -pass%'
  )
LAST 24 HOURS
```

---

## Hunt ≈ BB-2 (PowerShell / cmd + Compress-Archive + staging-ish paths)

```aql
SELECT sourceip, username, "Image", "CommandLine", DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE qid = 7400021
  AND "Event ID" = 1
  AND (
    "Image" ILIKE '%powershell.exe%' OR "Image" ILIKE '%pwsh.exe%' OR "Image" ILIKE '%cmd.exe%'
  )
  AND "CommandLine" ILIKE '%Compress-Archive%'
  AND (
    "CommandLine" ILIKE '%\Users\Public\%'
    OR "CommandLine" ILIKE '%\AppData\Local\Temp\%'
    OR "CommandLine" ILIKE '%C:\Windows\Temp\%'
    OR "CommandLine" ILIKE '%\ProgramData\%'
  )
LAST 24 HOURS
```

---

