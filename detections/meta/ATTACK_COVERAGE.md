# ATT&CK coverage index

Public / lab detections only. No client data.

Statuses: `planned` | `experimental` | `stable`

- **planned** — tracked intent; content not fully published yet  
- **experimental** — in repo; lab / adaptation use  
- **stable** — reviewed reference pattern  

---

## Standalone detections

| Technique | Name | Sigma | Type | Status | Notes |
|---|---|---|---|---|---|
| T1046 | Wormlike internal multi-host pattern | `detections/sigma/t1046_wormlike_internal_multi_host.yml` | new | planned | Behavioral discovery / scan-style activity |
| T1560.001 | Sensitive archive staging | `detections/sigma/t1560_001_sensitive_archive_staging.yml` | new | planned | Collection / staging |
| T1123 | Unauthorized audio capture | `detections/sigma/t1123_unauthorized_audio_capture.yml` | new | planned | Optional; publish only if fully generic |

---

## Packs

| Pack | Path | Coverage | Status | Notes |
|---|---|---|---|---|
| BRICKSTORM | `packs/brickstorm/` | Multi-technique (see pack README) | experimental | From public CISA reporting; lab use |

---

## License / use

See root [README](../../README.md) and [LICENSE](../../LICENSE). Validate in your environment before production.
