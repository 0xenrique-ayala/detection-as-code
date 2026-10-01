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

### BB-1

### BB-2

## Core Rule

## CR: 
