## Summary
<!-- 1–3 sentences: what this PR adds or changes -->

## Type
- [ ] New detection
- [ ] Tune / FP reduction
- [ ] Pack content (`packs/`)
- [ ] Docs / meta only
- [ ] Other:

## Intent
<!-- What malicious or suspicious behavior is this meant to catch? -->

## ATT&CK
| Technique ID | Name | Notes |
|---|---|---|
| T#### | | |
| — | Not mapped | Reason: |

## Data sources
<!-- e.g. process, network, auth, DNS — high level; no client-specific CEPs -->

## Portable logic
- Sigma path: `detections/sigma/` or `packs/.../sigma/`
- Link or path:

## SIEM implementation notes
- [ ] QRadar Rule Wizard: `detections/impl/qradar/wizard/` or pack path
- [ ] QRadar AQL: `detections/impl/qradar/aql/` or pack path
- [ ] Splunk SPL: `detections/impl/splunk/` or pack path
- [ ] N/A for this PR

## False positive risks
<!-- Top 2–3 benign cases and how the logic limits them -->

## Validation
<!-- How was this checked? Lab only / sample events / logic review / not run in SIEM -->

- [ ] Logic review only
- [ ] Tested with sample / synthetic data
- [ ] Tested in a lab SIEM
- [ ] Not production-validated (default for this repo)

## Adaptation notes
<!-- What a consumer must map in their environment (fields, thresholds, allowlists) -->

## Silent failure / coverage gaps
<!-- What would make this miss or stop firing without obvious errors? -->

## ATT&CK coverage index
- [ ] Updated `detections/meta/ATTACK_COVERAGE.md` (if standalone detection)
- [ ] N/A (docs/pack-only / no index change)

## Author checklist
- [ ] No client data (names, hosts, IPs, prod CEPs, internal ticket IDs)
- [ ] Lab / public framing; “validate before production” assumed
- [ ] File names use shared stem (`tXXXX_short_name`) where applicable
- [ ] Building blocks + core rule documented together in wizard notes (if QRadar)
- [ ] Sources cited for intel-derived content (e.g. CISA)

## Reviewer notes (optional)
<!-- Anything you want a reviewer to focus on -->
