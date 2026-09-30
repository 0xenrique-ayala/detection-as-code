# Detection-as-code workflow

## Publish model
- Content on `main` is the public published set.
- Prefer branch → pull request → merge for new detections (process practice).
- This repo does **not** auto-deploy to any SIEM.

## Layout
- Standalone detections: `detections/`
- Campaign kits: `packs/`
- ATT&CK index: `detections/meta/ATTACK_COVERAGE.md`

## Lab use
Example Sigma / QRadar / Splunk content is for adaptation. Validate data sources, fields, and thresholds in your environment before enablement.
