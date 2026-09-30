# BRICKSTORM pack

Public intel pack: example detections and supporting artifacts for **BRICKSTORM** backdoor activity, organized for lab use and adaptation.

This is **packaged detection content**, not a live hunt playbook.  
**No client data.** Validate data sources, fields, and thresholds in your environment before production use.

---

## Sources

Primary public reporting (CISA / partners):

| Reference | Link |
|---|---|
| CISA analysis report **AR25-338A** — BRICKSTORM Backdoor | https://www.cisa.gov/news-events/analysis-reports/ar25-338a |
| Related MAR / IOC packages (examples cited in public reporting) | MAR-251165, MAR-251217 / MAR-2512217, MAR-261234 (see CISA page for current downloads) |

CISA, NSA, and the Canadian Centre for Cyber Security have published analysis, IOCs, and detection signatures for BRICKSTORM (Go/Rust ELF backdoor used for long-term persistence, including activity relevant to virtualization and related environments).

This pack is **not** a CISA product and is **not** affiliated with CISA, NSA, or Cyber Centre.

---

## What’s in this pack

| Path | Contents |
|---|---|
| `iocs/` | Public IOC lists (e.g. hashes, DoH-related indicators) derived from open reporting |
| `yara/` | YARA rules (including CISA-style rules where applicable) |
| `sigma/` | Portable Sigma content |
| `qradar/aql/` | Example AQL searches |
| `qradar/wizard/` | Example QRadar Rule Wizard notes |
| `splunk/spl/` | Example SPL |
| `scripts/` | Helper scripts (lab) |
| `reports/` | Public analysis PDF(s) |
| `cronjobs/` | Optional scheduling helpers |

Exact filenames may vary; browse the folders for current content.

---

## How this content was produced

- Derived from **public** CISA (and partner) reporting and published IOCs/signatures.
- Some detection text (AQL, wizard notes, SPL) was **drafted with AI assistance**, then human-reviewed and organized into this repo layout.
- Example queries and rules are for **lab / adaptation**. They may need field mapping, allowlists, and threshold changes for any real environment.
- Not production-validated as a complete enterprise detection program.

---

## Suggested use

1. Read the CISA report for behavior, scope, and official guidance.
2. Prefer **behavioral** ideas over brittle single IOCs where possible.
3. Map example AQL/SPL/wizard steps to **your** log sources and property names.
4. Baseline in a non-production or tuned mode before enabling high-severity actions.
5. Report real BRICKSTORM or related activity to CISA / appropriate authorities as required.

---

## ATT&CK

Multi-technique pack (persistence, C2-style communications, web shell–like activity, DoH-related signals, etc.).  
See individual Sigma/rules and the root coverage index:

- `detections/meta/ATTACK_COVERAGE.md` (pack row)

Detailed technique mapping may be incomplete; improve per-rule metadata as content matures.

---

## License & attribution

- Repo license: [MIT](../../LICENSE) for **original packaging** in this repository.
- Public intel (CISA MARs, YARA, official IOCs) remains subject to **source terms** — always **cite CISA** (and partners) when redistributing or deriving.
- Provided **as-is**; no warranty.

---

## Related

- Repo workflow: `docs/DAC_WORKFLOW.md`
- PR template: `.github/pull_request_template.md`
