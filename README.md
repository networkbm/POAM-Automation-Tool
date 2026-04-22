# FedRAMP POA&M & VDR Automation Tool

A CLI tool that converts vulnerability scanner exports into a FedRAMP-compliant POA&M, manages the full finding lifecycle, generates FedRAMP 20x VDR reports, and produces per-release Product Vulnerability Disclosure Reports for customer-facing transparency.

---

## Setup

```bash
pip install openpyxl
```

---

## Files

| File | Purpose |
|---|---|
| `grc_tool.py` | Main CLI — use this for everything |
| `poam_converter.py` | Scanner parsing engine (used internally by grc_tool.py) |
| `sample_nessus.csv` | Sample Nessus export for testing |
| `sample_wiz.csv` | Sample Wiz export for testing |

---

## Supported Scanners

`nessus` · `tenable` · `qualys` · `wiz` · `generic`

---

## Commands

### convert
Import scanner findings into a POA&M. Duplicates are skipped automatically.

```bash
python3 grc_tool.py convert --input sample_nessus.csv --scanner nessus --output master_poam.xlsx
python3 grc_tool.py convert --input sample_wiz.csv --scanner wiz --output master_poam.xlsx
```

---

### dashboard
View a real-time health summary of your POA&M.

```bash
python3 grc_tool.py dashboard --poam master_poam.xlsx
```

---

### enrich
Auto-fill NIST 800-53 control mappings based on keywords. Only fills empty fields — never overwrites manual edits.

```bash
python3 grc_tool.py enrich --poam master_poam.xlsx

# With AI-generated remediation text (requires Ollama running locally)
python3 grc_tool.py enrich --poam master_poam.xlsx --ai
```

---

### close
Move a finding to the Closed sheet.

```bash
python3 grc_tool.py close --poam master_poam.xlsx --id POAM-0001 --method "Patched via Log4j upgrade to 2.15.0"
python3 grc_tool.py close --poam master_poam.xlsx --id POAM-0003 --method "Mitigated" --date 2026-04-15
```

---

### update
Update fields on an open finding. All fields are optional.

```bash
python3 grc_tool.py update --poam master_poam.xlsx --id POAM-0002 --milestone "Patch tested in staging" --poc "Bruce Wayne" --status "In Progress" --vendor-date 2026-04-10
```

---

### deviation
Mark a finding as a False Positive (`fp`) or Operational Requirement (`or`).

```bash
python3 grc_tool.py deviation --poam master_poam.xlsx --id POAM-0009 --type fp --rationale "HTTP TRACE disabled at load balancer; not exploitable"
python3 grc_tool.py deviation --poam master_poam.xlsx --id POAM-0010 --type or --rationale "Legacy system, compensating controls in place per SSP Section 13"
```

---

### report
Generate an Excel executive summary (severity counts, aging findings, breakdown by scanner).

```bash
python3 grc_tool.py report --poam master_poam.xlsx
python3 grc_tool.py report --poam master_poam.xlsx --output q2_report.xlsx
```

---

### conmon
Generate a monthly Continuous Monitoring report.

```bash
python3 grc_tool.py conmon --poam master_poam.xlsx
python3 grc_tool.py conmon --poam master_poam.xlsx --month 2026-04
python3 grc_tool.py conmon --poam master_poam.xlsx --month 2026-04 --output april_conmon.xlsx
```

---

### vdr
Generates a FedRAMP 20x VDR report from your existing POA&M. Produces two sheets — **Active Vulnerabilities (VDR-RPT-VDT)** and **Accepted Vulnerabilities (VDR-RPT-AVI)** — and outputs both Excel and JSON. The JSON can be served via any HTTP endpoint to satisfy the FedRAMP 20x API requirement.

- Live **CISA KEV** and **EPSS** lookups for accurate LEV/NLEV classification
- **N1–N5 adverse impact** auto-calculated and adjusted for KEV and IRV+LEV combinations
- **Evaluation deadlines** tracked per baseline — missed windows flagged as Overdue
- Findings open 192+ days are auto-moved to Accepted per VDR-TFR-MAV

```bash
python3 grc_tool.py vdr --poam master_poam.xlsx
python3 grc_tool.py vdr --poam master_poam.xlsx --baseline high --output vdr_submission.xlsx
```

Required update frequency by baseline: `low` = Monthly · `moderate` = Every 14 days · `high` = Weekly

Evaluation deadline window by baseline: `low` = 7 days · `moderate` = 5 days · `high` = 2 days from detection

---

### vdr-status
A quick daily health check that tells you what needs attention before you start your day. No files are generated — just a status output. Run this every morning.

Shows:
- CISA KEV findings requiring immediate action
- Findings that missed their evaluation deadline
- Remediation overdue count
- When your next VDR submission is due

```bash
python3 grc_tool.py vdr-status --poam master_poam.xlsx
python3 grc_tool.py vdr-status --poam master_poam.xlsx --baseline high
```

---

### product-vdr
Generate a per-release Product Vulnerability Disclosure Report — the format used by open source projects like curl to tell customers exactly what vulnerabilities exist in a given version of their software, which are fixed, and which are still open. This answers "Is this product safe to use today?"

Unlike the FedRAMP 20x VDR (which is a compliance report for FedRAMP reviewers), the Product VDR is customer-facing. You publish it alongside each release so downstream users can assess their exposure. Outputs Excel and JSON with live CISA KEV and EPSS enrichment on every CVE.

```bash
python3 grc_tool.py product-vdr --input vulns.csv --product "MyApp" --version "2.1.0"
python3 grc_tool.py product-vdr --input vulns.csv --product "MyApp" --version "2.1.0" --release-date 2026-04-22
```

---

### export — Submitting to an Assessor
Generate a clean, assessor-ready POA&M with only the two official FedRAMP sheets (Open and Closed POA&M Items). No internal report sheets.

```bash
python3 grc_tool.py export --poam master_poam.xlsx
python3 grc_tool.py export --poam master_poam.xlsx --output fedramp_poam_submission.xlsx
```

Hand the assessor the exported file. It follows the official FedRAMP POA&M template exactly.

---

## Daily Workflow

```bash
# 1. Morning check — CISA KEV, eval deadlines, next VDR due
python3 grc_tool.py vdr-status --poam master_poam.xlsx --baseline moderate

# 2. Import new scans
python3 grc_tool.py convert --input nessus_scan.csv --scanner nessus --output master_poam.xlsx
python3 grc_tool.py convert --input wiz_export.csv --scanner wiz --output master_poam.xlsx

# 3. Enrich with NIST controls
python3 grc_tool.py enrich --poam master_poam.xlsx

# 4. Check status
python3 grc_tool.py dashboard --poam master_poam.xlsx

# 5. Close a patched finding
python3 grc_tool.py close --poam master_poam.xlsx --id POAM-0003 --method "Patch applied"

# 6. Mark a false positive
python3 grc_tool.py deviation --poam master_poam.xlsx --id POAM-0007 --type fp --rationale "Not exploitable in this environment"

# 7. End of month — ConMon report
python3 grc_tool.py conmon --poam master_poam.xlsx --month 2026-04

# 8. Quarterly — executive summary
python3 grc_tool.py report --poam master_poam.xlsx --output q2_report.xlsx

# 9. FedRAMP 20x VDR submission
python3 grc_tool.py vdr --poam master_poam.xlsx --baseline moderate --output vdr_submission.xlsx

# 10. Traditional audit submission (Rev5 / POA&M)
python3 grc_tool.py export --poam master_poam.xlsx --output fedramp_submission.xlsx

# 11. On product release — publish a Product VDR alongside the release
python3 grc_tool.py product-vdr --input vulns.csv --product "MyApp" --version "2.1.0"
```

---

## Screenshots

![Screenshot 1](screenshots/Command-output.png)

## Notes

- POA&M IDs auto-increment across all scanners (`POAM-0001`, `POAM-0002`, ...)
- Duplicate findings (same title + asset) are skipped on import
- `--id` accepts `POAM-0001`, `0001`, or `1` interchangeably
- Severity color-coded: Critical (red), High (orange), Medium (yellow), Low (green)
