"""
grc_tool.py — FedRAMP GRC CLI tool for POA&M management.

Commands:
  convert    Import scanner findings into a master POA&M
  enrich     Add NIST 800-53 control mappings and AI remediation text
  close      Move a finding to the Closed sheet
  update     Update fields on an open finding
  deviation  Mark a finding as False Positive or Operational Requirement
  dashboard  Print a CLI status summary
  report     Generate an Excel executive summary report
  conmon     Generate a monthly Continuous Monitoring report

Usage examples:
  python3 grc_tool.py convert --input scan.csv --scanner nessus --output master_poam.xlsx
  python3 grc_tool.py enrich --poam master_poam.xlsx --ai
  python3 grc_tool.py dashboard --poam master_poam.xlsx
  python3 grc_tool.py close --poam master_poam.xlsx --id POAM-0003 --method "Patched"
  python3 grc_tool.py deviation --poam master_poam.xlsx --id POAM-0009 --type fp --rationale "Not exploitable"
  python3 grc_tool.py update --poam master_poam.xlsx --id POAM-0001 --milestone "Scheduled 2026-05-01" --poc "Jane Smith"
  python3 grc_tool.py conmon --poam master_poam.xlsx --month 2026-04
  python3 grc_tool.py report --poam master_poam.xlsx
"""

import argparse
import sys
from datetime import datetime, date, timedelta
from pathlib import Path
from collections import Counter, defaultdict

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

try:
    from poam_converter import (
        parse_nessus_csv, parse_nessus_xml,
        parse_tenable_csv, parse_qualys_csv,
        parse_wiz_csv, parse_generic_csv,
        build_poam_excel,
        POAM_COLUMNS,
        HEADER_FILL, HEADER_FONT, THIN_BORDER,
        SEVERITY_COLORS, _col_widths,
    )
except ImportError:
    print("ERROR: poam_converter.py not found. Make sure it is in the same directory.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Column index lookup — never hard-code column numbers
COL = {name: idx + 1 for idx, name in enumerate(POAM_COLUMNS)}

SCANNER_LABELS = {
    "nessus": "Nessus",
    "tenable": "Tenable.io",
    "qualys": "Qualys",
    "wiz": "Wiz",
    "generic": "Vulnerability Scanner",
}

# NIST 800-53 keyword → control mapping
# Each entry: (set_of_keywords, list_of_controls)
NIST_KEYWORD_MAP = [
    ({"cve-", "patch", "unpatched", "outdated", "end-of-life", "eol",
      "upgrade", "update required", "out of date"},
     ["SI-2", "RA-5"]),
    ({"remote code execution", "rce", "arbitrary code"},
     ["SI-2", "RA-5", "SI-3"]),
    ({"authentication bypass", "auth bypass", "unauthenticated",
      "unauthorized", "privilege escalation", "privilege", "sudo"},
     ["IA-2", "IA-5", "AC-3"]),
    ({"iam", "access key", "permission", "role", "policy", "least privilege",
      "overpermissive", "wildcard", "rbac"},
     ["AC-2", "AC-3", "AC-6"]),
    ({"mfa", "multi-factor", "two-factor", "2fa", "totp"},
     ["IA-2", "IA-5"]),
    ({"password", "credential", "default password", "weak password",
      "hardcoded", "cleartext password", "plaintext"},
     ["IA-5", "IA-6"]),
    ({"unencrypted", "encryption at rest", "not encrypted", "ebs",
      "disk encryption"},
     ["SC-28"]),
    ({"ssl", "tls", "weak cipher", "weak algorithm", "weak hash",
      "sha1", "md5", "cleartext", "plaintext traffic"},
     ["SC-8", "SC-23"]),
    ({"certificate", "cert", "expired cert", "self-signed"},
     ["SC-8", "IA-5"]),
    ({"security group", "firewall", "inbound", "unrestricted",
      "0.0.0.0", "open port", "exposed port", "network access"},
     ["SC-7", "AC-17"]),
    ({"ssh", "secure shell"},
     ["AC-17", "SC-8", "IA-2"]),
    ({"vpn", "remote access", "rdp", "remote desktop"},
     ["AC-17", "IA-2"]),
    ({"logging", "audit", "cloudtrail", "siem",
      "audit trail", "event log", "monitoring disabled"},
     ["AU-2", "AU-12"]),
    ({"log integrity", "log tamper", "log validation"},
     ["AU-9"]),
    ({"misconfiguration", "misconfigured", "default config",
      "hardening", "benchmark", "cis", "stig", "configuration"},
     ["CM-6", "CM-7"]),
    ({"unnecessary service", "unused service", "trace method",
      "expn", "debug enabled", "test endpoint"},
     ["CM-7"]),
    ({"supply chain", "third-party", "dependency", "library",
      "component", "npm", "pip", "maven"},
     ["SA-12", "SI-7"]),
    ({"malware", "antivirus", "anti-virus", "endpoint protection"},
     ["SI-3"]),
    ({"container", "docker", "kubernetes", "k8s", "pod",
      "running as root", "privileged container"},
     ["CM-6", "CM-7", "AC-6"]),
    ({"s3", "bucket", "blob storage", "object storage", "public bucket",
      "storage account"},
     ["AC-3", "SC-28", "AC-6"]),
    ({"secret", "api key", "token", "private key", "key rotation",
      "secrets manager", "vault"},
     ["SC-12", "IA-5"]),
    ({"sql injection", "sqli", "xss", "cross-site", "injection",
      "input validation", "command injection"},
     ["SI-10", "SI-3"]),
    ({"file disclosure", "directory traversal", "path traversal",
      "arbitrary file read", "lfi", "rfi"},
     ["AC-3", "SI-10"]),
    ({"backup", "recovery", "restore", "disaster recovery"},
     ["CP-9", "CP-10"]),
    ({"ntp", "time sync", "clock"},
     ["AU-8"]),
    ({"dns", "domain hijack", "subdomain takeover"},
     ["SC-20", "SC-21"]),
    ({"denial of service", "ddos", "resource exhaustion"},
     ["SC-5"]),
    ({"asset inventory", "unmanaged asset", "rogue device"},
     ["CM-8"]),
    ({"smb", "print spooler", "printnightmare", "smbghost"},
     ["CM-6", "SI-2"]),
]


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def load_poam(path):
    p = Path(path)
    if not p.exists():
        print(f"ERROR: POA&M file not found: {path}")
        sys.exit(1)
    wb = openpyxl.load_workbook(path)
    if "Open POA&M Items" not in wb.sheetnames:
        print(f"ERROR: Sheet 'Open POA&M Items' not found in {path}")
        sys.exit(1)
    if "Closed POA&M Items" not in wb.sheetnames:
        print(f"ERROR: Sheet 'Closed POA&M Items' not found in {path}")
        sys.exit(1)
    return wb, wb["Open POA&M Items"], wb["Closed POA&M Items"]


def save_poam(wb, path):
    try:
        wb.save(path)
    except PermissionError:
        print(f"ERROR: Cannot save — is {path} open in Excel? Close it and try again.")
        sys.exit(1)


def get_all_rows(ws):
    rows = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not any(row):
            continue
        rows.append(dict(zip(POAM_COLUMNS, row)))
    return rows


def find_row_by_id(ws, poam_id):
    target = poam_id.upper().strip()
    for row_num in range(2, ws.max_row + 1):
        val = ws.cell(row=row_num, column=COL["POA&M ID"]).value
        if val and str(val).upper().strip() == target:
            row_dict = {}
            for col_name in POAM_COLUMNS:
                row_dict[col_name] = ws.cell(row=row_num, column=COL[col_name]).value
            return row_num, row_dict
    return None, None


def normalize_id(raw_id):
    """Accept POAM-0001, 0001, or 1 — always return POAM-XXXX format."""
    raw = raw_id.strip().upper()
    if raw.startswith("POAM-"):
        return raw
    try:
        return f"POAM-{int(raw):04d}"
    except ValueError:
        return raw


def map_controls(title, description, cve):
    text = f"{title} {description} {cve}".lower()
    controls = []
    for keywords, ctrl_list in NIST_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            controls.extend(ctrl_list)
    # Always add SI-2/RA-5 if there's a CVE
    if cve and cve.upper().startswith("CVE-"):
        controls.extend(["SI-2", "RA-5"])
    return ", ".join(sorted(set(controls))) if controls else ""


def parse_date(val):
    """Parse a date value from openpyxl (string or datetime)."""
    if val is None:
        return None
    if isinstance(val, (datetime, date)):
        return val.date() if isinstance(val, datetime) else val
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%m-%d-%Y"):
        try:
            return datetime.strptime(str(val).strip(), fmt).date()
        except ValueError:
            continue
    return None


def is_overdue(date_val):
    d = parse_date(date_val)
    if d is None:
        return False
    return d < date.today()


def days_overdue(date_val):
    d = parse_date(date_val)
    if d is None:
        return 0
    delta = (date.today() - d).days
    return max(delta, 0)


def call_ollama(prompt):
    try:
        import requests
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "mistral", "prompt": prompt, "stream": False},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception:
        return None


def apply_row_style(ws, row_num, severity):
    color = SEVERITY_COLORS.get(severity, "FFFFFF")
    sev_fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
    for col_idx in range(1, len(POAM_COLUMNS) + 1):
        cell = ws.cell(row=row_num, column=col_idx)
        cell.border = THIN_BORDER
        cell.alignment = Alignment(vertical="top", wrap_text=True)
        if POAM_COLUMNS[col_idx - 1] in ("Original Risk Rating", "Adjusted Risk Rating"):
            cell.fill = sev_fill
            cell.font = Font(bold=True, name="Calibri", size=10)


# ---------------------------------------------------------------------------
# Subcommand: convert
# ---------------------------------------------------------------------------

def cmd_convert(args):
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    print(f"Parsing {args.scanner} export: {args.input}")

    if args.scanner == "nessus":
        if input_path.suffix.lower() in (".xml", ".nessus"):
            findings = parse_nessus_xml(args.input)
        else:
            findings = parse_nessus_csv(args.input)
    elif args.scanner == "tenable":
        findings = parse_tenable_csv(args.input)
    elif args.scanner == "qualys":
        findings = parse_qualys_csv(args.input)
    elif args.scanner == "wiz":
        findings = parse_wiz_csv(args.input)
    else:
        findings = parse_generic_csv(args.input)

    if not findings:
        print("No findings found (or all were informational). Check your input file.")
        sys.exit(0)

    print(f"Found {len(findings)} findings to add to POA&M.")
    build_poam_excel(findings, SCANNER_LABELS[args.scanner], args.output)


# ---------------------------------------------------------------------------
# Subcommand: enrich
# ---------------------------------------------------------------------------

def cmd_enrich(args):
    wb, ws_open, _ = load_poam(args.poam)
    today_str = date.today().strftime("%Y-%m-%d")

    controls_added = 0
    ai_enriched = 0
    skipped_controls = 0
    skipped_ai = 0
    ollama_unavailable = False

    print(f"Enriching {args.poam}...")
    if args.ai:
        print("AI mode enabled — connecting to Ollama/Mistral...")

    for row_num in range(2, ws_open.max_row + 1):
        poam_id = ws_open.cell(row=row_num, column=COL["POA&M ID"]).value
        if not poam_id:
            continue

        title = ws_open.cell(row=row_num, column=COL["Weakness Name"]).value or ""
        desc = ws_open.cell(row=row_num, column=COL["Weakness Description"]).value or ""
        cve = ws_open.cell(row=row_num, column=COL["CVE"]).value or ""
        existing_controls = ws_open.cell(row=row_num, column=COL["Controls"]).value

        # NIST control mapping — only if currently empty
        if not existing_controls:
            mapped = map_controls(title, desc, cve)
            if mapped:
                ws_open.cell(row=row_num, column=COL["Controls"]).value = mapped
                controls_added += 1
        else:
            skipped_controls += 1

        # AI remediation — only if --ai flag and currently empty
        if args.ai and not ollama_unavailable:
            existing_remediation = ws_open.cell(row=row_num, column=COL["Overall Remediation Plan"]).value
            if not existing_remediation:
                prompt = (
                    f"You are a FedRAMP GRC analyst. Write a 2-3 sentence remediation plan "
                    f"for the following vulnerability finding. Be specific and actionable.\n\n"
                    f"Finding: {title}\n"
                    f"Description: {desc}\n"
                    f"CVE: {cve if cve else 'N/A'}\n\n"
                    f"Remediation Plan:"
                )
                result = call_ollama(prompt)
                if result is None:
                    print("[AI] Ollama not available — skipping AI enrichment for remaining findings.")
                    ollama_unavailable = True
                else:
                    ws_open.cell(row=row_num, column=COL["Overall Remediation Plan"]).value = result
                    ai_enriched += 1
            else:
                skipped_ai += 1

    save_poam(wb, args.poam)
    print(f"\nEnrichment complete:")
    print(f"  NIST controls added:     {controls_added}")
    print(f"  NIST controls skipped (already set): {skipped_controls}")
    if args.ai:
        print(f"  AI remediation added:    {ai_enriched}")
        print(f"  AI remediation skipped (already set): {skipped_ai}")


# ---------------------------------------------------------------------------
# Subcommand: close
# ---------------------------------------------------------------------------

def cmd_close(args):
    poam_id = normalize_id(args.poam_id)
    wb, ws_open, ws_closed = load_poam(args.poam)

    row_num, row_dict = find_row_by_id(ws_open, poam_id)
    if row_num is None:
        print(f"ERROR: Finding '{poam_id}' not found in Open POA&M Items.")
        sys.exit(1)

    severity = row_dict.get("Original Risk Rating", "")
    closure_note = f"Closed: {args.method} on {args.close_date}"

    # Find next empty row in closed sheet
    closed_row = ws_closed.max_row + 1
    # If sheet is empty except header, start at row 2
    if closed_row == 1:
        closed_row = 2

    # Copy all values to closed sheet
    for col_name in POAM_COLUMNS:
        val = row_dict.get(col_name, "")
        ws_closed.cell(row=closed_row, column=COL[col_name]).value = val

    # Update closure fields
    ws_closed.cell(row=closed_row, column=COL["Status Date"]).value = args.close_date
    ws_closed.cell(row=closed_row, column=COL["Comments"]).value = closure_note

    # Apply styling to closed row
    apply_row_style(ws_closed, closed_row, severity)

    # Delete from open sheet
    ws_open.delete_rows(row_num)

    save_poam(wb, args.poam)
    print(f"Finding {poam_id} moved to Closed POA&M Items.")
    print(f"  Method: {args.method}")
    print(f"  Date:   {args.close_date}")


# ---------------------------------------------------------------------------
# Subcommand: update
# ---------------------------------------------------------------------------

def cmd_update(args):
    poam_id = normalize_id(args.poam_id)
    wb, ws_open, _ = load_poam(args.poam)

    row_num, row_dict = find_row_by_id(ws_open, poam_id)
    if row_num is None:
        print(f"ERROR: Finding '{poam_id}' not found in Open POA&M Items.")
        sys.exit(1)

    updated = []
    today_str = date.today().strftime("%Y-%m-%d")

    if args.milestone:
        ws_open.cell(row=row_num, column=COL["Milestone Changes"]).value = args.milestone
        updated.append(f"Milestone Changes = {args.milestone}")

    if args.poc:
        ws_open.cell(row=row_num, column=COL["Point of Contact"]).value = args.poc
        updated.append(f"Point of Contact = {args.poc}")

    if args.vendor_date:
        ws_open.cell(row=row_num, column=COL["Last Vendor Check-in Date"]).value = args.vendor_date
        updated.append(f"Last Vendor Check-in Date = {args.vendor_date}")

    if args.status:
        # Status text goes into Comments with a prefix tag
        existing = ws_open.cell(row=row_num, column=COL["Comments"]).value or ""
        status_entry = f"[STATUS {today_str}: {args.status}]"
        ws_open.cell(row=row_num, column=COL["Comments"]).value = f"{status_entry} {existing}".strip()
        updated.append(f"Status = {args.status}")

    # Always update Status Date
    ws_open.cell(row=row_num, column=COL["Status Date"]).value = today_str

    save_poam(wb, args.poam)

    if updated:
        print(f"Updated {poam_id}:")
        for u in updated:
            print(f"  {u}")
    else:
        print(f"No fields specified to update for {poam_id}. Use --milestone, --poc, --vendor-date, or --status.")


# ---------------------------------------------------------------------------
# Subcommand: deviation
# ---------------------------------------------------------------------------

def cmd_deviation(args):
    poam_id = normalize_id(args.poam_id)
    wb, ws_open, _ = load_poam(args.poam)

    row_num, row_dict = find_row_by_id(ws_open, poam_id)
    if row_num is None:
        print(f"ERROR: Finding '{poam_id}' not found in Open POA&M Items.")
        sys.exit(1)

    today_str = date.today().strftime("%Y-%m-%d")

    if args.dev_type == "fp":
        ws_open.cell(row=row_num, column=COL["False Positive"]).value = "Yes"
        ws_open.cell(row=row_num, column=COL["Operational Requirement"]).value = ""
        label = "False Positive"
    else:
        ws_open.cell(row=row_num, column=COL["Operational Requirement"]).value = "Yes"
        ws_open.cell(row=row_num, column=COL["False Positive"]).value = ""
        label = "Operational Requirement"

    ws_open.cell(row=row_num, column=COL["Deviation Rationale"]).value = args.rationale
    ws_open.cell(row=row_num, column=COL["Status Date"]).value = today_str

    save_poam(wb, args.poam)
    print(f"Finding {poam_id} marked as {label}.")
    print(f"  Rationale: {args.rationale}")


# ---------------------------------------------------------------------------
# Subcommand: dashboard
# ---------------------------------------------------------------------------

def cmd_dashboard(args):
    wb, ws_open, ws_closed = load_poam(args.poam)
    open_rows = get_all_rows(ws_open)
    closed_rows = get_all_rows(ws_closed)

    today = date.today()
    overdue = [r for r in open_rows if is_overdue(r.get("Scheduled Completion Date"))]
    due_this_month = [
        r for r in open_rows
        if not is_overdue(r.get("Scheduled Completion Date")) and
        (d := parse_date(r.get("Scheduled Completion Date"))) and
        d.year == today.year and d.month == today.month
    ]

    sev_counts = Counter(r.get("Original Risk Rating", "Unknown") for r in open_rows)

    # Top 5 oldest open findings
    dated = [(r, parse_date(r.get("Original Detection Date"))) for r in open_rows]
    dated = [(r, d) for r, d in dated if d is not None]
    dated.sort(key=lambda x: x[1])
    top5 = dated[:5]

    w = 62
    print("=" * w)
    print(f"  GRC DASHBOARD — {Path(args.poam).name}")
    print(f"  Generated: {today.strftime('%Y-%m-%d')}")
    print("=" * w)
    print(f"  {'OPEN ITEMS:':<22}{len(open_rows):<10}{'CLOSED ITEMS:':<18}{len(closed_rows)}")
    print(f"  {'OVERDUE:':<22}{len(overdue):<10}{'DUE THIS MONTH:':<18}{len(due_this_month)}")
    print("-" * w)
    print("  SEVERITY BREAKDOWN (Open)")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sev_counts.get(sev, 0)
        bar = "#" * count
        print(f"    {sev:<12} {count:>4}  {bar}")
    print("-" * w)
    print("  TOP 5 OLDEST OPEN FINDINGS")
    if top5:
        for i, (r, d) in enumerate(top5, 1):
            poam_id = r.get("POA&M ID", "?")
            sev = r.get("Original Risk Rating", "?")
            name = (r.get("Weakness Name") or "")[:38]
            scheduled = r.get("Scheduled Completion Date")
            overdue_days = days_overdue(scheduled)
            overdue_str = f"({overdue_days}d overdue)" if overdue_days > 0 else "(on track)"
            print(f"    {i}. {poam_id}  [{sev:<8}]  {name:<40} {overdue_str}")
    else:
        print("    No open findings.")
    print("=" * w)


# ---------------------------------------------------------------------------
# Subcommand: report
# ---------------------------------------------------------------------------

def cmd_report(args):
    wb_src, ws_open, ws_closed = load_poam(args.poam)
    open_rows = get_all_rows(ws_open)
    closed_rows = get_all_rows(ws_closed)

    today = date.today()
    output = args.output or f"grc_report_{today.strftime('%Y%m%d')}.xlsx"

    wb = openpyxl.Workbook()
    col_widths = _col_widths()

    # ---- Sheet 1: Summary ----
    ws_sum = wb.active
    ws_sum.title = "Summary"

    def hcell(ws, row, col, value):
        cell = ws.cell(row=row, column=col, value=value)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = THIN_BORDER
        return cell

    def dcell(ws, row, col, value, bold=False, fill_color=None):
        cell = ws.cell(row=row, column=col, value=value)
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = THIN_BORDER
        if bold:
            cell.font = Font(bold=True, name="Calibri", size=11)
        if fill_color:
            cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
        return cell

    # Summary header
    ws_sum.row_dimensions[1].height = 24
    for col, header in enumerate(["Severity", "Open", "Closed", "Total"], start=1):
        hcell(ws_sum, 1, col, header)
        ws_sum.column_dimensions[get_column_letter(col)].width = 18

    open_sev = Counter(r.get("Original Risk Rating", "Unknown") for r in open_rows)
    closed_sev = Counter(r.get("Original Risk Rating", "Unknown") for r in closed_rows)

    row = 2
    for sev in ["Critical", "High", "Medium", "Low"]:
        color = SEVERITY_COLORS.get(sev, "FFFFFF")
        dcell(ws_sum, row, 1, sev, fill_color=color)
        dcell(ws_sum, row, 2, open_sev.get(sev, 0))
        dcell(ws_sum, row, 3, closed_sev.get(sev, 0))
        dcell(ws_sum, row, 4, open_sev.get(sev, 0) + closed_sev.get(sev, 0))
        row += 1

    # Totals row
    dcell(ws_sum, row, 1, "TOTAL", bold=True)
    dcell(ws_sum, row, 2, len(open_rows), bold=True)
    dcell(ws_sum, row, 3, len(closed_rows), bold=True)
    dcell(ws_sum, row, 4, len(open_rows) + len(closed_rows), bold=True)
    row += 2

    # Overdue stats
    overdue_count = sum(1 for r in open_rows if is_overdue(r.get("Scheduled Completion Date")))
    overdue_pct = round(overdue_count / len(open_rows) * 100, 1) if open_rows else 0
    ws_sum.cell(row=row, column=1, value="Overdue Findings").font = Font(bold=True, name="Calibri")
    ws_sum.cell(row=row, column=2, value=overdue_count)
    ws_sum.cell(row=row, column=3, value=f"{overdue_pct}% of open")

    # ---- Sheet 2: Aging ----
    ws_age = wb.create_sheet("Aging")
    age_headers = ["POA&M ID", "Weakness Name", "Asset Identifier", "Original Risk Rating",
                   "Original Detection Date", "Scheduled Completion Date", "Days Overdue"]
    for col, h in enumerate(age_headers, start=1):
        cell = hcell(ws_age, 1, col, h)
        ws_age.column_dimensions[get_column_letter(col)].width = [12, 40, 20, 18, 20, 22, 14][col - 1]
    ws_age.row_dimensions[1].height = 24
    ws_age.freeze_panes = "A2"

    aging_data = [
        (r, days_overdue(r.get("Scheduled Completion Date")))
        for r in open_rows
    ]
    aging_data.sort(key=lambda x: x[1], reverse=True)

    for row_idx, (r, d_over) in enumerate(aging_data, start=2):
        vals = [
            r.get("POA&M ID"), r.get("Weakness Name"), r.get("Asset Identifier"),
            r.get("Original Risk Rating"), r.get("Original Detection Date"),
            r.get("Scheduled Completion Date"), d_over
        ]
        for col, val in enumerate(vals, start=1):
            cell = ws_age.cell(row=row_idx, column=col, value=val)
            cell.border = THIN_BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        # Color days overdue
        d_cell = ws_age.cell(row=row_idx, column=7)
        if d_over > 90:
            d_cell.fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
            d_cell.font = Font(bold=True, color="FFFFFF")
        elif d_over > 30:
            d_cell.fill = PatternFill(start_color="FF6600", end_color="FF6600", fill_type="solid")
        elif d_over > 0:
            d_cell.fill = PatternFill(start_color="FFCC00", end_color="FFCC00", fill_type="solid")
        else:
            d_cell.fill = PatternFill(start_color="00CC00", end_color="00CC00", fill_type="solid")

    # ---- Sheet 3: By Scanner ----
    ws_scan = wb.create_sheet("By Scanner")
    scan_headers = ["Scanner", "POA&M ID", "Weakness Name", "Original Risk Rating", "Scheduled Completion Date"]
    for col, h in enumerate(scan_headers, start=1):
        hcell(ws_scan, 1, col, h)
        ws_scan.column_dimensions[get_column_letter(col)].width = [20, 12, 45, 18, 22][col - 1]
    ws_scan.row_dimensions[1].height = 24
    ws_scan.freeze_panes = "A2"

    # Sort by scanner then severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    scanner_rows = sorted(
        open_rows,
        key=lambda r: (
            r.get("Weakness Detector Source", ""),
            sev_order.get(r.get("Original Risk Rating", ""), 99)
        )
    )

    for row_idx, r in enumerate(scanner_rows, start=2):
        for col, key in enumerate(["Weakness Detector Source", "POA&M ID", "Weakness Name",
                                    "Original Risk Rating", "Scheduled Completion Date"], start=1):
            cell = ws_scan.cell(row=row_idx, column=col, value=r.get(key, ""))
            cell.border = THIN_BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    try:
        wb.save(output)
        print(f"Executive report saved to: {output}")
        print(f"  Open findings:   {len(open_rows)}")
        print(f"  Closed findings: {len(closed_rows)}")
        print(f"  Overdue:         {overdue_count}")
    except PermissionError:
        print(f"ERROR: Cannot save — is {output} open in Excel?")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand: conmon
# ---------------------------------------------------------------------------

def cmd_conmon(args):
    wb_src, ws_open, ws_closed = load_poam(args.poam)
    open_rows = get_all_rows(ws_open)
    closed_rows = get_all_rows(ws_closed)

    today = date.today()
    if args.month:
        try:
            year, month = args.month.strip().split("-")
            year, month = int(year), int(month)
        except ValueError:
            print("ERROR: --month must be in format YYYY-MM (e.g. 2026-04)")
            sys.exit(1)
    else:
        year, month = today.year, today.month

    month_prefix = f"{year}-{month:02d}"
    output = args.output or f"conmon_{year}_{month:02d}.xlsx"

    def in_month(date_val):
        if date_val is None:
            return False
        return str(date_val).startswith(month_prefix)

    opened = [r for r in open_rows if in_month(r.get("Original Detection Date"))]
    closed = [r for r in closed_rows if in_month(r.get("Status Date"))]

    wb = openpyxl.Workbook()
    col_widths = _col_widths()

    def build_sheet(ws, title_text, rows):
        ws.title = title_text
        # Cover row
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(POAM_COLUMNS))
        cover = ws.cell(row=1, column=1,
                        value=f"ConMon Report — Month: {month_prefix} | Generated: {today} | System: {Path(args.poam).name}")
        cover.font = Font(bold=True, name="Calibri", size=11)
        cover.fill = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
        cover.font = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
        cover.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 24

        # Header row
        for col_idx, col_name in enumerate(POAM_COLUMNS, start=1):
            cell = ws.cell(row=2, column=col_idx, value=col_name)
            cell.fill = HEADER_FILL
            cell.font = HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = THIN_BORDER
            ws.column_dimensions[get_column_letter(col_idx)].width = col_widths.get(col_name, 15)
        ws.row_dimensions[2].height = 30
        ws.freeze_panes = "A3"

        for row_idx, r in enumerate(rows, start=3):
            sev = r.get("Original Risk Rating", "")
            color = SEVERITY_COLORS.get(sev, "FFFFFF")
            sev_fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
            for col_idx, col_name in enumerate(POAM_COLUMNS, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=r.get(col_name, ""))
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                if col_name in ("Original Risk Rating", "Adjusted Risk Rating"):
                    cell.fill = sev_fill
                    cell.font = Font(bold=True, name="Calibri", size=10)

    ws_opened = wb.active
    build_sheet(ws_opened, "Opened This Month", opened)
    ws_closed_sheet = wb.create_sheet("Closed This Month")
    build_sheet(ws_closed_sheet, "Closed This Month", closed)

    try:
        wb.save(output)
        print(f"ConMon report saved to: {output}")
        print(f"  Month:          {month_prefix}")
        print(f"  Opened:         {len(opened)}")
        print(f"  Closed:         {len(closed)}")
    except PermissionError:
        print(f"ERROR: Cannot save — is {output} open in Excel?")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand: export
# ---------------------------------------------------------------------------

def cmd_export(args):
    wb_src, ws_open, ws_closed = load_poam(args.poam)
    today = date.today()
    output = args.output or f"fedramp_poam_{today.strftime('%Y%m%d')}.xlsx"
    col_widths = _col_widths()

    wb = openpyxl.Workbook()

    def copy_sheet(ws_src, ws_dst):
        # Header row
        for col_idx, col_name in enumerate(POAM_COLUMNS, start=1):
            cell = ws_dst.cell(row=1, column=col_idx, value=col_name)
            cell.fill = HEADER_FILL
            cell.font = HEADER_FONT
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = THIN_BORDER
            ws_dst.column_dimensions[get_column_letter(col_idx)].width = col_widths.get(col_name, 15)
        ws_dst.row_dimensions[1].height = 30
        ws_dst.freeze_panes = "A2"

        # Data rows
        dst_row = 2
        for src_row in range(2, ws_src.max_row + 1):
            if not any(ws_src.cell(row=src_row, column=c).value for c in range(1, len(POAM_COLUMNS) + 1)):
                continue
            sev = ws_src.cell(row=src_row, column=COL["Original Risk Rating"]).value or ""
            color = SEVERITY_COLORS.get(sev, "FFFFFF")
            sev_fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
            for col_idx, col_name in enumerate(POAM_COLUMNS, start=1):
                val = ws_src.cell(row=src_row, column=col_idx).value
                cell = ws_dst.cell(row=dst_row, column=col_idx, value=val)
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                if col_name in ("Original Risk Rating", "Adjusted Risk Rating"):
                    cell.fill = sev_fill
                    cell.font = Font(bold=True, name="Calibri", size=10)
            dst_row += 1

    ws_open_dst = wb.active
    ws_open_dst.title = "Open POA&M Items"
    copy_sheet(ws_open, ws_open_dst)

    ws_closed_dst = wb.create_sheet("Closed POA&M Items")
    copy_sheet(ws_closed, ws_closed_dst)

    try:
        wb.save(output)
        open_count = ws_open_dst.max_row - 1
        closed_count = ws_closed_dst.max_row - 1
        print(f"FedRAMP POA&M export saved to: {output}")
        print(f"  Open findings:   {open_count}")
        print(f"  Closed findings: {closed_count}")
    except PermissionError:
        print(f"ERROR: Cannot save — is {output} open in Excel?")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parser + main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="grc_tool",
        description="FedRAMP GRC CLI — POA&M management tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # convert
    p_conv = sub.add_parser("convert", help="Import scanner findings into POA&M")
    p_conv.add_argument("--input", required=True, help="Scanner export file path")
    p_conv.add_argument("--scanner", required=True,
                        choices=["nessus", "tenable", "qualys", "wiz", "generic"])
    p_conv.add_argument("--output", default="poam_output.xlsx", help="Output POA&M file")

    # enrich
    p_enrich = sub.add_parser("enrich", help="Add NIST 800-53 mappings and AI remediation")
    p_enrich.add_argument("--poam", required=True, help="Path to master POA&M file")
    p_enrich.add_argument("--ai", action="store_true",
                          help="Use Ollama/Mistral to generate remediation text")

    # close
    p_close = sub.add_parser("close", help="Move a finding to Closed sheet")
    p_close.add_argument("--poam", required=True)
    p_close.add_argument("--id", required=True, dest="poam_id", help="POA&M ID (e.g. POAM-0003)")
    p_close.add_argument("--date", default=date.today().strftime("%Y-%m-%d"), dest="close_date")
    p_close.add_argument("--method", default="Remediated", help="Closure method description")

    # update
    p_update = sub.add_parser("update", help="Update fields on an open finding")
    p_update.add_argument("--poam", required=True)
    p_update.add_argument("--id", required=True, dest="poam_id")
    p_update.add_argument("--milestone", default=None, help="Milestone notes")
    p_update.add_argument("--poc", default=None, help="Point of Contact name")
    p_update.add_argument("--vendor-date", default=None, dest="vendor_date",
                          help="Last vendor check-in date (YYYY-MM-DD)")
    p_update.add_argument("--status", default=None, help="Status text (appended to Comments)")

    # deviation
    p_dev = sub.add_parser("deviation", help="Mark finding as False Positive or Operational Requirement")
    p_dev.add_argument("--poam", required=True)
    p_dev.add_argument("--id", required=True, dest="poam_id")
    p_dev.add_argument("--type", required=True, choices=["fp", "or"], dest="dev_type",
                       help="fp = False Positive, or = Operational Requirement")
    p_dev.add_argument("--rationale", required=True, help="Written justification")

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Print CLI health dashboard")
    p_dash.add_argument("--poam", required=True)

    # report
    p_report = sub.add_parser("report", help="Generate Excel executive summary")
    p_report.add_argument("--poam", required=True)
    p_report.add_argument("--output", default=None, help="Output file (default: grc_report_YYYYMMDD.xlsx)")

    # conmon
    p_conmon = sub.add_parser("conmon", help="Generate monthly ConMon report")
    p_conmon.add_argument("--poam", required=True)
    p_conmon.add_argument("--month", default=None, help="Month in YYYY-MM format (default: current month)")
    p_conmon.add_argument("--output", default=None, help="Output file (default: conmon_YYYY_MM.xlsx)")

    # export
    p_export = sub.add_parser("export", help="Export clean FedRAMP POA&M for assessor submission")
    p_export.add_argument("--poam", required=True)
    p_export.add_argument("--output", default=None, help="Output file (default: fedramp_poam_YYYYMMDD.xlsx)")

    args = parser.parse_args()

    dispatch = {
        "convert": cmd_convert,
        "enrich": cmd_enrich,
        "close": cmd_close,
        "update": cmd_update,
        "deviation": cmd_deviation,
        "dashboard": cmd_dashboard,
        "report": cmd_report,
        "conmon": cmd_conmon,
        "export": cmd_export,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
