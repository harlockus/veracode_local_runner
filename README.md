# Veracode Local Runner

A **customer-ready, read-only exporter** for Veracode AppSec data.  
Generates an Excel workbook from Veracode REST APIs with:

- **Apps** — application metadata (incl. custom fields `cf_Custom_1 … cf_Custom_25`)
- **Summaries** — derived from Reporting API: open findings by severity **5 → 0**, plus `last_scan_*` per analysis type
- **FrequencyCompliance** — policy frequency requirements, computed next due date, and status (IN_COMPLIANCE / PAST_DUE / UNKNOWN)
- **ReportingAPI** — full analytics rows, spanning 6-month windows (POST → POLL → GET with HAL pagination)
- **OpenFlawsSummary** — pivot table (sev **5..0** × STATIC/DYNAMIC/SCA/MPT + Total) and labeled, color-coded bar charts

✨ Polished **Rich UI** (`--pretty`) shows professional progress (pages, apps found, apps/sec).  
Silent mode (`--quiet`) suppresses progress and debug output.

---

## Requirements

- Python **3.9+**  
- Veracode **API ID/Key** (HMAC credentials)  
- Network access to `api.veracode.com` (US) or `api.veracode.eu` (EU)

### Install locally

```bash
python3 -m venv venv
source venv/bin/activate          # On Windows: venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt

Environment Setup

Create a .env file (never commit it). Example:
# Region (default is US)
VERACODE_BASE=https://api.veracode.com

# Veracode HMAC credentials
VERACODE_API_KEY_ID=vc_xxxxxxxxxxxxxx
VERACODE_API_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Optional tuning
PAGE_SLEEP=0.0
VERACODE_DEBUG=0
VERACODE_REPORTING_POLL_DELAY=3.0
VERACODE_REPORTING_POLL_TRIES=60

For EU tenants, set VERACODE_BASE=https://api.veracode.eu

Usage

Run the script with one of three modes:

1. Full export (Apps + Summaries + Compliance + Reporting + Charts)
python3 veracode_local_runner.py tenant-all-in-one \
  --reporting-start 2022-01-01 \
  --reporting-page-size 600 \
  --reporting-poll-delay 3.0 \
  --reporting-poll-tries 60 \
  --limit-apps 10000 \
  --page-size 200 \
  --sleep 0.05 \
  --pretty \
  --out tenant_all_in_one.xlsx

Smoke test (faster, small sample):
python3 veracode_local_runner.py tenant-all-in-one \
  --reporting-start 2024-01-01 \
  --reporting-page-size 600 \
  --reporting-poll-delay 2.0 \
  --reporting-poll-tries 30 \
  --limit-apps 100 \
  --page-size 200 \
  --sleep 0 \
  --pretty \
  --out tenant_all_in_one_smoke.xlsx

2. Frequency compliance only (per application)
python3 veracode_local_runner.py scan-compliance \
  --app <APPLICATION_GUID> \
  --out app_compliance.xlsx \
  --pretty

Produces two sheets: App, Compliance.

3. Frequency compliance only (entire tenant)
python3 veracode_local_runner.py tenant-scan-compliance \
  --limit-apps 10000 \
  --page-size 200 \
  --sleep 0.05 \
  --out tenant_compliance.xlsx \
  --pretty

Produces two sheets: Apps, Compliance.


Output Sheets
	•	Apps → metadata (name, BU, teams, policy, tags, cf_Custom_1..25)
	•	Summaries → open sev counts (open_sev_5..0), last_scan_*, policy_status
	•	FrequencyCompliance → scan type, frequency, last scan, next due, status (+ cf_*)
	•	ReportingAPI → full analytics rows (flattened JSON)
	•	OpenFlawsSummary → pivot by severity × analysis type, plus four bar charts

Severity color palette (5 → 0):
	•	5 = 🔴 Red
	•	4 = 🟠 Orange
	•	3 = 🟡 Yellow
	•	2 = 🔵 Blue
	•	1 = ⚪ Grey
	•	0 = 🟢 Green

Tuning Options
	•	--limit-apps → cap number of apps processed
	•	--page-size → adjust API page size (default 200)
	•	--sleep → delay between app calls (default 0.0)
	•	--reporting-start → earliest window (must be ≤6 months at a time; script walks windows until now)
	•	--reporting-page-size → rows per Reporting API page (default 600)
	•	--pretty → enable Rich UI (progress, apps/sec)
	•	--quiet → suppress progress + debug

Troubleshooting
	•	Region mismatch → set VERACODE_BASE to https://api.veracode.com (US, default) or https://api.veracode.eu (EU).
	•	Empty summaries → check that your --reporting-start covers actual findings data.
	•	Charts missing colors → upgrade openpyxl (pip install -U openpyxl). Labels always display.
	•	API throttling (429) → increase --sleep to 0.05–0.1 and/or reduce --limit-apps.

⸻
Security Notes
	•	This script is read-only.
	•	API requests are HMAC signed (never send username/password).
	•	.env should never be committed — use .env.example for sharing config.
	•	For CI (e.g., GitHub Actions), store keys in repository secrets.



