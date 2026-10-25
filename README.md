# Email Forensics and Phishing Investigator

A local, offline-first Streamlit application for examining saved `.eml` evidence. It extracts headers, Received routes, URLs, and attachment metadata; hashes original email files; records investigation events in SQLite; and generates HTML and CSV reports.

> **Forensic limitations:** This is an educational triage aid, not a malware scanner, attribution system, court-certified evidence store, or substitute for an organization's forensic process. Heuristics can produce false positives and false negatives. Preserve trusted originals, use verified working copies, and record analyst conclusions separately. A matching hash proves only that bytes match a known reference; it does not prove sender identity or truthful metadata.

## Features

- Multi-file `.eml` import, unique evidence IDs, SHA-256 verification, UTC timestamps, and a local evidence copy.
- Email header, authentication-result, conservative Received routing, URL, and MIME attachment inspection.
- Transparent rule-based score normalized to 0–100 and individual evidence/action details.
- Local SQLite investigation history and append-only-through-the-app custody events.
- Escaped standalone HTML report and structured findings CSV.
- Optional manual VirusTotal domain lookup. No link visiting, redirects, attachment upload, or API request without an explicit action.
- URL Reputation Checker with offline heuristics, existing VirusTotal URL report lookup, explicitly confirmed URL submission, bounded result polling, and redacted local CSV history.
- Synthetic tests use fictional identities and reserved `.example` domains.

## Requirements

- Python 3.10 or newer (tested project target)
- macOS, Windows, or another Python-supported desktop OS

## Install and run

### macOS / Linux

```bash
cd "/path/to/email foresnsic"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### Windows PowerShell

```powershell
cd "C:\path\to\email foresnsic"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit. The application creates `app_data/` for its SQLite database and preserved evidence files. Both are excluded from Git by `.gitignore`; back them up and restrict access according to your institution's evidence policy.

### Deploy on Streamlit Community Cloud

1. In Streamlit Community Cloud, create a new app from `ojhaddeepak/emailforensic`, select branch `main`, and set the main file path to `app.py`.
2. If enabling VirusTotal, add this in the app's **Settings → Secrets** as TOML:

   ```toml
   VIRUSTOTAL_API_KEY = "your_actual_api_key"
   ```

   The application reads the key from Cloud secrets without displaying it. Do not commit the key or put it in a public file.
3. Deploy the app and check the app logs if dependency installation or startup fails.

This project has no user authentication and stores uploaded emails, evidence copies, and its SQLite database under `app_data/` on the app's local filesystem. Hosted files may be accessible to anyone who can access the app, and local filesystem data may not survive restarts or redeployments. Do not upload real, confidential, or regulated email evidence to a publicly accessible deployment; use synthetic data for demonstrations. This app does not currently provide durable cloud storage or multi-user access controls.

### Optional VirusTotal setup

Create a private `.env` without overwriting one that already exists, then edit it locally:

```bash
cp -n .env.example .env
code .env
```

Replace the placeholder with `VIRUSTOTAL_API_KEY=your_actual_api_key`. Keep the key private. Domain and URL requests are explicit user actions; email files and attachments are never uploaded. `.env` is excluded from Git.

The URL Reputation Checker can retrieve an existing URL report or, with a separate explicit confirmation, submit a URL for analysis. VirusTotal receives the URL during either action. URLs that appear to contain credentials, tokens, reset codes, or sensitive authentication/query parameters are blocked from both actions. Query values are redacted in local URL history exports. Existing reports may be missing; scan results can be incomplete or outdated. The checker never visits the URL itself.

If an API key has been pasted into a chat, issue tracker, screenshot, or other shared location, revoke it and create a replacement before using the integration. Never add the key to source control.

## Tests

```bash
python -m pytest -q
```

## Demonstration scenario

1. Open **Import Email Evidence** and select a synthetic or authorized `.eml` file.
2. Record the evidence ID and SHA-256 shown after import.
3. Inspect the raw and parsed fields under **Email Header Analysis**, then compare original Received lines under **Routing Analysis**.
4. Review offline URL indicators and attachment hashes without opening links or files.
5. Explain the score as a transparent triage heuristic and inspect its component findings.
6. Download the HTML report and findings CSV; verify the original's stored hash under **Chain of Custody**.
7. Open **URL Reputation Checker**, enter an authorized URL, inspect it offline, and explicitly check for an existing report or confirm a scan submission.
8. Review URL history and download its CSV; query values and sensitive path fragments are redacted.
9. Point out the audit log, UTC timestamps, privacy boundary for external lookups, and integrity/attribution limitations.

## Project layout

```text
app.py
config.py
modules/             Parsing, analysis, SQLite, scoring, reports, and VT client
pages/               Dashboard and import/analysis workflows
tests/               Unit and workflow tests
sample_emails/       Notes on synthetic fixtures
app_data/             Runtime data; ignored by Git
```

## Data-handling notes

- Only `.eml` uploads are accepted, with a 20 MB per-file, 25-file-per-import, and 100 MB combined batch limit.
- Attachment metadata and hashes are extracted from the in-memory parsed message; attachments are not exported or opened.
- Stored email copies are created with unique evidence IDs and are not overwritten through the import workflow.
- Email bodies are kept locally as parsed investigation data to support reports. Protect `app_data/` as sensitive material.
- SQLite triggers prevent normal application updates/deletes to custody events, but a person with direct database/filesystem access can alter them.
- Authentication-Results are untrusted header text unless verified against receiver-side records.
