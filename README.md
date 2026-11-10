# ReportForge

<p align="center">
  <img src="assets/reportforge-logo.png" alt="ReportForge Logo" width="200" />
</p>

<p align="center">
  <a href="https://github.com/K4SLR/reportforge/actions/workflows/ci.yml"><img src="https://github.com/K4SLR/reportforge/actions/workflows/ci.yml/badge.svg" alt="ReportForge CI Status" /></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python Version" />
  <img src="https://img.shields.io/badge/release-v2.0.0-0ea5e9" alt="Release Version" />
  <img src="https://img.shields.io/badge/license-MIT-informational" alt="License" />
</p>

**ReportForge** is a Python-based command-line security automation tool designed to generate compliance-ready vulnerability reports for **Vulnerability Disclosure Programs (VDP)**, **Computer Security Incident Response Teams (CSIRT)**, and **Bug Bounty** submissions.

The tool ingests vulnerability findings in JSON format, computes CVSS v3.1 base scores mathematically, sanitizes sensitive credentials from network proofs of concept, validates target scope boundaries, and compiles final deliverables in Microsoft Word (`.docx`), companion Markdown (`.md`), and redacted JSON datasets.

---

## Core Purpose & Utility

In responsible vulnerability disclosure, researchers often spend substantial manual effort transcribing findings, building tables, calculating CVSS metrics, masking confidential tokens, and adapting technical evidence to match diverse organizational document formats.

**ReportForge** automates this entire reporting workflow:
1. **Automated Report Generation:** Converts technical findings into complete reporting packages covering General Information, Vulnerability Details, Steps to Reproduce, Proof of Concept (PoC), Remediation Blueprints, References, and Executive Conclusions.
2. **Dual Template Support (Presets & Custom Files):** Tailors documents to match target organizational structures using built-in presets or by directly ingesting custom user-supplied `.docx` template files.
3. **Deterministic Scoring & Remediation:** Delivers verified CVSS v3.1 mathematical scoring, official CWE/OWASP categorizations, and concrete code-level remediation blueprints for development teams.
4. **Automated Evidence Redaction:** Eliminates the risk of exposing active session cookies, authorization headers, or private keys when attaching raw HTTP requests and responses as evidence.

---

## Key Features

### 1. Multi-CSIRT Presets & Dynamic Custom Template Ingestion
- **Built-in Presets (`--preset`):** Select pre-configured organizational presets directly from the command line to format documents to target reporting standards.
- **Custom Template Ingestion (`--template`):** Ingest any external `.docx` file provided by an organization or enterprise. The engine parses the document structure, maps variables, and populates data tables without breaking the original margins, headers, footers, or layout.

### 2. Automated CVSS v3.1 Calculator & Severity Normalizer
- Computes CVSS v3.1 Base Scores deterministically from vector strings (e.g., `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`).
- Normalizes severity ratings to standard CSIRT classifications: `Critical`, `High`, `Medium`, `Low`, and `Informational`.

### 3. Automated HTTP & JSON Evidence Sanitizer
- Scans raw HTTP requests and responses before injecting them into reports.
- Redacts sensitive credentials to `[REDACTED]`, covering `Authorization` (`Bearer` / `Basic`), `Cookie`, `Set-Cookie`, `X-API-Key`, sensitive query parameters (`token`, `api_key`, `secret`, `password`, `session_id`), and confidential JSON payload keys.

### 4. ScopeGuard Target Validation
- Verifies whether reported endpoints fall within authorized scope boundaries (`In-Scope` vs. `Out-of-Scope`) based on domain wildcards, ports, and sub-paths.
- Features an `--exclude-out-of-scope` flag to automatically filter out non-qualifying findings from the final document.

### 5. DevFixer Remediation Blueprint & CWE Mapping
- Maps vulnerability types (`SQLI`, `IDOR`, `XSS`, `SSRF`, `PATH_TRAVERSAL`, `INFO_DISCLOSURE`) to official **CWE** identifiers and **OWASP Top 10** categories with authoritative references.
- Generates defensive code patches (Python, JavaScript, SQL, Nginx) directly into the recommendation and proof of concept sections.

### 6. Multi-Finding Support & Document Integrity Verifier
- Supports compiling single or multiple findings into a unified report, automatically sorted from highest to lowest severity.
- Provides a dedicated `verify` subcommand to validate OpenXML structural integrity and verify that all document fields have been populated.

---

## Project Structure

```text
reportforge/
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions automated test workflow
├── assets/
│   └── reportforge-logo.png # Project logo
├── reportforge/
│   ├── __init__.py          # Package version metadata
│   ├── __main__.py          # Python module execution entrypoint
│   ├── cli.py               # Command-line interface parser
│   ├── registry.py          # CSIRT preset catalog & field mappings
│   ├── enrichment.py        # CVSS calculator, HTTP sanitizer, ScopeGuard, & DevFixer library
│   ├── parser.py            # JSON findings loader and normalizer
│   ├── template_builder.py  # Base document template generator (.docx)
│   ├── fetcher.py           # Template cache manager & safety validator
│   └── engine.py            # DOCX document populator & Markdown exporter
├── templates/               # Built-in base templates directory (.docx)
├── examples/                # Sample vulnerability findings & scope configurations
├── output/                  # Generated report deliverables (.docx, .md, .json)
├── tests/                   # Automated unit and integration test suite
├── pyproject.toml           # Package build and dependency configuration
├── LICENSE                  # MIT License
└── README.md                # Project documentation
```

---

## Installation

Ensure your environment is running **Python 3.10+**, then clone and install:

```bash
git clone https://github.com/K4SLR/reportforge.git
cd reportforge
pip install -e .
```

---

## CLI Usage Guide

### 1. List Available Presets
Display all registered organizational preset configurations:

```bash
reportforge list-presets
```

### 2. Update Local Template Cache
Build and refresh base template assets in the local cache directory:

```bash
reportforge update-presets
```

### 3. Generate a Report Using a Preset
Compile a complete `.docx` report, companion Markdown file, and sanitized JSON dataset:

```bash
reportforge generate \
  --findings examples/sample_findings.json \
  --scope examples/nusatech_scope.json \
  --preset nusatech \
  --exclude-out-of-scope \
  --participant "k4slr" \
  --alias "k4slr" \
  --asset-name "Telemetry & Information Service Portal" \
  --asset-type "Website / API" \
  --domain-ip "portal.nusatech.local / 192.0.2.10" \
  --app-version "v2.1" \
  --output output/Laporan_VDP_Final.docx \
  --md output/Laporan_VDP_Final.md \
  --json-out output/findings_sanitized.json
```

### 4. Generate a Report Using a Custom Template File (`--template`)
When an organization provides a specific `.docx` reporting format, supply the file path via `--template` (or `-t`):

```bash
reportforge generate \
  --findings examples/sample_findings.json \
  --template path/to/target_csirt_template.docx \
  --participant "k4slr" \
  --alias "k4slr" \
  --asset-name "Telemetry & Information Service Portal" \
  --domain-ip "portal.nusatech.local / 192.0.2.10" \
  --output output/Custom_CSIRT_Report.docx
```

### 5. Verify Document Integrity
Inspect a generated `.docx` archive to verify OpenXML validity and placeholder resolution:

```bash
reportforge verify -d output/Laporan_VDP_Final.docx
```

---

## Command-Line Arguments Reference

| Argument | Short | Description |
| :--- | :---: | :--- |
| `--findings` | `-f` | **(Required)** Path to input vulnerability findings JSON file. |
| `--preset` | `-p` | Target organization preset (`nusatech`, `aurorafin`, `garudacloud`, `generic`). |
| `--template` | `-t` | Path to custom user-supplied `.docx` template (overrides preset). |
| `--scope` | `-s` | Path to scope JSON file for ScopeGuard boundary checks. |
| `--exclude-out-of-scope` | — | Automatically filter out findings outside authorized scope. |
| `--participant` | `-n` | Researcher identifier for General Information tables (default: `k4slr`). |
| `--alias` | `-a` | Researcher alias / handle (default: `k4slr`). |
| `--asset-name` | — | Name of tested target asset. |
| `--asset-type` | — | Category of tested asset (e.g., `Website / API / Server`). |
| `--domain-ip` | — | Target domain name and/or IP address. |
| `--app-version` | — | Target application software build/version. |
| `--contact` | — | Contact email or communications channel. |
| `--output` | `-o` | Output file path for generated `.docx` report. |
| `--md` | — | Optional output path for companion Markdown report. |
| `--json-out` | — | Optional output path for enriched and sanitized JSON data. |
| `--refresh` | — | Force local template cache reconstruction before generation. |

---

## Input Findings Schema (`findings.json`)

ReportForge accepts an array of finding objects in standard JSON format:

```json
[
  {
    "id": "NUSA-001",
    "title": "Broken Object Level Authorization (IDOR) on Document Export Endpoint",
    "endpoint": "https://portal.nusatech.local/api/v1/dokumen/unduh?id=801",
    "vuln_type": "IDOR",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "description": "The document download endpoint does not verify ownership of the requested document ID against the authenticated session.",
    "impact": "Authenticated users can download internal records belonging to other accounts by modifying the 'id' parameter.",
    "status": "OPEN",
    "asset_name": "Telemetry & Information Service Portal",
    "asset_type": "Website / API",
    "domain_ip": "portal.nusatech.local / 192.0.2.10",
    "app_version": "v2.1",
    "steps_to_reproduce": [
      "Authenticate as Test Account A and record the document export request for id=801.",
      "Open an isolated browser session and authenticate as Test Account B.",
      "Send a GET request to /api/v1/dokumen/unduh?id=801 and observe successful file retrieval with HTTP 200 OK."
    ],
    "raw_http_request": "GET /api/v1/dokumen/unduh?id=801&api_key=sk_live_dummy9988 HTTP/1.1\r\nHost: portal.nusatech.local\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummysecret\r\nCookie: session_id=sess_dummy12345\r\n\r\n"
  }
]
```

---

## Automated Testing

Execute the test suite to verify CVSS scoring, HTTP sanitization, ScopeGuard enforcement, and OpenXML generation:

```bash
python -m unittest discover -s tests -v
```

---

## Star History

<p align="center">
  <a href="https://star-history.com/#K4SLR/reportforge&Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=K4SLR/reportforge&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=K4SLR/reportforge&type=Date" />
      <img alt="ReportForge Star History Chart" src="https://api.star-history.com/svg?repos=K4SLR/reportforge&type=Date" width="100%" />
    </picture>
  </a>
</p>

---

## License

Distributed under the **MIT License**. Copyright (c) 2026 **k4slr**. See [`LICENSE`](LICENSE) for details.
