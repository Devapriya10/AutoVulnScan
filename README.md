# AutoVulnScan

Automated Vulnerability Assessment and Reporting Tool built with Python.

AutoVulnScan is a cybersecurity project designed to automate the initial stages of vulnerability assessment by combining Nmap service discovery, Nmap vulnerability scripts, vulnerability parsing, severity classification, remediation guidance, CVE/NVD enrichment, SQLite storage, and automated report generation.

---

## Features

- Nmap service and version detection
- Nmap NSE vulnerability scanning
- Confirmed vulnerability extraction
- Preliminary vulnerability severity classification
- Remediation recommendations
- CVE/NVD enrichment for findings containing CVE identifiers
- Standardized vulnerability finding model
- SQLite scan and finding storage
- JSON report generation
- HTML report generation
- PDF report generation
- Command-line interface with target validation
- Support for IP addresses, hostnames, and network ranges

---

## Architecture

```text
                 ┌─────────────────────┐
                 │      User Target    │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    CLI / main.py    │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Nmap Service Scan │
                 │      (-sV)          │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Nmap Vulnerability  │
                 │    NSE Scripts      │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Vulnerability Parser│
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Severity +          │
                 │ Remediation         │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    NVD / CVE        │
                 │    Enrichment       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Standardized Finding│
                 │       Model         │
                 └──────────┬──────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │   SQLite   │ │   Reports  │ │   Console  │
       │  Database  │ │ JSON/HTML/ │ │   Output   │
       │            │ │    PDF     │ │            │
       └────────────┘ └────────────┘ └────────────┘
