# Cybersecurity Audit Plan & Reconnaissance Scanner

An enterprise-grade Cybersecurity Audit Plan and accompanying automated Python reconnaissance tool designed to evaluate, measure, and strengthen the security posture of modern digital infrastructure[cite: 1]. Grounded in the **NIST Cybersecurity Framework (CSF 2.0)** and **ISO/IEC 27001** standards[cite: 1].

## 📌 Features

- **Port Scanning**: Automated discovery of standard network ports (`21`, `22`, `80`, `443`, `3389`, `8080`) to identify exposed services[cite: 1].
- **HTTP Header Audit**: Inspection of vital web security controls including `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`[cite: 1].
- **SSL/TLS Certificate Inspection**: Verification of certificate issuers, subjects, cipher suites, and expiration schedules[cite: 1].
- **JSON Log Export**: Structured output logging (`audit_report.json`) for seamless integration into SIEM and compliance reporting tools[cite: 1].
- 
## 📂 Repository Structure

```text
├── CybersecurityAuditPlan.py   # Python automated auditing script
├── audit_report.json           # Sample JSON audit scan log output
└── README.md                   # Project documentation

## 🚀 Getting Started

### Prerequisites

* Python 3.10+ installed on your system.


* Standard Python library dependencies (`socket`, `ssl`, `json`, `urllib.request`, `datetime`).

### Usage

1. **Clone the repository:**
```bash
git clone [https://github.com/aryaevuru14/Cybersecurity-Audit-Plan.git](https://github.com/aryaevuru14/Cybersecurity-Audit-Plan.git)
cd Cybersecurity-Audit-Plan

2. **Run the auditor script:**
```bash
python CybersecurityAuditPlan.py

3. **View the audit output:**
Open the generated `audit_report.json` file to review target security findings.

## 📊 Sample Audit Output

```json
{
    "target": "example.com",
    "timestamp": "2026-10-06T17:57:03.148279+00:00",
    "port_scan": {
        "80": "OPEN",
        "443": "OPEN"
    },
    "http_headers": {
        "Strict-Transport-Security": {
            "status": "FAIL - MISSING",
            "value": null
        }
    }
}

## 📜 Compliance & Framework Alignment

* **NIST CSF 2.0**: Identify, Protect, Detect, Respond, Recover.


* **ISO/IEC 27001**: Control Domain A.12 (Operations Security) and A.13 (Communications Security).


* **CVSS v3.1**: Risk prioritization scoring for vulnerability remediation matrices.
