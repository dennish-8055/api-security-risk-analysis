# API Security Risk Analysis

**Future Interns – Cyber Security Internship Program 2026**  
**Task 3: API Security Risk Analysis**  
**Assessment Target:** JSONPlaceholder REST API (`https://jsonplaceholder.typicode.com`)  
**Auditor:** Senior Application Security (AppSec) Engineer / Security Auditor  
**Host Environment:** Windows 11 | Python 3.14.3 | Visual Studio Code | GitHub Desktop  

---

## 1. Project Overview

This repository contains the complete implementation, automated tooling, test suite, and formal technical documentation for **Future Interns Cyber Security Task 3 (2026)**.

The project performs an evidence-based, defensive, read-only API security risk assessment against a safe public demonstration REST API: **JSONPlaceholder**. The assessment inspects public endpoint architectures, HTTP response headers, data minimization behaviors, rate-limiting exposure, and error responses, evaluating all observations against the **OWASP API Security Top 10 (2023)** standard and the **Shieldfy API Security Checklist**.

> [!IMPORTANT]
> **Demonstration API Context:**  
> JSONPlaceholder is intentionally architected as a free, open, stateless demonstration and prototyping service. It maintains no private user accounts, financial ledgers, or production databases. Observations made during this audit reflect deliberate mock design choices for developer education and must **not** be misconstrued as exploitable vulnerabilities in commercial production environments.

---

## 2. Assessment Objectives

1. **Defensive API Auditing:** Demonstrate professional, read-only Application Security assessment methodology without invasive or disruptive actions.
2. **Security Header Inspection:** Evaluate transport and defensive HTTP headers (`Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy`, `Cache-Control`, `Server`, `X-Powered-By`).
3. **Data Minimization & Privacy:** Analyze JSON payload structures to identify sensitive-looking fields (synthetic PII such as email, phone, physical address, and GPS coordinates).
4. **Rate Limiting & Abuse Visibility:** Inspect response headers for quota metadata and rate-limiting enforcement signals.
5. **OWASP API Top 10 Taxonomy:** Classify all technical observations into standardized severity tiers (`LOW`, `INFORMATIONAL`, `NOT TESTABLE`).
6. **Production Remediation Blueprints:** Formulate practical hardening recommendations for modern enterprise SaaS APIs, paired with simple business benefit explanations.

---

## 3. Ethical Rules of Engagement & Scope

This assessment is strictly defensive and educational.

### Permitted Actions:
- Standard HTTP `GET` requests to documented JSONPlaceholder endpoints.
- Reviewing public documentation and schema contracts.
- Inspecting HTTP response status codes, headers, and JSON bodies.
- Comparing publicly accessible resource identifiers.
- Controlled automated execution via custom Python audit scripts with polite delays.

### Strictly Prohibited Actions:
- No exploitation, penetration, or state tampering.
- No authentication bypass or privilege escalation attempts.
- No credential stuffing, dictionary attacks, or brute force.
- No Denial of Service (DoS), stress testing, or flood requests.
- No destructive HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- No testing against private or unauthorized production APIs.
- No testing or harvesting of genuine human personal data.

### The "Not Testable" Standard:
Whenever a security property (e.g., Broken Object Level Authorization, Broken Authentication, or Injection Resistance) cannot be verified safely due to the public mock nature of the target, it is explicitly classified as:
> **`NOT TESTABLE WITH SELECTED DEMO API`**

---

## 4. Audited Endpoints

The audit evaluates six representative endpoints illustrating core RESTful design patterns:

| Endpoint Path | HTTP Method | Target Purpose | Parameter Type | Documented Return Type |
| :--- | :---: | :--- | :--- | :--- |
| `/posts` | `GET` | List all blog post records | None | Array of 100 Post Objects |
| `/posts/1` | `GET` | Retrieve single post by ID | Path variable (`/1`) | Single Post Object |
| `/users` | `GET` | List all user profile entities | None | Array of 10 User Objects |
| `/users/1` | `GET` | Retrieve single user profile by ID | Path variable (`/1`) | Single User Object (Nested PII) |
| `/comments?postId=1` | `GET` | List comments filtered by post ID | Query string (`postId=1`) | Array of 5 Comment Objects |
| `/todos/1` | `GET` | Retrieve single todo record by ID | Path variable (`/1`) | Single Todo Object |

---

## 5. Tools & Technologies Used

- **Operating System:** Windows 11 (64-bit)
- **Language / Runtime:** Python 3.14.3
- **HTTP Client:** `requests` (v2.34.2)
- **PDF Generation Engine:** `reportlab` (v5.1.0)
- **Test Framework:** `unittest` (Python Standard Library) with mock transports
- **Development & Version Control:** Visual Studio Code & GitHub Desktop
- **Security Standards:** OWASP API Security Top 10 (2023 Edition) & Shieldfy Checklist

---

## 6. Project Structure

```
FUTURE_CS_03/
│
├── README.md                                  # Root documentation and project overview
├── requirements.txt                           # Project dependencies (requests, reportlab)
├── .gitignore                                 # Clean version control exclusions
├── FINAL_CHECKLIST.md                         # Task verification and handoff checklist
│
├── src/                                       # Core Python source code
│   ├── __init__.py                            # Package initializer
│   ├── api_audit.py                           # Defensive read-only API auditing tool
│   ├── security_checks.py                     # Header, body, and PII inspection engine
│   ├── risk_classifier.py                     # Evidence-based risk classification engine
│   └── generate_pdf.py                        # Automated professional PDF report builder
│
├── tests/                                     # Automated test suite (fully mocked)
│   ├── __init__.py                            # Test package initializer
│   └── test_security_checks.py                # 12 unit tests for checks and error handling
│
├── evidence/                                  # Audit evidence and screenshots
│   └── screenshots/
│       └── README.md                          # Guide for capturing the 7 required screenshots
│
├── results/                                   # Audit outputs and raw telemetry
│   ├── api_responses/                         # Saved JSON payloads from audited endpoints
│   ├── response_headers/                      # Saved HTTP response headers (JSON format)
│   └── api_security_findings.json             # Consolidated structured findings database
│
├── analysis/                                  # Detailed cybersecurity analysis modules
│   ├── scope_and_methodology.md               # Scope boundaries, rules, and testing lifecycle
│   ├── endpoint_analysis.md                   # Detailed technical analysis of every endpoint
│   ├── authentication_authorization.md        # Deep-dive on auth, BOLA, and SaaS controls
│   ├── security_headers.md                    # Technical inspection of all response headers
│   ├── risk_assessment.md                     # Master findings table and threat models
│   └── remediation_plan.md                    # 12-point production SaaS remediation blueprint
│
└── report/                                    # Formal deliverables
    ├── API_Security_Risk_Analysis_Report.md   # Comprehensive 21-section Markdown report
    └── API_Security_Risk_Analysis_Report.pdf  # Professional 6-page typeset PDF report
```

---

## 7. Installation & Setup (Windows 11)

### Step 1: Open Project in Visual Studio Code
Open your VS Code editor, click **File > Open Folder...**, and select:
```
C:\Users\denni\Desktop\FUTURE_CS_03
```

### Step 2: Open Integrated Terminal
Press ``Ctrl + ` `` (or select **Terminal > New Terminal**) to open a PowerShell session in the project root.

### Step 3: Install Required Dependencies
Run the following command to install the required packages (`requests` and `reportlab`):
```powershell
python -m pip install -r requirements.txt
```

---

## 8. How to Run the Security Audit

Execute the automated API security audit tool:
```powershell
python src/api_audit.py
```

### What This Command Does:
1. Safely transmits 6 single HTTP GET requests to JSONPlaceholder with a 5.0s timeout.
2. Enforces strict domain validation and refuses to follow unexpected external redirects.
3. Inspects response status codes, headers, and payload structures.
4. Saves response bodies to `results/api_responses/`.
5. Saves response headers to `results/response_headers/`.
6. Compiles structured findings into `results/api_security_findings.json`.
7. Prints a formatted summary table to your terminal.

---

## 9. How to Run Automated Unit Tests

Execute the unit test suite:
```powershell
python -m unittest discover -s tests -v
```

### Expected Output:
```
test_detect_pii_in_user_profile (test_security_checks.TestResponseBodyChecker.test_detect_pii_in_user_profile) ... ok
test_detect_suspicious_secret_keys (test_security_checks.TestResponseBodyChecker.test_detect_suspicious_secret_keys) ... ok
test_empty_and_none_body_handling (test_security_checks.TestResponseBodyChecker.test_empty_and_none_body_handling) ... ok
test_classification_of_demo_api_audit (test_security_checks.TestRiskClassifier.test_classification_of_demo_api_audit) ... ok
test_connection_error_handling (test_security_checks.TestSafeAPIAuditorMocked.test_connection_error_handling) ... ok
test_successful_mocked_get_request (test_security_checks.TestSafeAPIAuditorMocked.test_successful_mocked_get_request) ... ok
test_timeout_handling (test_security_checks.TestSafeAPIAuditorMocked.test_timeout_handling) ... ok
test_url_boundary_validation (test_security_checks.TestSafeAPIAuditorMocked.test_url_boundary_validation) ... ok
test_all_security_headers_present (test_security_checks.TestSecurityHeaderChecker.test_all_security_headers_present) ... ok
test_information_disclosure_headers (test_security_checks.TestSecurityHeaderChecker.test_information_disclosure_headers) ... ok
test_missing_headers_detection (test_security_checks.TestSecurityHeaderChecker.test_missing_headers_detection) ... ok
test_rate_limiting_headers_parsing (test_security_checks.TestSecurityHeaderChecker.test_rate_limiting_headers_parsing) ... ok

----------------------------------------------------------------------
Ran 12 tests in 0.002s

OK
```
*All 12 tests run with 100% mocked network transports and socket-level isolation, never making real network calls.*

---

## 10. How to Re-generate the PDF Report

The professional PDF report can be recompiled at any time by running:
```powershell
python src/generate_pdf.py
```
This builds `report/API_Security_Risk_Analysis_Report.pdf` with cover page, running headers/footers, dynamic page numbers ("Page X of Y"), and stylized tables.

---

## 11. Key Findings Summary

| ID | Finding Title | Severity | Affected Scope | Recommendation |
| :---: | :--- | :---: | :--- | :--- |
| **FIND-01** | Technology Fingerprinting via X-Powered-By Header | **LOW** | All 6 Audited Endpoints | Disable header: `app.disable('x-powered-by')` |
| **FIND-02** | Missing HTTP Strict Transport Security (HSTS) | **LOW** | All 6 Audited Endpoints | Add `Strict-Transport-Security: max-age=31536000` |
| **FIND-03** | Permissive Cache-Control Policy on Data Endpoints | **LOW** | All 6 Audited Endpoints | Apply `Cache-Control: no-store, private` on SaaS APIs |
| **FIND-04** | Simulated Excessive Data Exposure (Synthetic PII) | **INFORMATIONAL** | `/users`, `/users/1` | Enforce strict Data Transfer Objects (DTOs) & masking |
| **FIND-05** | Exposed Rate-Limiting Quota Metadata | **INFORMATIONAL** | All 6 Audited Endpoints | Adopt standard IETF RateLimit headers |
| **FIND-06** | Object-Level Authorization (BOLA) Validation | **NOT TESTABLE** | `/posts/1`, `/users/1`, etc. | Require OAuth 2.0 and contextual ownership checks |
| **FIND-07** | Input Validation & Injection Resistance | **NOT TESTABLE** | `/comments?postId=1` | Enforce schema validation & parameterized queries |

---

## 12. Assessment Limitations

1. **Target Architecture Constraints:** JSONPlaceholder has no user authentication or private tenancy engine; authorization flaws (BOLA/BFLA) cannot be confirmed on open public test fixtures.
2. **Defensive Testing Boundaries:** Active penetration testing, SQL injection payloads, brute forcing, and DoS flooding were strictly excluded by ethical rules.
3. **Synthetic Data:** All returned records are simulated dummy fixtures; no real personal data was processed.

---

## 13. References

- [OWASP API Security Top 10 (2023)](https://github.com/OWASP/API-Security)
- [Shieldfy API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [JSONPlaceholder Official Documentation](https://jsonplaceholder.typicode.com/guide/)
- [RFC 6797: HTTP Strict Transport Security (HSTS)](https://datatracker.ietf.org/doc/html/rfc6797)
- [RFC 7234: HTTP Caching](https://datatracker.ietf.org/doc/html/rfc7234)
- [RFC 7807: Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)
