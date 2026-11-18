# FINAL_CHECKLIST.md — Task 3 Verification & Submission Checklist

**Project:** Future Interns – Cyber Security Task 3 (2026)  
**Project Title:** API Security Risk Analysis  
**Project Location:** `C:\Users\denni\Desktop\FUTURE_CS_03`  
**Target API:** JSONPlaceholder (`https://jsonplaceholder.typicode.com`)  
**Auditor Level:** Senior Application Security (AppSec) Engineer / API Security Auditor  
**Date:** November 2026  

---

## 1. Project Verification Summary

| Category | Requirement Status | Notes |
| :--- | :---: | :--- |
| **Defensive & Read-Only Scope** | **COMPLETED & VERIFIED** | Only GET requests issued; no state alteration, DoS, or credential attacks. |
| **Source Code Tooling** | **COMPLETED & VERIFIED** | `src/api_audit.py`, `security_checks.py`, `risk_classifier.py`, `generate_pdf.py`. |
| **Automated Unit Tests** | **COMPLETED & VERIFIED** | 12 tests passing with 100% success rate using mocked network transports. |
| **Empirical Results Data** | **COMPLETED & VERIFIED** | 6 responses in `results/api_responses/`, 6 headers in `results/response_headers/`, and `results/api_security_findings.json`. |
| **Cybersecurity Analysis** | **COMPLETED & VERIFIED** | 6 dedicated technical analysis markdown modules in `analysis/`. |
| **Formal Report Deliverable** | **COMPLETED & VERIFIED** | 21-section Markdown report + 6-page typeset PDF report in `report/`. |
| **Screenshot Guidance** | **COMPLETED & VERIFIED** | Explicit manual capture guide in `evidence/screenshots/README.md`. |
| **Root Documentation** | **COMPLETED & VERIFIED** | Professional root `README.md`, `requirements.txt`, and `.gitignore`. |

---

## 2. Inventory of Files Created

```
C:\Users\denni\Desktop\FUTURE_CS_03\
│
├── .gitignore                                     [Configuration] Version control exclusion patterns
├── requirements.txt                               [Configuration] Dependencies: requests>=2.31.0, reportlab>=4.0.0
├── README.md                                      [Documentation] Comprehensive project guide & execution commands
├── FINAL_CHECKLIST.md                             [Deliverable] This verification and handoff document
│
├── src/                                           [Source Code]
│   ├── __init__.py                                [Package] Module initialization
│   ├── api_audit.py                              [Audit Tool] Safe GET requests, host validation, findings generation
│   ├── security_checks.py                        [Security Engine] Header baseline checks, PII pattern detection
│   ├── risk_classifier.py                        [Classifier] Evidence-based severity & likelihood rules
│   └── generate_pdf.py                           [Report Engine] Automated ReportLab PDF generator
│
├── tests/                                         [Automated Tests]
│   ├── __init__.py                                [Package] Test module initialization
│   └── test_security_checks.py                   [Unit Tests] 12 comprehensive unit tests with mocked transports
│
├── evidence/                                      [Evidence Instructions]
│   └── screenshots/
│       └── README.md                              [Guide] Detailed instructions for capturing the 7 real screenshots
│
├── results/                                       [Empirical Telemetry]
│   ├── api_security_findings.json                 [Findings] Machine-readable audit findings database
│   ├── api_responses/                             [Data] Saved response payloads:
│   │   ├── posts.json                             (GET /posts - 27.5 KB)
│   │   ├── posts_1.json                           (GET /posts/1 - 292 B)
│   │   ├── users.json                             (GET /users - 5.6 KB)
│   │   ├── users_1.json                           (GET /users/1 - 509 B)
│   │   ├── comments_postId_1.json                 (GET /comments?postId=1 - 1.5 KB)
│   │   └── todos_1.json                           (GET /todos/1 - 83 B)
│   └── response_headers/                          [Headers] Saved HTTP response headers:
│       ├── posts_headers.json
│       ├── posts_1_headers.json
│       ├── users_headers.json
│       ├── users_1_headers.json
│       ├── comments_postId_1_headers.json
│       └── todos_1_headers.json
│
├── analysis/                                      [Technical Analysis Modules]
│   ├── scope_and_methodology.md                   [AppSec] Ethical scope, testing rules, and lifecycle
│   ├── endpoint_analysis.md                       [AppSec] Complete breakdown of all 6 audited endpoints
│   ├── authentication_authorization.md            [AppSec] Auth, BOLA, BFLA, and production SaaS architecture
│   ├── security_headers.md                        [AppSec] Evaluation of HSTS, CSP, Cache-Control, CORS, etc.
│   ├── risk_assessment.md                         [AppSec] Findings table with evidence, likelihood, and business impact
│   └── remediation_plan.md                        [AppSec] 12 production hardening principles with business benefits
│
└── report/                                        [Formal Audit Reports]
    ├── API_Security_Risk_Analysis_Report.md       [Report] Complete 21-section markdown audit report
    └── API_Security_Risk_Analysis_Report.pdf      [Report] Typeset 6-page PDF report with cover page and page numbers
```

---

## 3. Unit Test Verification Results

* **Execution Command:** `python -m unittest discover -s tests -v`
* **Test Count:** 12 tests
* **Result:** **100% Passed (OK)**
* **Execution Time:** ~0.002s
* **Network Dependency:** Strictly Zero (100% mocked requests with strict socket blocking guard in `setUp`)
* **Terminal Hygiene:** 100% Clean — Zero connection retries, zero timeout delays, and zero disk pollution.

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

---

## 4. The 7 Screenshots Required from You

In strict compliance with assignment guidelines, no fake or synthetic screenshot files were placed in the directory. You will capture these 7 genuine screenshots on your computer following the guide in `evidence/screenshots/README.md`:

1. **`01_project_structure.png`:** VS Code Explorer sidebar showing the fully expanded project tree.
2. **`02_api_endpoint_requests.png`:** Successful GET request to `https://jsonplaceholder.typicode.com/posts/1` (in browser Developer Tools Network tab or terminal).
3. **`03_response_headers.png`:** VS Code editor displaying `results/response_headers/posts_1_headers.json`.
4. **`04_json_response_analysis.png`:** VS Code editor displaying `results/api_responses/users_1.json` with synthetic PII fields.
5. **`05_python_audit_execution.png`:** VS Code terminal showing the completed execution of `python src/api_audit.py` with the summary table.
6. **`06_unit_tests.png`:** VS Code terminal showing all 12 unit tests passing via `python -m unittest discover -s tests -v`.
7. **`07_final_report.png`:** PDF reader (Edge, Acrobat, or VS Code) displaying `report/API_Security_Risk_Analysis_Report.pdf`.

---

## 5. Assessment Limitations & Ethical Boundaries

* **Demonstration API Target:** JSONPlaceholder is an open, unauthenticated mock service. It has no private user databases or authorization engine.
* **Not Testable Standard:** Properties such as Broken Object Level Authorization (BOLA), Broken Authentication, and Injection Resistance were designated **NOT TESTABLE WITH SELECTED DEMO API**.
* **Zero Disruption:** Testing was strictly read-only; no state modification, credential stuffing, brute force, or DoS testing was conducted.

---

## 6. Exact Commands to Run in VS Code Terminal

Open terminal in `C:\Users\denni\Desktop\FUTURE_CS_03` and run:

```powershell
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Run the automated API security audit
python src/api_audit.py

# 3. Run all unit tests
python -m unittest discover -s tests -v

# 4. (Optional) Recompile the PDF report if modifications are made
python src/generate_pdf.py
```
