# Evidence Screenshots Guide

**Project:** Future Interns – Cyber Security Task 3 (2026)  
**Project Title:** API Security Risk Analysis  
**Location:** `C:\Users\denni\Desktop\FUTURE_CS_03\evidence\screenshots\`  

This guide provides step-by-step instructions for capturing genuine evidence screenshots on Windows 11.

> [!IMPORTANT]
> **No Placeholder or Fake Images:** In accordance with professional integrity and internship guidelines, do not generate artificial or synthetic screenshot files. Follow the instructions below to capture real screenshots from your own computer and save them with the exact specified filenames in this directory.

---

## Screenshot Inventory Summary

| Filename | Subject / Window to Capture | Key Elements Required |
| :--- | :--- | :--- |
| `01_project_structure.png` | VS Code Explorer Side Panel | Expanded directory tree showing all files and folders |
| `02_api_endpoint_requests.png` | Terminal or Browser / Postman | Live GET request and 200 OK response from JSONPlaceholder |
| `03_response_headers.png` | VS Code Editor showing headers JSON | Real response headers (`x-powered-by`, `x-ratelimit-limit`, etc.) |
| `04_json_response_analysis.png` | VS Code Editor showing user profile | `users_1.json` displaying synthetic PII fields (email, address, geo) |
| `05_python_audit_execution.png` | VS Code Integrated Terminal | Full execution output of `python src/api_audit.py` with findings table |
| `06_unit_tests.png` | VS Code Integrated Terminal | Output of `python -m unittest discover -s tests -v` showing all 12 tests OK |
| `07_final_report.png` | PDF Reader (Edge / Acrobat / VS Code) | `API_Security_Risk_Analysis_Report.pdf` open and clearly legible |

---

## Detailed Step-by-Step Capture Instructions

### Screenshot 01: Complete Project Structure
* **Filename:** `01_project_structure.png`
* **What to Open:** Visual Studio Code with the folder `FUTURE_CS_03` opened.
* **What to Expand:** In the left-hand Explorer sidebar, expand all directories:
  * `src/` (`__init__.py`, `api_audit.py`, `security_checks.py`, `risk_classifier.py`, `generate_pdf.py`)
  * `tests/` (`__init__.py`, `test_security_checks.py`)
  * `analysis/` (all 6 `.md` files)
  * `results/` (`api_responses/`, `response_headers/`, `api_security_findings.json`)
  * `report/` (`.md` and `.pdf`)
  * `evidence/` (`screenshots/README.md`)
  * Root files: `README.md`, `requirements.txt`, `.gitignore`, `FINAL_CHECKLIST.md`
* **How to Capture:** Press `Win + Shift + S`, select the VS Code window showing the sidebar tree, and save as `evidence/screenshots/01_project_structure.png`.

---

### Screenshot 02: API Endpoint Requests
* **Filename:** `02_api_endpoint_requests.png`
* **What to Open:** Your web browser (Edge/Chrome) or PowerShell / VS Code terminal.
* **Action:**
  * In browser: Navigate to `https://jsonplaceholder.typicode.com/posts/1` and open Developer Tools (`F12`) to the **Network** tab, refreshing the page to show the `200 OK` GET request.
  * *OR in terminal:* Run:
    ```powershell
    python -c "import requests; r = requests.get('https://jsonplaceholder.typicode.com/posts/1'); print('Status:', r.status_code); print(r.text)"
    ```
* **What must be visible:** The URL `https://jsonplaceholder.typicode.com/posts/1`, status `200 OK`, and the returned JSON post body.
* **How to Capture:** Press `Win + Shift + S` and save as `evidence/screenshots/02_api_endpoint_requests.png`.

---

### Screenshot 03: Actual Response Headers
* **Filename:** `03_response_headers.png`
* **What to Open:** VS Code Editor.
* **Action:** Open `results/response_headers/posts_1_headers.json`.
* **What must be visible:** Real response headers showing:
  * `"x-powered-by": "Express"`
  * `"Cache-Control": "max-age=43200"`
  * `"x-ratelimit-limit": "3600000"`
  * `"x-content-type-options": "nosniff"`
  * `"Server": "cloudflare"`
* **How to Capture:** Press `Win + Shift + S` capturing the editor window and save as `evidence/screenshots/03_response_headers.png`.

---

### Screenshot 04: JSON Response Analysis (Synthetic PII)
* **Filename:** `04_json_response_analysis.png`
* **What to Open:** VS Code Editor.
* **Action:** Open `results/api_responses/users_1.json`.
* **What must be visible:** The user record showing synthetic contact information and physical address:
  * `"name": "Leanne Graham"`
  * `"email": "Sincere@april.biz"`
  * `"address"` with `"street"`, `"city"`, `"zipcode"`, and `"geo"` coordinates (`lat`, `lng`)
  * `"phone": "1-770-736-8031 x56442"`
* **How to Capture:** Press `Win + Shift + S` and save as `evidence/screenshots/04_json_response_analysis.png`.

---

### Screenshot 05: Python Audit Execution
* **Filename:** `05_python_audit_execution.png`
* **What to Open:** VS Code Integrated Terminal (PowerShell).
* **Action:** Run the command:
  ```powershell
  python src/api_audit.py
  ```
* **What must be visible:**
  * Banner: `FUTURE INTERNS CYBER SECURITY - API SECURITY AUDIT TOOL`
  * Progress lines for all 6 endpoints (`Status: 200 OK | Size: ... bytes | Time: ... ms`)
  * The aligned terminal summary table displaying finding IDs `FIND-01` through `FIND-07` with severities (`LOW`, `INFORMATIONAL`, `NOT TESTABLE`)
  * Message: `[SUCCESS] API Security Audit execution finished successfully.`
* **How to Capture:** Press `Win + Shift + S` and save as `evidence/screenshots/05_python_audit_execution.png`.

---

### Screenshot 06: Automated Unit Tests Passing
* **Filename:** `06_unit_tests.png`
* **What to Open:** VS Code Integrated Terminal.
* **Action:** Run the unit test discovery command:
  ```powershell
  python -m unittest discover -s tests -v
  ```
* **What must be visible:**
  * All 12 unit tests listed with `... ok` status.
  * Final summary: `Ran 12 tests in 0.00Xs` and `OK`.
* **How to Capture:** Press `Win + Shift + S` and save as `evidence/screenshots/06_unit_tests.png`.

---

### Screenshot 07: Final Security Report
* **Filename:** `07_final_report.png`
* **What to Open:** Open `report/API_Security_Risk_Analysis_Report.pdf` in your preferred PDF reader (Microsoft Edge, Adobe Acrobat, or VS Code PDF viewer).
* **What must be visible:** The cover page and Executive Summary showing the report title:
  * `API SECURITY RISK ANALYSIS REPORT`
  * Future Interns Cyber Security 2026 header
  * Corporate cover metadata box and ethical statement callout banner.
* **How to Capture:** Press `Win + Shift + S` and save as `evidence/screenshots/07_final_report.png`.

---

## Verification Checklist

Before final submission to GitHub Desktop or Future Interns portal:
- [ ] All 7 files exist in `evidence/screenshots/`
- [ ] Files are named exactly as specified (PNG format, lowercase with underscores)
- [ ] Images are crisp, legible, and uncropped
- [ ] No personal sensitive information (passwords, private SSH keys, personal system tokens) is visible in the screenshots.
