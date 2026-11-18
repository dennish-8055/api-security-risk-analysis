# Scope and Methodology

**Project:** Future Interns – Cyber Security Task 3 (2026)  
**Project Title:** API Security Risk Analysis  
**Auditor Level:** Senior Application Security (AppSec) Engineer / API Security Auditor  
**Target Environment:** Windows 11 | Python 3.14.3 | Visual Studio Code | GitHub Desktop  
**Target API:** JSONPlaceholder (`https://jsonplaceholder.typicode.com`)  
**Official API Documentation:** [JSONPlaceholder Guide](https://jsonplaceholder.typicode.com/guide/)  

---

## 1. Executive Context & Objective

The objective of this assessment is to conduct a professional, defensive, read-only Application Programming Interface (API) security risk analysis against a representative public REST service. The evaluation reviews architectural design patterns, HTTP response headers, data minimization behaviors, error responses, and configuration controls.

This project references the **OWASP API Security Top 10 (2023)** standard and the **Shieldfy API Security Checklist** as foundational security benchmarks. All analysis, findings, risk classifications, and remediation strategies presented in this report represent original technical work tailored specifically to the audited endpoints.

---

## 2. Ethical Rules of Engagement & Boundaries

Security assessments must strictly conform to authorized parameters and ethical boundaries. This project is defensive and educational:

### 2.1 Permitted Actions
- **Safe HTTP GET Requests:** Issuing a minimal, controlled volume of standard GET requests to documented public endpoints.
- **Documentation Review:** Examining the published API guide, schema specifications, and parameter contracts.
- **Header Inspection:** Evaluating response headers (e.g., `Cache-Control`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Server`, `X-Powered-By`, CORS policies).
- **Body & Data Minimization Analysis:** Inspecting returned JSON payloads to identify field exposure, structure conventions, and simulated Personally Identifiable Information (PII).
- **Rate-Limiting Visibility Review:** Passively observing quota and rate-limit metadata exposed in response headers.
- **Defensive Error Review:** Evaluating standard HTTP status codes returned for valid, documented endpoints.

### 2.2 Prohibited Actions
- **No Exploitation or Penetration:** No attempts to break, manipulate, or subvert server logic.
- **No Authentication Bypass Attempts:** No credential attacks, token forging, cookie tampering, or unauthorized privilege escalation.
- **No Brute-Force Attacks:** No dictionary attacks, credential stuffing, or enumerative fuzzing.
- **No Denial of Service (DoS):** No high-volume concurrency, stress testing, flood requests, or resource exhaustion.
- **No Destructive HTTP Methods:** `POST`, `PUT`, `PATCH`, and `DELETE` requests are strictly forbidden to ensure state immutability.
- **No Private or Production Targeting:** Confining all requests strictly to the authorized demonstration host `jsonplaceholder.typicode.com`.
- **No Real User PII Exposure:** Testing is limited to synthetic fixtures; real human personal data is neither processed nor targeted.

---

## 3. The "Not Testable" Determination Principle

A core principle of professional cybersecurity auditing is intellectual honesty. An auditor must never fabricate vulnerabilities or infer exploitable flaws where empirical verification is impossible due to target architectural constraints.

**JSONPlaceholder is intentionally designed as an open, stateless, static mock REST API.** It contains:
- No real authentication engine (no user login, OAuth 2.0 provider, API key gateway, or JWT verification).
- No tenancy or real object-level ownership boundaries (every mock resource is designed to be globally readable).
- No sensitive operational database (all responses are static test JSON fixtures).

Consequently, whenever a security property (such as Broken Object Level Authorization, Broken Authentication, or SQL/NoSQL Injection resistance) cannot be safely verified with this demonstration API, it is explicitly classified as:

> **`NOT TESTABLE WITH SELECTED DEMO API`**

This ensures that intentional demonstration features are never misconstrued as critical production vulnerabilities.

---

## 4. Assessment Methodology

The assessment follows a structured 5-stage lifecycle adapted from the OWASP Testing Guide (OTG) and NIST SP 800-115:

```
[ Stage 1: Reconnaissance & Target Scope Definition ]
                         │
                         ▼
[ Stage 2: Passive Documentation & Contract Review ]
                         │
                         ▼
[ Stage 3: Automated Read-Only Audit Execution (Python Tool) ]
                         │
                         ▼
[ Stage 4: Defensive Header, PII, & Architectural Analysis ]
                         │
                         ▼
[ Stage 5: Risk Classification, Remediation, & Reporting ]
```

### Stage 1: Reconnaissance & Target Scope Definition
Target endpoints are selected to represent core REST API patterns: collections, individual resource lookups, relational query filtering, and task records.

### Stage 2: Passive Documentation & Contract Review
Reviewing official specifications at `https://jsonplaceholder.typicode.com/guide/` to identify expected parameters, resource relationships, and intended behavior.

### Stage 3: Automated Read-Only Audit Execution
Executing `src/api_audit.py` to transmit single, controlled GET requests with a strict 5.0-second timeout, polite inter-request delays (0.5s), and non-redirect chasing.

### Stage 4: Defensive Analysis
Inspecting HTTP response codes, headers, and bodies:
- **Header checks:** Missing defense-in-depth headers, technology disclosure (`X-Powered-By`), caching flags.
- **Body checks:** Data structure, field breadth, presence of synthetic contact details (email, phone, address, geolocation).
- **Traffic checks:** Rate-limit ceiling headers (`x-ratelimit-limit`).

### Stage 5: Risk Classification & Reporting
Categorizing all observations using transparent criteria into `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`, and `NOT TESTABLE`. Formulating practical SaaS remediation blueprints.

---

## 5. Tools & Environment Specifications

| Component | Specification / Version | Purpose |
| :--- | :--- | :--- |
| **Operating System** | Microsoft Windows 11 Pro / Enterprise | Host operating system |
| **Runtime** | Python 3.14.3 | Execution environment |
| **HTTP Client** | `requests` (v2.34.2) | Defensive GET request transport |
| **PDF Engine** | `reportlab` (v5.1.0) | Automated report compilation |
| **Testing Harness**| `unittest` (Standard Library) | Isolated test suite with mocked transports |
| **IDE** | Visual Studio Code | Code development & inspection |
| **Version Control**| Git / GitHub Desktop | Workspace change management |
| **Benchmark** | OWASP API Security Top 10 (2023) | Vulnerability mapping & taxonomy |
