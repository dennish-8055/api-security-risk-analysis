# API SECURITY RISK ANALYSIS REPORT

**Future Interns – Cyber Security Task 3 (2026)**  
**Document Classification:** Confidential / Security Assessment Report  
**Date of Assessment:** November 2026  
**Auditor / Security Engineer:** Future Interns Cyber Security Assessment Team  
**Assessment Target:** JSONPlaceholder RESTful API (`https://jsonplaceholder.typicode.com`)  
**Assessment Type:** Defensive, Read-Only API Security Risk Assessment  
**Reference Framework:** OWASP API Security Top 10 (2023) & Shieldfy API Security Checklist  

---

## 1. Cover Page

```
========================================================================================
                          FUTURE INTERNS - CYBER SECURITY
                            INTERNSHIP PROGRAM 2026

                       API SECURITY RISK ANALYSIS REPORT
                 DEFENSIVE APPLICATION PROGRAMMING INTERFACE AUDIT

          Target System:        JSONPlaceholder REST API
          Domain:               https://jsonplaceholder.typicode.com
          Assessment Standard:  OWASP API Security Top 10 (2023)
          Testing Boundary:     Strictly Defensive / Read-Only (HTTP GET)
          Assessment Date:      November 2026
          Lead Auditor:         Senior AppSec Engineer / Security Auditor
          Deliverable Status:   Final Deliverable (Task 3)
========================================================================================
```

---

## 2. Executive Summary

During November 2026, a defensive, read-only API security risk assessment was conducted against the public JSONPlaceholder REST demonstration service (`https://jsonplaceholder.typicode.com`). The objective of this engagement was to evaluate core API design patterns, transport and response header security, data minimization policies, error handling, rate-limiting exposure, and authorization boundaries using the **OWASP API Security Top 10 (2023)** benchmark.

### Key Assessment Findings:
1. **Public Demonstration Target Architecture:** JSONPlaceholder is an intentionally public, static, stateless demonstration API designed for frontend prototyping and developer education. It does not maintain private user accounts, financial records, or operational databases.
2. **Read-Only Scope Compliance:** All audit operations strictly complied with ethical testing rules. Only six safe, controlled HTTP GET requests were issued via a custom Python security audit tool (`src/api_audit.py`). No exploitation, authentication bypass attempts, credential attacks, or denial-of-service activities were conducted.
3. **Identified Defense-in-Depth Opportunities (LOW Severity):**
   * **Technology Disclosure (CWE-200):** Outgoing HTTP responses explicitly disclose the backend framework via `X-Powered-By: Express` across all 6 audited endpoints, and `Via: 2.0 heroku-router` on `/todos/1`.
   * **Missing HSTS (RFC 6797):** The `Strict-Transport-Security` header is absent across all 6 audited endpoints, allowing browser clients to attempt initial unencrypted HTTP connections.
   * **Permissive Caching:** All 6 data endpoints return `Cache-Control: max-age=43200` (12-hour public cache), which is acceptable for static mock data but poses severe data-leakage risks if replicated in an authenticated production SaaS API.
4. **Data Minimization Observations (INFORMATIONAL):** Endpoints `/users` and `/users/1` return complete synthetic user records including mock emails, telephone numbers, street addresses, and GPS coordinates without field masking. While harmless on synthetic data, this mirrors production **Excessive Data Exposure (OWASP API3:2023)**.
5. **Rate-Limiting Exposure (INFORMATIONAL):** Rate-limiting metadata is actively published on all 6 endpoints: `/posts`, `/posts/1`, `/users`, `/users/1`, and `/comments?postId=1` advertise a limit of `3,600,000`, while `/todos/1` advertises `1,000` via Heroku.
6. **Architectural Boundaries (NOT TESTABLE):** Verification of **Broken Object Level Authorization (BOLA / OWASP API1:2023)**, Broken Authentication (OWASP API2:2023), and injection resistance (OWASP API8:2023) was classified as **NOT TESTABLE WITH SELECTED DEMO API** because the target lacks authentication mechanisms and active injection testing was excluded under ethical rules.

Overall, the demonstration API functions securely within its intended public educational scope. A twelve-point enterprise remediation plan is provided to guide production SaaS implementations.

---

## 3. Assessment Objectives

The primary objectives of this security engagement were:
* **Validate Defensive Read-Only Methodology:** Demonstrate how a cybersecurity auditor can safely inspect and baseline an external REST API without executing intrusive, destructive, or prohibited attacks.
* **Inspect HTTP Response Security Headers:** Evaluate the presence and configuration of modern defense-in-depth headers including HSTS, CSP, X-Content-Type-Options, and Cache-Control.
* **Analyze Data Minimization & PII Handling:** Identify how structured data is returned and determine whether sensitive fields (such as phone numbers, emails, and geolocation) are filtered or masked.
* **Review Rate Limiting Transparency:** Passively inspect response headers for quota metadata and throttling enforcement indicators.
* **Map Observations to OWASP API Security Top 10:** Categorize all technical observations against industry-recognized threat categories.
* **Formulate SaaS Remediation Blueprints:** Deliver concrete, actionable guidance explaining both the technical implementation and the executive business benefits for real-world production platforms.

---

## 4. API Overview

**Target Host:** `https://jsonplaceholder.typicode.com`  
**Provider / Maintainer:** Typicode  
**Official Documentation:** [https://jsonplaceholder.typicode.com/guide/](https://jsonplaceholder.typicode.com/guide/)  
**Infrastructure Stack:** Hosted behind Cloudflare edge reverse proxies with backend services powered by Node.js and Express. Certain endpoints (such as `/todos/1`) route through Heroku router containers (`via: 2.0 heroku-router`).  
**Functional Purpose:** JSONPlaceholder is an open, free, online REST API that developers can use whenever they need mock data for testing web applications, mobile apps, tutorials, and scripts without deploying a custom backend.

---

## 5. Scope and Authorization

### 5.1 In-Scope Target Endpoints
The scope of this assessment was strictly limited to the following six documented GET endpoints:
1. `GET /posts` (Collection of 100 mock post entities)
2. `GET /posts/1` (Single post entity lookup)
3. `GET /users` (Collection of 10 mock user profiles)
4. `GET /users/1` (Single user profile entity lookup)
5. `GET /comments?postId=1` (Relational query-filtered comment collection)
6. `GET /todos/1` (Single todo task item lookup)

### 5.2 Ethical Boundary Rules
* **Strict Read-Only Operations:** No state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) were transmitted.
* **No Authentication Bypass or Brute Force:** No credential stuffing, dictionary attacks, or token tampering.
* **No Denial-of-Service (DoS):** Requests were limited to single queries spaced with polite delays (0.5s) and a 10.0-second timeout.
* **No Injection Attacks:** No SQL, NoSQL, or XSS payloads were injected into query parameters.
* **No Private Systems:** No private corporate endpoints or production databases were probed.

---

## 6. Tools Used

| Tool / Technology | Version | Purpose in Assessment |
| :--- | :--- | :--- |
| **Python** | 3.14.3 | Core runtime environment for automated security audit tools |
| **Python Requests** | 2.34.2 | Synchronous HTTP client library configured for safe, read-only GET requests |
| **ReportLab** | 5.1.0 | Programmatic PDF report generation engine |
| **Python unittest** | Built-in | Automated unit test suite with mocked network transports |
| **Visual Studio Code** | 1.95+ | Integrated development and code analysis environment |
| **GitHub Desktop** | Latest | Version control management and workspace tracking |
| **OWASP API Security Top 10** | 2023 Edition | Reference vulnerability standard and taxonomy |

---

## 7. Methodology

The assessment followed an adapted, defensive five-phase methodology:

```
[ Phase 1: Passive Reconnaissance & Documentation Review ]
                             │
                             ▼
[ Phase 2: Defensive Audit Tool Architecture (Python Tool Development) ]
                             │
                             ▼
[ Phase 3: Controlled Read-Only Execution & Evidence Capture ]
                             │
                             ▼
[ Phase 4: Security Inspection & Risk Classification ]
                             │
                             ▼
[ Phase 5: Production SaaS Remediation Architecture & Reporting ]
```

1. **Reconnaissance:** Reviewed published schema guides at `https://jsonplaceholder.typicode.com/guide/` to establish baseline expectations.
2. **Tool Architecture:** Developed `src/api_audit.py`, `src/security_checks.py`, and `src/risk_classifier.py` featuring strict host validation, non-redirect chasing, and graceful error trapping.
3. **Controlled Execution:** Issued single GET requests to the six designated endpoints, capturing raw response bodies into `results/api_responses/` and headers into `results/response_headers/`.
4. **Security Inspection:** Evaluated response headers, body data structures, and status codes.
5. **Remediation & Reporting:** Synthesized findings, applied the "Not Testable" rule where applicable, and compiled this formal audit report.

---

## 8. Endpoints Tested

The table below summarizes the technical specifications of all audited endpoints:

| Endpoint Path | HTTP Method | Target Purpose | Parameter Type | Documented Return Type |
| :--- | :---: | :--- | :--- | :--- |
| `/posts` | `GET` | List all blog post records | None | Array of 100 Post Objects |
| `/posts/1` | `GET` | Retrieve single post by ID | Path variable (`/1`) | Single Post Object |
| `/users` | `GET` | List all user profile entities | None | Array of 10 User Objects |
| `/users/1` | `GET` | Retrieve single user profile by ID | Path variable (`/1`) | Single User Object |
| `/comments?postId=1` | `GET` | List comments filtered by post ID | Query string (`postId=1`) | Array of 5 Comment Objects |
| `/todos/1` | `GET` | Retrieve single todo record by ID | Path variable (`/1`) | Single Todo Object |

---

## 9. Observed Results

All requests completed successfully with HTTP status code `200 OK`. The empirical measurements recorded during the audit are presented below:

| Endpoint | Status Code | Content-Type | Response Size (Bytes) | Response Time (ms) | Content Structure |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **GET /posts** | `200 OK` | `application/json; charset=utf-8` | 27,520 B | 511.5 ms | Array of 100 objects |
| **GET /posts/1** | `200 OK` | `application/json; charset=utf-8` | 292 B | 94.4 ms | Single object (4 keys: userId, id, title, body) |
| **GET /users** | `200 OK` | `application/json; charset=utf-8` | 5,645 B | 63.7 ms | Array of 10 objects |
| **GET /users/1** | `200 OK` | `application/json; charset=utf-8` | 509 B | 88.9 ms | Single object (nested PII) |
| **GET /comments?postId=1** | `200 OK` | `application/json; charset=utf-8` | 1,510 B | 89.3 ms | Array of 5 objects |
| **GET /todos/1** | `200 OK` | `application/json; charset=utf-8` | 83 B | 128.2 ms | Single object (4 keys: userId, id, title, completed) |

---

## 10. Authentication Assessment

### 10.1 Observations
* **Authentication Requirement:** Unauthenticated. All six endpoints responded immediately without requiring credentials.
* **Token Exchanges:** The service does not issue, accept, or validate Bearer JWTs, OAuth 2.0 tokens, API keys, or session cookies.
* **Authentication Strength:** **NOT TESTABLE WITH SELECTED DEMO API**. Token entropy, expiration lifetimes, signing algorithm integrity, and password hashing policies could not be evaluated because no authentication layer exists.

### 10.2 Analysis & SaaS Context
While unauthenticated access is intentional for a public prototyping API, deploying an unauthenticated API in an enterprise production environment constitutes **OWASP API2:2023 - Broken Authentication**, allowing anonymous actors to exfiltrate proprietary data with zero accountability.

---

## 11. Authorization Assessment

### 11.1 Broken Object Level Authorization (BOLA / OWASP API1:2023)
* **Observation:** Any user ID (`/users/1`, `/users/2`, `/users/3`) or post ID can be queried sequentially without permission checks.
* **AppSec Evaluation:** In a production application handling private user accounts, sequential access without contextual ownership verification (`resource.owner_id == caller.id`) is a critical BOLA vulnerability.
* **Audit Limitation:** Validating BOLA requires comparing access across two distinct authenticated user sessions. Because JSONPlaceholder has no user accounts or authorization engine, this property is classified as **NOT TESTABLE WITH SELECTED DEMO API**.

### 11.2 Broken Function Level Authorization (BFLA / OWASP API5:2023)
* **Observation:** No administrative endpoints or privilege hierarchies exist on the demo host.
* **Audit Limitation:** Marked **NOT TESTABLE WITH SELECTED DEMO API**.

---

## 12. Data Exposure Assessment

### 12.1 Excessive Data Exposure & Data Minimization
* **Observation on `/users` and `/users/1`:** The responses return complete user records containing deeply nested simulated Personally Identifiable Information (PII):
  * Personal email addresses (`Sincere@april.biz`)
  * Telephone numbers (`1-770-736-8031 x56442`)
  * Physical street addresses (`Kulas Light, Apt. 556, Gwenborough`)
  * GPS coordinates (`lat: -37.3159, lng: 81.1496`)
* **Evaluation:**
  * **On JSONPlaceholder:** This data is entirely synthetic mock data created for frontend UI prototyping; no real personal data exists or is breached (**INFORMATIONAL**).
  * **Production SaaS Analogy:** Returning raw, unmasked customer database records without filtering via Data Transfer Objects (DTOs) violates **OWASP API3:2023 (Broken Object Property Level Authorization)** and privacy regulations (GDPR Article 5(1)(c) Data Minimisation, CCPA).

---

## 13. Rate-Limiting Assessment

### 13.1 Quota Metadata Observations
* **Headers Observed:**
  * `/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`: `x-ratelimit-limit: 3600000`
  * `/todos/1`: `x-ratelimit-limit: 1000`
* **Evaluation:**
  * Rate-limiting headers are actively published across all endpoints.
  * While transparent headers aid legitimate developers, exposing exact decrement counters allows malicious automated scrapers to pace their requests just below blocking thresholds (**INFORMATIONAL**).
* **Testing Limitation:** Deliberately sending thousands of requests to trigger rate limiting was strictly prohibited under ethical testing boundaries. Actual enforcement under high concurrency was **NOT TESTABLE WITH SELECTED DEMO API**.

---

## 14. Input Validation Assessment

### 14.1 Query Parameter Validation
* **Observation on `/comments?postId=1`:** The endpoint accepted and parsed the integer query parameter `postId=1` normally, returning five matching comment objects.
* **Production Analogy:** In production, unvalidated query parameters can expose APIs to SQL injection, NoSQL query-parser injection, or Server-Side Request Forgery (SSRF).
* **Testing Limitation:** In strict adherence to defensive read-only rules, no active injection payloads (`' OR 1=1--`, `<script>`, or malformed types) were transmitted. Marked **NOT TESTABLE WITH SELECTED DEMO API**.

---

## 15. Security Headers Assessment

The table below presents the compliance status of HTTP security headers across all audited endpoints:

| Header Name | Verified Presence on Audited Endpoints | Observed Value(s) | Expected SaaS Baseline | Status / Severity | AppSec Impact Analysis |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Strict-Transport-Security** | **Absent on all 6 endpoints** | *None* | `max-age=31536000; includeSubDomains; preload` | **LOW** | Browser clients lack instructions to enforce HTTPS permanently; vulnerable to SSL stripping on initial connection. |
| **X-Content-Type-Options** | **Present on all 6 endpoints** | `nosniff` | `nosniff` | **COMPLIANT** | Properly instructs browsers not to sniff MIME types away from declared `application/json`. |
| **Content-Security-Policy** | **Absent on all 6 endpoints** | *None* | `default-src 'none'; frame-ancestors 'none'` | **INFORMATIONAL** | CSP is primarily an HTML browser defense; recommended as defense-in-depth on JSON endpoints. |
| **Cache-Control** | **Present on all 6 endpoints** | `max-age=43200` | `no-store, no-cache, private` | **LOW** *(Demo)* / **MED** *(SaaS)* | Responses cached in shared proxies for 12 hours. Benign for mock data; critical data-leakage risk for private user data. |
| **X-Powered-By** | **Present on all 6 endpoints** | `Express` | *Suppressed / Removed* | **LOW** | Discloses underlying runtime technology (Node.js/Express), facilitating framework-specific adversary reconnaissance. |
| **Server** | **Present on all 6 endpoints** | `cloudflare` | Generic / Obfuscated | **INFORMATIONAL** | Standard edge CDN reverse proxy identifier. |
| **Via** | **Present on /todos/1** | `2.0 heroku-router` | *Suppressed / Removed* | **LOW** | Discloses Heroku router backend routing container. |
| **Access-Control-Allow-Credentials**| **Present on all 6 endpoints** | `true` | Explicit origin whitelist | **INFORMATIONAL** | Enables cross-origin test apps to fetch data; must be strictly origin-bound in production. |

---

## 16. Risk Classification Table

The master findings table below summarizes all observations, categorizing each into confirmed findings, potential real-world risks, and testing limitations:

| Finding ID | Finding Title | Affected Endpoint | Empirical Evidence | Severity | Likelihood | Business Impact | Remediation Recommendation | Testing Limitation |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **FIND-01** | Technology Fingerprinting via X-Powered-By Header | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Header returned: `x-powered-by: Express` across all 6 audited endpoints. | **LOW** | HIGH | Assists attackers in fingerprinting backend framework (Node.js/Express) to identify framework-specific CVEs. | Disable the header: `app.disable('x-powered-by')` or use `helmet.hidePoweredBy()`. | None. Confirmed via response header inspection across all endpoints. |
| **FIND-02** | Missing HTTP Strict Transport Security (HSTS) Header | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | `Strict-Transport-Security` header is absent across all 6 audited endpoints. | **LOW** | LOW | Leaves web browser clients susceptible to potential SSL stripping or initial unencrypted HTTP downgrade. | Configure edge proxy/web server: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. | None. Confirmed absent across all audited responses. |
| **FIND-03** | Permissive Cache-Control Policy on Data Endpoints | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Header returned: `Cache-Control: max-age=43200` (12 hours) across all 6 audited endpoints. | **LOW** *(Demo)* / **MED** *(SaaS)* | MEDIUM | Public caching is safe for mock fixtures, but caching authenticated user data in shared proxies/CDNs leaks private records. | Apply `Cache-Control: no-store, no-cache, must-revalidate, private` on all authenticated endpoints. | Assessed via header inspection. Caching is intentional on JSONPlaceholder. |
| **FIND-04** | Simulated Excessive Data Exposure (Synthetic PII) | `/users`, `/users/1` | Body returns unmasked fields: `email`, `phone`, `address`, `geo.lat`, `geo.lng`. | **INFORMATIONAL** *(Demo)* / **HIGH** *(SaaS)* | N/A | Harmless on mock data; in production, exposing complete customer PII without filtering violates GDPR/CCPA & OWASP API3. | Implement strict Data Transfer Objects (DTOs) and field serializers to return only requested fields. | Data is synthetic mock fixture data. No real human PII exists on the server. |
| **FIND-05** | Exposed Rate-Limiting Quota Metadata | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Headers observed: `x-ratelimit-limit: 3600000` (on 5 endpoints) and `1000` (on `/todos/1`). | **INFORMATIONAL** | LOW | Transparent quota values allow attackers to calibrate scraping speeds just below blocking thresholds. | Maintain rate limits; adopt standard IETF RateLimit headers and enforce dynamic IP/token throttling. | Quota exhaustion was not attempted due to ethical read-only boundaries. |
| **FIND-06** | Object-Level & Functional Authorization Verification | `/posts/1`, `/users/1`, `/todos/1` | Endpoints return records to any caller without credentials. | **NOT TESTABLE** | N/A | **NOT TESTABLE WITH SELECTED DEMO API.** JSONPlaceholder has no user accounts, private tenancy, or authorization logic. | Require OAuth 2.0 access tokens and enforce contextual ownership checks (`resource.owner_id == caller.id`). | Marked NOT TESTABLE. Attempting authorization bypass was neither possible nor ethical. |
| **FIND-07** | Input Validation & Injection Resistance Under Defensive Testing | `/comments?postId=1` | Documented integer query parameter parsed normally. | **NOT TESTABLE** | N/A | **NOT TESTABLE WITH SELECTED DEMO API.** Testing was restricted to safe, documented GET queries. | Enforce strict schema validation (JSON Schema/Pydantic) and parameterized database queries. | Marked NOT TESTABLE. Active attack payloads (SQLi, NoSQLi, XSS) were strictly prohibited. |

---

## 17. Business Impact

In cybersecurity auditing, technical findings must be articulated in terms of real-world business risk:

1. **Reputational & Customer Trust Risk:** Exposing customer personal details (PII) or business records via unauthenticated endpoints or broken object authorization (BOLA) leads to high-profile data breaches, public disclosure notices, and immediate loss of customer confidence.
2. **Regulatory & Financial Penalties:** Under privacy mandates such as GDPR (Article 83), fines for inadequate technical safeguards and data minimization failures can reach up to €20 million or 4% of global annual turnover. CCPA mandates statutory damages between \$100 and \$750 per consumer per incident for data exfiltration resulting from security negligence.
3. **Operational Disruption:** Inadequate rate-limiting and unbounded collection queries allow scrapers or malicious botnets to exhaust backend compute, memory, and database connection pools, causing unplanned downtime for legitimate enterprise customers.
4. **Reconnaissance Advantage to Attackers:** Publishing technology banners (`X-Powered-By: Express`, `Via: 2.0 heroku-router`) provides threat actors with free intelligence, enabling them to automate scans for framework-specific vulnerabilities.

---

## 18. Remediation Recommendations

To transition from an open mock architecture to an enterprise-grade SaaS production environment, engineering teams should implement the following twelve controls:

1. **Mandate Authentication:** Protect all non-public endpoints using OAuth 2.0 / OpenID Connect access tokens.
2. **Issue Short-Lived Access Tokens:** Use 15-minute JWTs signed with asymmetric keys (`RS256`), supported by secure refresh token rotation.
3. **Enforce Contextual Object-Level Authorization:** Check on every request that `resource.owner_id == current_user.id` or `resource.tenant_id == current_user.tenant_id`.
4. **Enforce Data Minimization via DTOs:** Never serialize raw database entities directly to the client; filter responses through strict schemas and mask PII fields.
5. **Apply Multi-Tiered Rate Limiting:** Enforce token-bucket throttling at the API Gateway (e.g. 10 req/min unauthenticated, 120 req/min authenticated) and return HTTP `429 Too Many Requests`.
6. **Validate Input with Strict Schemas:** Validate all query parameters, path variables, and request bodies using allowlist schemas (e.g., Pydantic or JSON Schema) and parameterized database queries.
7. **Restrict CORS Configurations:** Replace permissive origin policies with an explicit allowlist of authorized origin domains; never pair `allow-credentials: true` with a wildcard.
8. **Enforce Transport Security (HSTS):** Deploy `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` and enforce TLS 1.3 exclusively.
9. **Suppress Technology Disclosure Banners:** Strip `X-Powered-By` in application framework configuration and edge reverse proxies.
10. **Implement Secure, Masked Logging:** Record security events (failed logins, 403 authorization denials, 429 rate limit trips) while automatically scrubbing tokens, passwords, and PII from log pipelines.
11. **Standardize Error Handling:** Adopt RFC 7807 (Problem Details for HTTP APIs); never return raw database exceptions, stack traces, or internal server paths.
12. **Maintain OpenAPI Specifications & CI/CD Security Gates:** Keep OpenAPI 3.1 contracts updated and integrate automated API security linting into continuous deployment pipelines.

---

## 19. Testing Limitations

This assessment was governed by strict ethical and technical boundaries:
* **Target Environment Constraints:** JSONPlaceholder is an open, unauthenticated mock REST server. It possesses no user accounts, private records, or access control engines.
* **Read-Only Engagement Rules:** No state-altering requests (`POST`, `PUT`, `PATCH`, `DELETE`) were issued.
* **No Active Penetration Testing:** Exploitation, credential stuffing, brute-forcing, injection attacks, and denial-of-service testing were excluded by design.
* **Synthetic Data Boundary:** All analyzed records were simulated test fixtures; no genuine human personal data was accessed.
* **Empirical Integrity:** All properties that could not be evaluated safely were classified as **NOT TESTABLE WITH SELECTED DEMO API**. No results, vulnerabilities, or headers were invented.

---

## 20. Conclusion

This API security risk analysis successfully demonstrated how an Application Security engineer conducts a thorough, defensive, read-only evaluation of an external RESTful API.

By inspecting real response headers, analyzing JSON payload structures, and building an automated Python audit tool (`src/api_audit.py`), the assessment identified practical configuration observations (such as `X-Powered-By` disclosure, absence of HSTS, and permissive caching) while clearly distinguishing between intentional mock demonstration design and critical production vulnerabilities.

Adhering to the twelve-point remediation plan will enable engineering organizations to design, deploy, and maintain robust, resilient, and compliant RESTful APIs.

---

## 21. References

1. **OWASP API Security Project (2023):**  
   [https://github.com/OWASP/API-Security](https://github.com/OWASP/API-Security)
2. **Shieldfy API Security Checklist:**  
   [https://github.com/shieldfy/API-Security-Checklist](https://github.com/shieldfy/API-Security-Checklist)
3. **JSONPlaceholder Official Documentation & Guide:**  
   [https://jsonplaceholder.typicode.com/guide/](https://jsonplaceholder.typicode.com/guide/)
4. **RFC 6797: HTTP Strict Transport Security (HSTS):**  
   [https://datatracker.ietf.org/doc/html/rfc6797](https://datatracker.ietf.org/doc/html/rfc6797)
5. **RFC 7234: Hypertext Transfer Protocol (HTTP/1.1): Caching:**  
   [https://datatracker.ietf.org/doc/html/rfc7234](https://datatracker.ietf.org/doc/html/rfc7234)
6. **RFC 7807: Problem Details for HTTP APIs:**  
   [https://datatracker.ietf.org/doc/html/rfc7807](https://datatracker.ietf.org/doc/html/rfc7807)
7. **NIST SP 800-115: Technical Guide to Information Security Testing and Assessment:**  
   [https://csrc.nist.gov/publications/detail/sp/800-115/final](https://csrc.nist.gov/publications/detail/sp/800-115/final)
