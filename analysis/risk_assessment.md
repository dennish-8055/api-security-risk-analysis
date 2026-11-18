# API Security Risk Assessment & Findings

**Project:** Future Interns – Cyber Security Task 3 (2026)  
**Standard Framework:** OWASP API Security Top 10 (2023)  
**Classification Model:** Evidence-Based Severity & Likelihood Matrix  

---

## 1. Risk Evaluation Methodology

Every observation in this assessment is evaluated according to two independent dimensions:
1. **Severity (Impact):** The potential damage to confidentiality, integrity, availability, or regulatory compliance if the condition were present in a live production environment.
2. **Likelihood:** The probability of a threat actor discovering and exploiting the condition based on attack complexity, access prerequisites, and prevailing defensive controls.

### Severity Rating Definitions
* **HIGH:** Demonstrable, exploitable vulnerability resulting in immediate system compromise, unauthorized data exfiltration, or complete authentication/authorization bypass. (*Note: No HIGH findings were identified in this read-only assessment.*)
* **MEDIUM:** Security weakness that could compromise data privacy or system integrity under specific conditions (e.g., sensitive records cached on public proxies, excessive PII returned without filtering).
* **LOW:** Defense-in-depth gaps, minor security misconfigurations, or technology fingerprinting disclosures that marginally assist an attacker's reconnaissance.
* **INFORMATIONAL:** Compliant baseline controls, normal architectural design behaviors, or developer-friendly metadata.
* **NOT TESTABLE:** Security properties that cannot be validated because the target is an intentionally public, unauthenticated demonstration API or because ethical boundaries prohibited invasive testing.

---

## 2. Categorized Findings Summary

Findings are segregated into three distinct categories:
1. **Confirmed Observations:** Direct, empirically verified technical states (e.g., `X-Powered-By: Express` present, HSTS absent, `Cache-Control: max-age=43200`).
2. **Potential Real-World Risks:** Real-world architectural vulnerabilities that would emerge if these design patterns were deployed in an enterprise SaaS API (e.g., returning unmasked PII without DTO filtering, caching private records).
3. **Areas Not Testable:** Security properties that could not be tested safely or architecturally against this demonstration service (e.g., BOLA/IDOR, injection resistance).

---

## 3. Comprehensive Master Findings Table

| Finding ID | Finding Title | Affected Endpoint | Empirical Evidence | Severity | Likelihood | Business Impact | Remediation Recommendation | Testing Limitation |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **FIND-01** | **Technology Fingerprinting via X-Powered-By Header** | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Header returned: `x-powered-by: Express` across all 6 audited endpoints. | **LOW** | HIGH | Assists attackers in fingerprinting backend framework (Node.js/Express) to identify framework-specific CVEs. | Disable the header: `app.disable('x-powered-by')` or use `helmet.hidePoweredBy()`. | None. Confirmed via response header inspection across all endpoints. |
| **FIND-02** | **Missing HTTP Strict Transport Security (HSTS) Header** | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | `Strict-Transport-Security` header is absent across all 6 audited endpoints. | **LOW** | LOW | Leaves web browser clients susceptible to potential SSL stripping or initial unencrypted HTTP downgrade. | Configure edge proxy/web server: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. | None. Confirmed absent across all audited responses. |
| **FIND-03** | **Permissive Cache-Control Policy on Data Endpoints** | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Header returned: `Cache-Control: max-age=43200` (12 hours) across all 6 audited endpoints. | **LOW** *(Demo)* / **MED** *(SaaS)* | MEDIUM | Public caching is safe for mock fixtures, but caching authenticated user data in shared proxies/CDNs leaks private records. | Apply `Cache-Control: no-store, no-cache, must-revalidate, private` on all authenticated endpoints. | Assessed via header inspection. Caching is intentional on JSONPlaceholder. |
| **FIND-04** | **Simulated Excessive Data Exposure (Synthetic PII)** | `/users`, `/users/1` | Body returns unmasked fields: `email`, `phone`, `address`, `geo.lat`, `geo.lng`. | **INFORMATIONAL** *(Demo)* / **HIGH** *(SaaS)* | N/A | Harmless on mock data; in production, exposing complete customer PII without filtering violates GDPR/CCPA & OWASP API3. | Implement strict Data Transfer Objects (DTOs) and field serializers to return only requested fields. | Data is synthetic mock fixture data. No real human PII exists on the server. |
| **FIND-05** | **Exposed Rate-Limiting Quota Metadata** | All 6 Audited Endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`, `/todos/1`) | Headers observed: `x-ratelimit-limit: 3600000` (on 5 endpoints) and `1000` (on `/todos/1`). | **INFORMATIONAL** | LOW | Transparent quota values allow attackers to calibrate scraping speeds just below blocking thresholds. | Maintain rate limits; adopt standard IETF RateLimit headers and enforce dynamic IP/token throttling. | Quota exhaustion was not attempted due to ethical read-only boundaries. |
| **FIND-06** | **Object-Level & Functional Authorization Verification** | `/posts/1`, `/users/1`, `/todos/1` | Endpoints return records to any caller without credentials. | **NOT TESTABLE** | N/A | **NOT TESTABLE WITH SELECTED DEMO API.** JSONPlaceholder has no user accounts, private tenancy, or authorization logic. | Require OAuth 2.0 access tokens and enforce contextual ownership checks (`resource.owner_id == caller.id`). | Marked NOT TESTABLE. Attempting authorization bypass was neither possible nor ethical. |
| **FIND-07** | **Input Validation & Injection Resistance Under Defensive Testing** | `/comments?postId=1` | Documented integer query parameter parsed normally. | **NOT TESTABLE** | N/A | **NOT TESTABLE WITH SELECTED DEMO API.** Testing was restricted to safe, documented GET queries. | Enforce strict schema validation (JSON Schema/Pydantic) and parameterized database queries. | Marked NOT TESTABLE. Active attack payloads (SQLi, NoSQLi, XSS) were strictly prohibited. |

---

## 4. In-Depth Finding Breakdowns

### 4.1 FIND-01: Technology Fingerprinting via X-Powered-By Header
* **OWASP Mapping:** API8:2023 - Security Misconfiguration | CWE-200: Exposure of Sensitive Information
* **Technical Analysis:** The Express framework, by default, appends `X-Powered-By: Express` to all outgoing HTTP responses. This was empirically verified on all 6 audited endpoints. This informs any caller that the backend is powered by Node.js and Express.
* **Threat Model:** While not an exploitable vulnerability in isolation, technical reconnaissance is the preliminary phase of targeted cyber attacks. If a zero-day vulnerability or high-severity flaw (such as prototype pollution in specific Express body parsers) is announced, automated adversary scanners can instantly isolate hosts publishing this banner.
* **Defense Justification:** Suppression of this header costs zero performance overhead and adheres to defense-in-depth principles.

### 4.2 FIND-02: Missing HTTP Strict Transport Security (HSTS) Header
* **OWASP Mapping:** API8:2023 - Security Misconfiguration | RFC 6797
* **Technical Analysis:** While TLS 1.3 encryption was confirmed during connection establishment, HSTS is absent across all 6 audited endpoint responses. When an application lacks HSTS, a user or browser client navigating to the plain HTTP URL (`http://jsonplaceholder.typicode.com`) sends an initial unencrypted HTTP request before the server responds with a 301/302 redirect to HTTPS. An active network attacker (e.g. on public Wi-Fi) can intercept this initial request and execute an SSL stripping attack.
* **Defense Justification:** HSTS permanently eliminates plaintext fallback for supporting clients.

### 4.3 FIND-03: Permissive Cache-Control Policy on Data Endpoints
* **OWASP Mapping:** API8:2023 - Security Misconfiguration | RFC 7234
* **Technical Analysis:** The response header `Cache-Control: max-age=43200` instructs downstream intermediaries (Cloudflare edge nodes, intermediate corporate web proxies, browser disk caches) to store the returned body for up to 12 hours (43,200 seconds). This header was confirmed present on all 6 endpoints.
* **Production Context Comparison:** For an open public mock API, caching is a best practice to reduce server compute load. However, this same header applied to an enterprise API endpoint returning private user records creates a critical vulnerability: shared caches (such as corporate forward proxies or shared CDN caches) may serve cached private customer data to subsequent unauthorized requesters.

### 4.4 FIND-04: Simulated Excessive Data Exposure (Synthetic PII)
* **OWASP Mapping:** API3:2023 - Broken Object Property Level Authorization
* **Technical Analysis:** When querying `/users` or `/users/1`, the response body includes not merely basic account identifiers, but complete simulated PII: personal email addresses (`Sincere@april.biz`), direct phone numbers (`1-770-736-8031 x56442`), full street addresses, zip codes, and geographic coordinates (`lat: -37.3159, lng: 81.1496`).
* **AppSec Reality:** On JSONPlaceholder, this data is 100% fictional test data. However, this endpoint architecture demonstrates a common production anti-pattern: generic database queries (`SELECT * FROM users`) returned directly to the client, relying on frontend UI code to hide sensitive fields. In production, this allows malicious callers to inspect raw API responses and harvest personal customer data.

### 4.5 FIND-05: Exposed Rate-Limiting Quota Metadata
* **OWASP Mapping:** API4:2023 - Unrestricted Resource Consumption
* **Technical Analysis:** Rate-limiting headers are exposed across all 6 endpoints. Five endpoints (`/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`) advertise `x-ratelimit-limit: 3600000`, while `/todos/1` advertises `x-ratelimit-limit: 1000`. High-volume limits or explicit decrement counters allow automated adversaries to pace their scrapers or brute-force attempts just below the throttling threshold.

### 4.6 FIND-06 & FIND-07: Architectural & Testing Boundaries (Not Testable)
* **BOLA / IDOR Verification:** JSONPlaceholder does not authenticate users, maintain tenants, or restrict records. Testing authorization bypass was neither technically possible nor ethically permissible.
* **Input Validation & Injection Resistance:** The assessment strictly adhered to read-only GET requests with documented parameters. Injecting malformed characters, SQL metacharacters, or fuzzing payloads was prohibited under the ethical rules of engagement. Both items are correctly recorded as **NOT TESTABLE WITH SELECTED DEMO API**.
