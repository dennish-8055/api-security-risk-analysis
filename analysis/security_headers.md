# HTTP Security Headers Assessment

**Target:** `https://jsonplaceholder.typicode.com`  
**Assessment Mode:** Strictly Defensive / Read-Only (HTTP GET)  
**Standard References:**  
- OWASP API Security Top 10 (2023): **API8:2023 - Security Misconfiguration**  
- RFC 6797 (HTTP Strict Transport Security)  
- RFC 7234 (HTTP/1.1 Caching)  
- W3C Cross-Origin Resource Sharing (CORS)  

---

## 1. Raw Response Headers Observed

During the execution of `src/api_audit.py`, real HTTP response headers were captured individually across all six audited endpoints. A representative sample from `GET /posts/1` is displayed below:

```http
HTTP/1.1 200 OK
Date: Wed, 18 Nov 2026 18:24:02 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
access-control-allow-credentials: true
Cache-Control: max-age=43200
etag: W/"124-yiKdLzqO5gfBrJFrcdJ8Yq0LGnU"
expires: -1
pragma: no-cache
vary: Origin, Accept-Encoding
x-content-type-options: nosniff
x-powered-by: Express
x-ratelimit-limit: 3600000
x-ratelimit-remaining: 3599999
x-ratelimit-reset: 1790812826
cf-cache-status: HIT
Server: cloudflare
CF-RAY: a5c902813b9bb251-SIN
alt-svc: h3=":443"; ma=86400
```

---

## 2. Comprehensive Header-by-Header Empirical Analysis

In strict accordance with professional AppSec auditing standards, each header statement below is validated against the actual saved header files in `results/response_headers/`.

### 2.1 Transport Layer Security & HSTS
* **Header Checked:** `Strict-Transport-Security` (HSTS)
* **Observed Status Across Endpoints:** **ABSENT ON ALL 6 AUDITED ENDPOINTS**  
  (Verified absent in: `posts_headers.json`, `posts_1_headers.json`, `users_headers.json`, `users_1_headers.json`, `comments_postId_1_headers.json`, `todos_1_headers.json`).
* **Technical Function:** HSTS instructs conforming web browsers that all future communications with the host domain must be strictly conducted over HTTPS, automatically upgrading HTTP links and preventing SSL stripping / man-in-the-middle (MitM) attacks.
* **AppSec Evaluation:**  
  * While the audited connection was established over TLS/HTTPS, the absence of the HSTS header allows initial plaintext requests to reach the server before redirecting.
  * *Relevance Context:* HSTS is enforced by web browsers. Pure native/programmatic API clients (e.g., Python `requests`, iOS/Android mobile networking stacks) with hardcoded HTTPS URLs ignore HSTS headers. However, if web applications consume this API directly within a browser context, HSTS is a critical defense-in-depth measure.
  * **Classification:** **LOW Severity** (Defense-in-depth observation).

### 2.2 MIME Sniffing Prevention
* **Header Checked:** `X-Content-Type-Options`
* **Observed Status Across Endpoints:** **PRESENT ON ALL 6 AUDITED ENDPOINTS** (`x-content-type-options: nosniff`).
* **Technical Function:** Prevents web browsers from trying to "mime-sniff" the content type away from the declared `Content-Type` header (e.g., executing a JSON or text response as HTML/JavaScript if malicious code is embedded).
* **AppSec Evaluation:**  
  * **Positive Security Finding.** This configuration properly prevents legacy browser MIME confusion attacks.
  * **Classification:** **INFORMATIONAL (Compliant Baseline Control)**.

### 2.3 Content Security Policy (CSP)
* **Header Checked:** `Content-Security-Policy` (CSP)
* **Observed Status Across Endpoints:** **ABSENT ON ALL 6 AUDITED ENDPOINTS**.
* **Technical Function:** Defines allowed sources of scripts, styles, frames, and images to prevent Cross-Site Scripting (XSS) and clickjacking.
* **AppSec Evaluation:**  
  * CSP is primarily an HTML rendering defense for user-facing web pages. Pure REST JSON APIs returning `Content-Type: application/json` are not parsed as HTML documents by standard modern browsers.
  * However, enterprise API hardening standards (such as OWASP Secure Headers) recommend sending `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on JSON APIs as defense-in-depth to protect against edge cases where raw JSON endpoints are opened directly in browser tabs.
  * **Classification:** **INFORMATIONAL / LOW (Defense-in-Depth)**.

### 2.4 Caching Policy (Cache-Control & Pragma)
* **Header Checked:** `Cache-Control`
* **Observed Status Across Endpoints:** **PRESENT ON ALL 6 AUDITED ENDPOINTS** (`max-age=43200`, which equates to 12 hours).
* **Related Headers:** `pragma: no-cache`, `expires: -1`, `cf-cache-status: HIT`.
* **Technical Function:** Controls whether responses may be stored by intermediate web caches, CDNs, corporate proxy servers, or local client storage.
* **AppSec Evaluation:**  
  * For JSONPlaceholder, caching static mock data at Cloudflare edge nodes for 12 hours (`max-age=43200`) is efficient and intentional.
  * *Production Risk Translation:* In an enterprise SaaS API, if endpoints returning authenticated user data (such as `/users/1` or `/billing`) include permissive caching without `no-store` or `private`, intermediate caches or shared proxy caches may store sensitive customer data, allowing other users on the same proxy to retrieve cached personal records.
  * **Classification:** **LOW Severity** (Appropriate for demo API; caution for production).

### 2.5 Technology Stack Disclosure (Information Fingerprinting)
* **Headers Checked:** `Server`, `X-Powered-By`, `Via`
* **Observed Values Across Endpoints:**
  * `Server: cloudflare` (Present on all 6 endpoints)
  * `x-powered-by: Express` (Present on all 6 endpoints)
  * `via: 2.0 heroku-router` (Observed specifically on `GET /todos/1`, revealing backend hosting topology)
* **Technical Function:** Identifies the edge reverse proxy, hosting provider, and underlying application framework running on Node.js.
* **AppSec Evaluation:**  
  * Exposing `x-powered-by: Express` violates the principle of minimal information disclosure (CWE-200). While knowing the framework is not an exploitable vulnerability in itself, it gives potential adversaries an initial reconnaissance advantage, allowing them to search for Express-specific middleware flaws, prototype pollution CVEs, or version-specific bugs.
  * **Classification:** **LOW Severity** (CWE-200 Information Exposure).

### 2.6 Cross-Origin Resource Sharing (CORS) Configuration
* **Headers Checked:** `access-control-allow-credentials: true`, `vary: Origin, Accept-Encoding`
* **Observed Status Across Endpoints:** Present on all 6 endpoints.
* **Technical Function:** Dictates whether cross-origin web browsers can access the API response and whether credentials (cookies, authorization headers) can be shared across domains.
* **AppSec Evaluation:**  
  * In JSONPlaceholder, setting `access-control-allow-credentials: true` enables browser-based frontend applications (e.g. React, Vue, Angular demos on localhost or GitHub Pages) to consume test data.
  * In a production API, pairing `access-control-allow-credentials: true` with a reflected origin or wildcard (`*`) is a high-severity vulnerability that permits malicious third-party websites to extract private user data via cross-site requests.
  * **Classification:** **INFORMATIONAL (Permissive for public demo; requires strict origin whitelist in production)**.

### 2.7 Rate-Limiting Headers
* **Headers Checked:** `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`
* **Observed Values Across Endpoints:**
  * `/posts`, `/posts/1`, `/users`, `/users/1`, `/comments?postId=1`: `x-ratelimit-limit: 3600000` (3.6 million requests per quota window)
  * `/todos/1`: `x-ratelimit-limit: 1000` (1,000 requests per quota window via Heroku router)
* **AppSec Evaluation:**  
  * Rate-limiting headers are actively returned across all endpoints. The variation illustrates different infrastructure routing tiers (Cloudflare edge caching vs Heroku backend container routing).
  * Exposing quota numbers is developer-friendly, but production APIs should monitor abuse patterns and return RFC 7231 `Retry-After` upon threshold breaches.
  * **Classification:** **INFORMATIONAL**.

---

## 3. Security Headers Compliance Summary Table

| Header Name | Verified Presence on Audited Endpoints | Observed Value(s) | Expected SaaS Baseline | Risk Severity | Context & Impact |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Strict-Transport-Security** | **Absent on all 6 endpoints** | *None* | `max-age=31536000; includeSubDomains; preload` | **LOW** | Prevents SSL stripping / protocol downgrade in browsers |
| **X-Content-Type-Options** | **Present on all 6 endpoints** | `nosniff` | `nosniff` | **COMPLIANT** | Properly blocks MIME confusion attacks |
| **Content-Security-Policy** | **Absent on all 6 endpoints** | *None* | `default-src 'none'; frame-ancestors 'none'` | **INFORMATIONAL** | Hardens endpoint if loaded directly in browser context |
| **Cache-Control** | **Present on all 6 endpoints** | `max-age=43200` | `no-store, no-cache, private` | **LOW** | 12h public cache is safe for mock, high-risk for private SaaS |
| **X-Powered-By** | **Present on all 6 endpoints** | `Express` | *Suppressed / Removed* | **LOW** | Leaks Node.js Express framework identity (CWE-200) |
| **Server** | **Present on all 6 endpoints** | `cloudflare` | Generic / Obfuscated | **INFORMATIONAL** | Cloudflare edge identification is standard for CDN protection |
| **Via** | **Present on /todos/1** | `2.0 heroku-router` | *Suppressed / Removed* | **LOW** | Reveals Heroku backend hosting infrastructure |
| **Access-Control-Allow-Credentials**| **Present on all 6 endpoints**| `true` | Whitelisted origins only | **INFORMATIONAL** | Allows web demos to fetch; must restrict in production |
| **X-RateLimit-Limit** | **Present on all 6 endpoints** | `3600000` (5 endpoints) / `1000` (`/todos/1`) | Tiered per tenant/user | **INFORMATIONAL** | Transparent quota metadata visibility |
