# Endpoint Security Analysis

**Target Host:** `https://jsonplaceholder.typicode.com`  
**Assessment Mode:** Strictly Defensive / Read-Only (HTTP GET)  
**Total Endpoints Audited:** 6 Endpoints  

---

## 1. Executive Summary of Audited Endpoints

The audit evaluated six representative endpoints illustrating core architectural RESTful patterns:
1. **Unfiltered Collection Retrieval** (`/posts`, `/users`)
2. **Direct Object Identifier Lookup** (`/posts/1`, `/users/1`, `/todos/1`)
3. **Query Parameter Relational Filtering** (`/comments?postId=1`)

Every request returned HTTP `200 OK` with JSON payloads (`application/json; charset=utf-8`). The sections below present empirical measurements and AppSec evaluations for each endpoint.

---

## 2. Comprehensive Endpoint Profiles

### 2.1 Endpoint: GET /posts

* **Full URL:** `https://jsonplaceholder.typicode.com/posts`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 27,520 bytes (27.5 KB)
* **Response Structure:** Array of 100 JSON objects. Each object contains four fields:
  ```json
  {
    "userId": "integer",
    "id": "integer",
    "title": "string",
    "body": "string"
  }
  ```
* **Authentication Required:** No. Publicly accessible without tokens, cookies, or API keys.
* **Sensitive-Looking Fields Returned:** None observed. Content consists of simulated Latin dummy text (*Lorem Ipsum* style).
* **Security Observations:**
  * Endpoint returns all 100 records in a single payload without mandatory pagination (`limit`, `offset`, or `page` cursors).
  * In a production SaaS environment, unbounded collection queries can lead to **Unrestricted Resource Consumption (OWASP API4:2023)**, allowing scrapers or malicious clients to exhaust database and network throughput.
  * In JSONPlaceholder, this behavior is intentional as a static mock fixture for UI prototyping.
* **Testing Limitations:**
  * Stress testing with high-volume collection requests was prohibited by ethical testing rules.

---

### 2.2 Endpoint: GET /posts/1

* **Full URL:** `https://jsonplaceholder.typicode.com/posts/1`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 292 bytes
* **Response Structure:** Single JSON object:
  ```json
  {
    "userId": 1,
    "id": 1,
    "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
    "body": "quia et suscipit\nsuscipit recusandae consequuntur..."
  }
  ```
* **Authentication Required:** No.
* **Sensitive-Looking Fields Returned:** None.
* **Security Observations:**
  * Uses sequential, predictable integer IDs (`id: 1`). In production applications, sequential integer keys facilitate trivial resource enumeration and scraping.
  * Modern production APIs typically employ non-sequential identifiers (such as UUIDv4 or ULID) alongside strict access-control checks.
* **Testing Limitations:**
  * Verifying Broken Object Level Authorization (BOLA/IDOR) was impossible because the demo API has no concept of private user ownership or access control boundaries. Marked **NOT TESTABLE WITH SELECTED DEMO API**.

---

### 2.3 Endpoint: GET /users

* **Full URL:** `https://jsonplaceholder.typicode.com/users`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 5,645 bytes (5.6 KB)
* **Response Structure:** Array of 10 complete user profile objects. Each object contains deeply nested identity attributes:
  ```json
  {
    "id": "integer",
    "name": "string",
    "username": "string",
    "email": "string",
    "address": {
      "street": "string",
      "suite": "string",
      "city": "string",
      "zipcode": "string",
      "geo": { "lat": "string", "lng": "string" }
    },
    "phone": "string",
    "website": "string",
    "company": { "name": "string", "catchPhrase": "string", "bs": "string" }
  }
  ```
* **Authentication Required:** No.
* **Sensitive-Looking Fields Returned:**
  * Email addresses (`email`)
  * Full physical mailing addresses (`address.street`, `suite`, `city`, `zipcode`)
  * GPS coordinates (`geo.lat`, `geo.lng`)
  * Direct phone numbers (`phone`)
* **Security Observations:**
  * **Excessive Data Exposure & Lack of Data Minimization:** In a production SaaS environment, returning all user profiles complete with physical addresses, phone numbers, and coordinates to any unauthenticated caller is a critical privacy breach (violating OWASP API3:2023, GDPR Article 5(1)(c), and CCPA).
  * However, for JSONPlaceholder, this is **synthetic test data**. The names, addresses, and telephone numbers are fictional fixtures designed to test frontend forms.
  * No authorization checks or field masking filters are present.
* **Testing Limitations:**
  * Verified as mock fixture data. No real human subjects or production databases were probed.

---

### 2.4 Endpoint: GET /users/1

* **Full URL:** `https://jsonplaceholder.typicode.com/users/1`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 509 bytes
* **Response Structure:** Single complete user object (Leanne Graham / Bret) with nested contact, address, GPS, and company structures.
* **Authentication Required:** No.
* **Sensitive-Looking Fields Returned:** Full synthetic PII set:
  * Name: `Leanne Graham`
  * Email: `Sincere@april.biz`
  * Phone: `1-770-736-8031 x56442`
  * Address: `Kulas Light, Apt. 556, Gwenborough 92998-3874`
  * Coordinates: `lat: -37.3159, lng: 81.1496`
* **Security Observations:**
  * Demonstrates how an API can return an entire database record directly without passing through a Data Transfer Object (DTO) or serializer filter.
  * If replicated in production, any user could view any other user's private home address and phone number simply by altering the URL integer parameter (`/users/2`, `/users/3`), which represents classic **Broken Object Level Authorization (BOLA / OWASP API1:2023)**.
* **Testing Limitations:**
  * Marked **NOT TESTABLE WITH SELECTED DEMO API** for real vulnerability confirmation, because JSONPlaceholder does not maintain private user accounts or access tokens.

---

### 2.5 Endpoint: GET /comments?postId=1

* **Full URL:** `https://jsonplaceholder.typicode.com/comments?postId=1`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 1,510 bytes (1.5 KB)
* **Response Structure:** Array of 5 comment objects associated with `postId: 1`:
  ```json
  {
    "postId": 1,
    "id": "integer",
    "name": "string",
    "email": "string",
    "body": "string"
  }
  ```
* **Authentication Required:** No.
* **Sensitive-Looking Fields Returned:** `email` addresses of commenters.
* **Security Observations:**
  * Demonstrates query parameter parsing (`?postId=1`).
  * The API cleanly handles query-based relational filtering.
  * In a production API, query parameters must be strictly validated against an allowlist schema (e.g. ensuring `postId` is strictly a positive integer) to prevent SQL, NoSQL, or query-parser injection vulnerabilities.
* **Testing Limitations:**
  * In strict adherence to ethical read-only rules, no active injection payloads (`' OR 1=1--`, `${sleep}`, or script tags) were sent. Marked **NOT TESTABLE WITH SELECTED DEMO API**.

---

### 2.6 Endpoint: GET /todos/1

* **Full URL:** `https://jsonplaceholder.typicode.com/todos/1`
* **HTTP Method:** `GET`
* **HTTP Status Code:** `200 OK`
* **Content-Type:** `application/json; charset=utf-8`
* **Response Size:** 83 bytes
* **Response Structure:** Minimal JSON object:
  ```json
  {
    "userId": 1,
    "id": 1,
    "title": "delectus aut autem",
    "completed": false
  }
  ```
* **Authentication Required:** No.
* **Sensitive-Looking Fields Returned:** None.
* **Security Observations:**
  * Returns an internal state boolean (`completed: false`).
  * In a real task management platform, task items belong to specific tenants or user accounts. Accessing `/todos/1` without authentication would represent unauthorized data disclosure.
* **Testing Limitations:**
  * Authorization cannot be evaluated on an unauthenticated mock fixture API.

---

## 3. Comparative Endpoint Matrix

| Endpoint | HTTP Status | Response Size | Auth Req? | Sensitive Fields | Primary AppSec Observation | Real-World Production Analogy |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **GET /posts** | `200 OK` | 27.5 KB | No | None | Unbounded collection, no pagination | Unrestricted Resource Consumption (API4:2023) |
| **GET /posts/1** | `200 OK` | 292 B | No | None | Sequential ID, public access | Object Enumeration / IDOR candidate |
| **GET /users** | `200 OK` | 5.6 KB | No | Email, Phone, Address, Geo | Simulated PII in collection | Excessive Data Exposure / PII Leak (API3:2023) |
| **GET /users/1** | `200 OK` | 509 B | No | Email, Phone, Address, Geo | Unmasked profile record returned | Broken Object Property Level Auth (API3:2023) |
| **GET /comments?postId=1**| `200 OK`| 1.5 KB | No | Commenter Emails | Relational query filtering | Potential Query Injection if unvalidated |
| **GET /todos/1** | `200 OK` | 83 B | No | None | Direct record lookup | Object-Level Authorization failure (BOLA) |
