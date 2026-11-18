# Authentication and Authorization Assessment

**Focus Standards:**  
- OWASP API Security Top 10 (2023):  
  - **API1:2023 - Broken Object Level Authorization (BOLA)**  
  - **API2:2023 - Broken Authentication**  
  - **API5:2023 - Broken Function Level Authorization (BFLA)**  
- Shieldfy API Security Checklist (Authentication & Access Control)  

---

## 1. Authentication Analysis

### 1.1 Current State in JSONPlaceholder
During the automated read-only audit across all six endpoints:
* **Authentication Requirement:** `None`. No endpoints required API keys, Bearer tokens, basic credentials, or session cookies.
* **Tokens Required:** None. All requests sent without `Authorization` headers succeeded immediately with HTTP `200 OK`.
* **Credential Exchanges:** No login endpoints (`/auth/login`, `/oauth/token`) or session issuance mechanisms exist.
* **Authentication Strength Assessment:** **NOT TESTABLE WITH SELECTED DEMO API**. Because no authentication mechanism exists on JSONPlaceholder, password complexity, token entropy, cryptographic signing algorithms (e.g., RS256 vs HS256), and session expiration cannot be evaluated.

### 1.2 Evaluation & Real-World Risk Translation
* **In JSONPlaceholder (Mock API Context):**  
  The absence of authentication is an **intentional design feature**. The service was created specifically as an open prototyping endpoint for developers testing frontend fetch calls and mock data grids without managing API keys.
* **In Production SaaS Applications (Real-World Risk Context):**  
  If a production API allows unauthenticated access to endpoints handling user profiles, financial ledgers, or private task data, it constitutes **OWASP API2:2023 - Broken Authentication**. Unauthenticated exposure allows anonymous threat actors to harvest data, perform mass scraping, and access sensitive business data with zero accountability.

---

## 2. Authorization Analysis

### 2.1 Object-Level Authorization (BOLA / IDOR)
**Broken Object Level Authorization (BOLA)** occurs when an API endpoint exposes an object identifier (e.g., `/users/{id}` or `/posts/{id}`) and fails to validate whether the authenticated caller has legitimate permission to access that specific object.

* **Audit Observations on JSONPlaceholder:**
  * Querying `/users/1` returns user ID 1.
  * Querying `/users/2` returns user ID 2.
  * Querying `/todos/1` returns todo ID 1.
  * All records are accessible by any client altering the integer parameter in the URL.
* **AppSec Determination:**  
  While this mirrors the structural symptom of BOLA/IDOR, it is **not a confirmed vulnerability on JSONPlaceholder** because the API does not maintain tenant boundaries or private records.
* **Audit Limitation:**  
  Verifying real-world BOLA requires comparing access across two distinct authenticated user sessions (e.g., verifying whether User A can access User B's private resources using User A's valid token). Since JSONPlaceholder does not support user accounts or authentication tokens, this check is classified as **NOT TESTABLE WITH SELECTED DEMO API**.

### 2.2 Functional-Level Authorization (BFLA)
**Broken Function Level Authorization (BFLA)** occurs when administrative or privileged functions (e.g., `/admin/users`, `/users/delete`) are accessible to regular unprivileged users or anonymous callers due to flawed role checks.

* **Audit Observations on JSONPlaceholder:**
  * No administrative hierarchy exists.
  * Destructive state-altering methods (`POST`, `PUT`, `DELETE`) are mocked locally by JSONPlaceholder's Express server without persisting changes or validating administrative roles.
  * Testing destructive endpoints was excluded under ethical read-only testing rules.

---

## 3. Production SaaS Remediation Architecture

To achieve enterprise-grade security, production APIs must implement a layered authentication and authorization architecture:

```
[ Incoming Client Request ]
             │
             ▼
[ API Gateway / Reverse Proxy ]
  ├── 1. TLS 1.3 Termination & HSTS Enforcement
  ├── 2. Rate Limiting & DDoS Shielding (Token Bucket)
  └── 3. Token Authentication Verification (JWT Signature / Expiry)
             │ (Injects Validated User Claims)
             ▼
[ Application Backend / Microservice ]
  ├── 4. Role-Based Access Control (RBAC) Check (e.g., Admin vs User)
  └── 5. Contextual Object-Level Authorization Check (BOLA Defense)
             │
             ├── Rule: Is resource.owner_id == request.user_id?
             ├── Rule: Does request.tenant_id == resource.tenant_id?
             │
             ▼
[ Data Access Layer / Database ]
  └── 6. Data Transfer Object (DTO) Filtering (BOPLA Defense)
```

### 3.1 Recommended Authentication Standards
1. **OAuth 2.0 & OpenID Connect (OIDC):** Standardize on industry-proven protocols rather than rolling custom authentication logic.
2. **Short-Lived Access Tokens:** Issue JSON Web Tokens (JWT) with strict 15-minute lifespans, signed with asymmetric keys (e.g., `RS256` or `EdDSA`). Avoid symmetric `HS256` with shared secrets.
3. **Secure Refresh Token Rotation:** Store refresh tokens in `HttpOnly`, `Secure`, `SameSite=Strict` cookies or secure client vaults, invalidating token families upon reuse detection.

### 3.2 Recommended Authorization Code Pattern
In production frameworks (such as FastAPI, Django REST Framework, or Express.js), object authorization must never rely on client-supplied IDs alone:

```python
# Production Defense Example (FastAPI / Python)
@app.get("/api/v1/users/{user_id}/profile")
def get_user_profile(
    user_id: int, 
    current_user: User = Depends(get_current_authenticated_user)
):
    # Enforce Object-Level Authorization (BOLA Mitigation)
    if current_user.id != user_id and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: You do not have permission to access this profile."
        )
    
    # Retrieve record from database scoped to tenant/user
    profile = db.query(UserProfile).filter(UserProfile.id == user_id).first()
    
    # Enforce Data Minimization via DTO (BOPLA Mitigation)
    return UserProfilePublicDTO.from_orm(profile)
```

---

## 4. Assessment Summary Matrix

| Area | Observed Demo State | Tested Against Exploit? | Status Classification | Production SaaS Requirement |
| :--- | :--- | :---: | :--- | :--- |
| **Authentication** | Completely unauthenticated | No (Ethical constraint) | **NOT TESTABLE** | OAuth 2.0 / JWT / OpenID Connect |
| **Token Validation**| No tokens used | No | **NOT TESTABLE** | RS256 Signature + Expiration verification |
| **Object Auth (BOLA)** | Sequential IDs globally readable | No | **NOT TESTABLE** | Contextual check (`owner_id == current_user.id`) |
| **Role Auth (BFLA)**| No role hierarchy | No | **NOT TESTABLE** | Mandatory RBAC / ABAC middleware |
