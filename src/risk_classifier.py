"""
risk_classifier.py - Risk Classification Engine
Future Interns Cyber Security Task 3 (2026)

This module provides structured, evidence-based risk classification
categorizing security observations into:
- HIGH
- MEDIUM
- LOW
- INFORMATIONAL
- NOT TESTABLE

Key AppSec Principles:
- Never assign HIGH severity without empirical evidence of a serious, demonstrated security impact.
- Differentiate between intentional public demonstration API behavior and production SaaS vulnerabilities.
- Never claim a header is present or absent across all endpoints unless each endpoint's saved headers support that statement.
"""

from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    NOT_TESTABLE = "NOT TESTABLE"


class Likelihood(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_APPLICABLE = "N/A"


class Finding:
    """Represents a single standardized security audit finding."""

    def __init__(
        self,
        finding_id: str,
        title: str,
        affected_endpoint: str,
        evidence: str,
        severity: Severity,
        likelihood: Likelihood,
        business_impact: str,
        recommendation: str,
        testing_limitation: str,
        category: str = "General",
        owasp_category: Optional[str] = None,
    ):
        self.finding_id = finding_id
        self.title = title
        self.affected_endpoint = affected_endpoint
        self.evidence = evidence
        self.severity = severity
        self.likelihood = likelihood
        self.business_impact = business_impact
        self.recommendation = recommendation
        self.testing_limitation = testing_limitation
        self.category = category
        self.owasp_category = owasp_category

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into a serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "owasp_category": self.owasp_category or "N/A",
            "affected_endpoint": self.affected_endpoint,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "likelihood": self.likelihood.value,
            "business_impact": self.business_impact,
            "recommendation": self.recommendation,
            "testing_limitation": self.testing_limitation,
        }


class RiskClassifier:
    """
    Evaluates raw audit observations and produces structured findings
    with transparent justification rules.
    """

    @classmethod
    def evaluate_audit(cls, audit_results: List[Dict[str, Any]]) -> List[Finding]:
        """
        Processes list of audited endpoints and produces consolidated findings.
        Explicitly validates whether headers are present or absent on every audited endpoint.
        """
        findings: List[Finding] = []
        finding_counter = 1

        total_count = len(audit_results)
        endpoints_missing_hsts = []
        endpoints_missing_csp = []
        endpoints_with_powered_by = []
        endpoints_with_cache_control = []
        endpoints_with_rate_limits = []
        user_endpoints_with_pii = []

        for item in audit_results:
            endpoint = item.get("endpoint", "")
            headers = item.get("header_checks", {})
            body = item.get("body_checks", {})

            # Check HSTS presence / absence per endpoint
            missing_headers = headers.get("missing_security_headers", {})
            if "Strict-Transport-Security (HSTS)" in missing_headers:
                endpoints_missing_hsts.append(endpoint)

            # Check CSP presence / absence per endpoint
            if "Content-Security-Policy (CSP)" in missing_headers:
                endpoints_missing_csp.append(endpoint)

            # Check information disclosure per endpoint
            info = headers.get("information_disclosure", {})
            if "x-powered-by" in info:
                endpoints_with_powered_by.append((endpoint, info.get("x-powered-by")))

            # Check caching policy per endpoint
            caching = headers.get("caching_policy", {})
            if caching.get("raw_value"):
                endpoints_with_cache_control.append((endpoint, caching.get("raw_value")))

            # Check rate limiting per endpoint
            rate_limits = headers.get("rate_limit_headers", {})
            if rate_limits:
                endpoints_with_rate_limits.append((endpoint, rate_limits))

            # Check for PII fields on /users or /users/1
            if "/users" in endpoint and body.get("exposed_pii_fields"):
                user_endpoints_with_pii.append({
                    "endpoint": endpoint,
                    "fields": body.get("exposed_pii_fields", []),
                })

        # -------------------------------------------------------------
        # FINDING 01: Information Disclosure via X-Powered-By Header
        # -------------------------------------------------------------
        if endpoints_with_powered_by:
            if len(endpoints_with_powered_by) == total_count:
                affected_scope = f"All {total_count} Audited Endpoints ({', '.join([e[0] for e in endpoints_with_powered_by])})"
                evidence_text = f"HTTP response header 'x-powered-by: {endpoints_with_powered_by[0][1]}' returned across all {total_count} audited endpoints."
            else:
                affected_scope = ", ".join([e[0] for e in endpoints_with_powered_by])
                evidence_text = f"HTTP response header 'x-powered-by' returned on: {affected_scope}."

            findings.append(
                Finding(
                    finding_id=f"FIND-{finding_counter:02d}",
                    title="Technology Fingerprinting via X-Powered-By Header",
                    category="Configuration & Header Security",
                    owasp_category="API8:2023 - Security Misconfiguration",
                    affected_endpoint=affected_scope,
                    evidence=evidence_text,
                    severity=Severity.LOW,
                    likelihood=Likelihood.HIGH,
                    business_impact=(
                        "Reveals backend runtime technology (Express.js) to potential adversaries. "
                        "While not directly exploitable alone, it assists attackers in crafting targeted "
                        "exploits against framework-specific CVEs."
                    ),
                    recommendation=(
                        "Disable the 'x-powered-by' header in the application framework "
                        "(e.g., in Express: app.disable('x-powered-by') or helmet.hidePoweredBy())."
                    ),
                    testing_limitation="None. Header presence verified directly in HTTP response.",
                )
            )
            finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 02: Missing HTTP Strict Transport Security (HSTS)
        # -------------------------------------------------------------
        if endpoints_missing_hsts:
            if len(endpoints_missing_hsts) == total_count:
                affected_scope = f"All {total_count} Audited Endpoints ({', '.join(endpoints_missing_hsts)})"
                evidence_text = f"Strict-Transport-Security header is absent across all {total_count} audited endpoints."
            else:
                affected_scope = ", ".join(endpoints_missing_hsts)
                evidence_text = f"Strict-Transport-Security header is absent on: {affected_scope}."

            findings.append(
                Finding(
                    finding_id=f"FIND-{finding_counter:02d}",
                    title="Missing HTTP Strict Transport Security (HSTS) Header",
                    category="Transport Security",
                    owasp_category="API8:2023 - Security Misconfiguration",
                    affected_endpoint=affected_scope,
                    evidence=evidence_text,
                    severity=Severity.LOW,
                    likelihood=Likelihood.LOW,
                    business_impact=(
                        "Without HSTS, web browsers interacting with this API domain might allow "
                        "unencrypted HTTP fallback or SSL stripping on initial connection. "
                        "For pure programmatic API clients with HTTPS hardcoded, impact is minimal."
                    ),
                    recommendation=(
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
                        "at the edge proxy, load balancer, or web server."
                    ),
                    testing_limitation="None. Header absence verified directly across audited endpoints.",
                )
            )
            finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 03: Public Caching of Structured User Data
        # -------------------------------------------------------------
        if endpoints_with_cache_control:
            all_endpoints_list = [e[0] for e in endpoints_with_cache_control]
            sample_val = endpoints_with_cache_control[0][1]
            if len(endpoints_with_cache_control) == total_count:
                affected_scope = f"All {total_count} Audited Endpoints ({', '.join(all_endpoints_list)})"
                evidence_text = f"Cache-Control header returned with '{sample_val}' across all {total_count} audited endpoints."
            else:
                affected_scope = ", ".join(all_endpoints_list)
                evidence_text = f"Cache-Control header returned on {affected_scope} with '{sample_val}'."

            findings.append(
                Finding(
                    finding_id=f"FIND-{finding_counter:02d}",
                    title="Permissive Cache-Control Policy on Data Endpoints",
                    category="Data Storage & Caching",
                    owasp_category="API8:2023 - Security Misconfiguration",
                    affected_endpoint=affected_scope,
                    evidence=evidence_text,
                    severity=Severity.LOW,
                    likelihood=Likelihood.MEDIUM,
                    business_impact=(
                        "In this mock API, responses contain static test fixtures, so caching is benign. "
                        "However, in a production SaaS platform, caching responses containing user profiles "
                        "or private records in shared intermediate caches (proxies, CDNs) risks exposing "
                        "confidential information to unauthorized third parties."
                    ),
                    recommendation=(
                        "In production environments, specify 'Cache-Control: no-store, no-cache, "
                        "must-revalidate, private' on all authenticated API endpoints returning sensitive user data."
                    ),
                    testing_limitation=(
                        "Assessed via response header inspection. Public mock data caching is intentional "
                        "by design for JSONPlaceholder scalability."
                    ),
                )
            )
            finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 04: Synthetic Personally Identifiable Information (PII) Exposure
        # -------------------------------------------------------------
        if user_endpoints_with_pii:
            affected_endpoints = ", ".join([u["endpoint"] for u in user_endpoints_with_pii])
            sample_fields = user_endpoints_with_pii[0]["fields"]
            fields_str = ", ".join(sample_fields[:6])
            findings.append(
                Finding(
                    finding_id=f"FIND-{finding_counter:02d}",
                    title="Simulated Excessive Data Exposure (Synthetic PII)",
                    category="Data Minimization & Privacy",
                    owasp_category="API3:2023 - Broken Object Property Level Authorization",
                    affected_endpoint=affected_endpoints,
                    evidence=f"Unmasked synthetic PII fields returned in body: {fields_str}.",
                    severity=Severity.INFORMATIONAL,
                    likelihood=Likelihood.NOT_APPLICABLE,
                    business_impact=(
                        "On JSONPlaceholder, all data is synthetic fixture data explicitly created "
                        "for testing and prototyping; no real personal data exists or is breached. "
                        "In a production system, returning full phone numbers, addresses, and GPS "
                        "coordinates on general queries without masking constitutes a severe privacy "
                        "and compliance violation (GDPR, CCPA, OWASP API3)."
                    ),
                    recommendation=(
                        "Apply data minimization principles (filter/mask PII fields), implement strict "
                        "Data Transfer Objects (DTOs), and enforce object property-level authorization."
                    ),
                    testing_limitation=(
                        "Data was verified to be fictional mock data. No real human PII is hosted on JSONPlaceholder."
                    ),
                )
            )
            finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 05: Visible Rate Limiting Headers
        # -------------------------------------------------------------
        if endpoints_with_rate_limits:
            limits_summary = []
            for ep, r_hdr in endpoints_with_rate_limits:
                lim = r_hdr.get("x-ratelimit-limit", "N/A")
                limits_summary.append(f"{ep}: limit={lim}")

            evidence_text = f"Rate-limit headers exposed across endpoints ({'; '.join(limits_summary)})."
            affected_scope = ", ".join([e[0] for e in endpoints_with_rate_limits])

            findings.append(
                Finding(
                    finding_id=f"FIND-{finding_counter:02d}",
                    title="Exposed Rate-Limiting Quota Metadata",
                    category="Traffic & Resource Management",
                    owasp_category="API4:2023 - Unrestricted Resource Consumption",
                    affected_endpoint=affected_scope,
                    evidence=evidence_text,
                    severity=Severity.INFORMATIONAL,
                    likelihood=Likelihood.LOW,
                    business_impact=(
                        "The API transparently exposes its rate limit ceiling and remaining budget. "
                        "While standard for developer ergonomics, attackers can monitor remaining "
                        "budget to optimize scraping or denial-of-inventory thresholds without triggering alarms."
                    ),
                    recommendation=(
                        "Standardize on RFC 7231 / RFC 6585 rate limiting (Retry-After) or standard "
                        "IETF RateLimit headers; ensure backend enforces dynamic IP and token throttling."
                    ),
                    testing_limitation=(
                        "Ethical read-only boundaries prohibited stress testing or quota exhaustion. "
                        "Actual rate limit enforcement at scale was NOT tested."
                    ),
                )
            )
            finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 06: Object-Level Authorization & Access Controls
        # -------------------------------------------------------------
        findings.append(
            Finding(
                finding_id=f"FIND-{finding_counter:02d}",
                title="Object-Level & Functional Authorization Verification",
                category="Authentication & Authorization",
                owasp_category="API1:2023 - Broken Object Level Authorization (BOLA)",
                affected_endpoint="All Endpoints (/posts/1, /users/1, /todos/1, etc.)",
                evidence="Endpoints are intentionally accessible to the public without authentication credentials.",
                severity=Severity.NOT_TESTABLE,
                likelihood=Likelihood.NOT_APPLICABLE,
                business_impact=(
                    "NOT TESTABLE WITH SELECTED DEMO API. JSONPlaceholder is architected as an "
                    "open mock REST server without user accounts, authentication tokens, or tenancy boundaries. "
                    "No production authorization flaw can be inferred from open public demo endpoints."
                ),
                recommendation=(
                    "For production APIs: Require OAuth 2.0 / OpenID Connect access tokens, and enforce "
                    "contextual authorization checks verifying that requesting user id matches resource owner id."
                ),
                testing_limitation=(
                    "Marked NOT TESTABLE WITH SELECTED DEMO API. Attempting authorization bypass or "
                    "privilege escalation was neither possible nor ethically permissible."
                ),
            )
        )
        finding_counter += 1

        # -------------------------------------------------------------
        # FINDING 07: Input Validation & Injection Boundaries
        # -------------------------------------------------------------
        findings.append(
            Finding(
                finding_id=f"FIND-{finding_counter:02d}",
                title="Input Validation & Injection Resistance Under Defensive Testing",
                category="Input Validation",
                owasp_category="API8:2023 - Security Misconfiguration",
                affected_endpoint="/comments?postId=1",
                evidence="Standard query parameters accepted and parsed normally as integer identifiers.",
                severity=Severity.NOT_TESTABLE,
                likelihood=Likelihood.NOT_APPLICABLE,
                business_impact=(
                    "NOT TESTABLE WITH SELECTED DEMO API under ethical rules. In accordance with the "
                    "defensive, read-only testing scope, no active injection payloads (SQLi, NoSQLi, command injection) "
                    "or malformed payloads were transmitted."
                ),
                recommendation=(
                    "For production APIs: Implement strict server-side schema validation (JSON Schema / Pydantic), "
                    "parameterized queries, and explicit type checking for all query string and body parameters."
                ),
                testing_limitation=(
                    "Marked NOT TESTABLE WITH SELECTED DEMO API. Testing was strictly confined to safe GET "
                    "requests with documented parameters."
                ),
            )
        )

        return findings
