"""
security_checks.py - Security Inspection Engine for REST APIs
Future Interns Cyber Security Task 3 (2026)

This module provides defensive, read-only inspection of API response headers,
status codes, content types, and response bodies against industry best
practices (OWASP API Security Top 10 and RFC standards).
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple


class SecurityHeaderChecker:
    """
    Evaluates HTTP response headers against security baseline standards.

    Important AppSec Note:
    A missing or sub-optimal header is a configuration observation and defense-in-depth
    opportunity, not automatic proof of an exploitable critical vulnerability.
    """

    # Baseline security headers to check
    HEADER_DEFINITIONS = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "purpose": "Enforces HTTPS connections and prevents SSL stripping attacks.",
            "browser_specific": True,
            "recommended": "max-age=31536000; includeSubDomains; preload",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "purpose": "Prevents MIME-type sniffing by clients.",
            "browser_specific": True,
            "recommended": "nosniff",
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "purpose": "Restricts resource loading origins; mitigates XSS and injection in browsers.",
            "browser_specific": True,
            "recommended": "default-src 'none'; frame-ancestors 'none'",
        },
        "cache-control": {
            "name": "Cache-Control",
            "purpose": "Governs browser and proxy caching of potentially sensitive responses.",
            "browser_specific": False,
            "recommended": "no-store, no-cache, must-revalidate, private",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "purpose": "Prevents embedding in frames/iframes to protect against clickjacking.",
            "browser_specific": True,
            "recommended": "DENY",
        },
    }

    @classmethod
    def check_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Inspect headers dictionary (case-insensitively) for presence, values,
        and potential information disclosure.
        """
        # Normalize header keys to lowercase for reliable comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        results = {
            "present_security_headers": {},
            "missing_security_headers": {},
            "information_disclosure": {},
            "caching_policy": {},
            "cors_configuration": {},
            "rate_limit_headers": {},
        }

        # 1. Baseline Security Headers
        for header_key, meta in cls.HEADER_DEFINITIONS.items():
            if header_key in lower_headers:
                results["present_security_headers"][meta["name"]] = {
                    "header": header_key,
                    "value": lower_headers[header_key],
                    "purpose": meta["purpose"],
                    "browser_specific": meta["browser_specific"],
                }
            else:
                results["missing_security_headers"][meta["name"]] = {
                    "header": header_key,
                    "purpose": meta["purpose"],
                    "browser_specific": meta["browser_specific"],
                    "recommendation": meta["recommended"],
                }

        # 2. Information Disclosure Headers (CWE-200)
        disclosure_targets = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]
        for target in disclosure_targets:
            if target in lower_headers:
                results["information_disclosure"][target] = lower_headers[target]

        # 3. Cache Control Inspection
        cache_header = lower_headers.get("cache-control", "")
        results["caching_policy"] = {
            "raw_value": cache_header,
            "is_cached": "max-age" in cache_header and "no-store" not in cache_header,
            "has_no_store": "no-store" in cache_header,
            "has_private": "private" in cache_header,
            "observation": (
                "Response permits public/client caching without 'no-store'."
                if ("max-age" in cache_header and "no-store" not in cache_header)
                else "Caching policy restricts storing or requires revalidation."
            ),
        }

        # 4. CORS Response Headers
        cors_keys = [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "vary",
        ]
        for key in cors_keys:
            if key in lower_headers:
                results["cors_configuration"][key] = lower_headers[key]

        # 5. Rate-Limiting Headers
        rate_keys = [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "retry-after",
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
        ]
        for key in rate_keys:
            if key in lower_headers:
                results["rate_limit_headers"][key] = lower_headers[key]

        return results


class ResponseBodyChecker:
    """
    Evaluates response bodies for data exposure, structure consistency,
    and potential PII (Personally Identifiable Information).
    """

    SENSITIVE_PATTERNS = {
        "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        "phone": re.compile(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        "geo_coordinates": re.compile(r"^-?\d{1,3}\.\d{4,}$"),
    }

    SUSPICIOUS_KEY_NAMES = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth_token",
        "private_key",
        "credit_card",
        "ssn",
    ]

    @classmethod
    def inspect_body(cls, data: Any) -> Dict[str, Any]:
        """
        Inspect parsed JSON body for data structure and sensitive fields.
        Safely handles dicts, lists, primitives, and empty inputs.
        """
        findings = {
            "record_count": 0,
            "data_type": type(data).__name__,
            "exposed_pii_fields": set(),
            "suspicious_keys_found": [],
            "sample_structure": {},
            "data_minimization_notes": [],
        }

        if data is None:
            findings["data_type"] = "None"
            return findings

        # Normalize data into a list of dictionaries for inspection
        records: List[Dict[str, Any]] = []
        if isinstance(data, list):
            findings["record_count"] = len(data)
            records = [item for item in data if isinstance(item, dict)]
            if records:
                findings["sample_structure"] = cls._extract_keys(records[0])
        elif isinstance(data, dict):
            findings["record_count"] = 1
            records = [data]
            findings["sample_structure"] = cls._extract_keys(data)
        else:
            findings["record_count"] = 1
            return findings

        # Scan for sensitive field names and patterns
        for record in records:
            cls._scan_nested_record(record, findings)

        # Convert set of exposed PII to sorted list for clean serialization
        findings["exposed_pii_fields"] = sorted(list(findings["exposed_pii_fields"]))

        # Check for data minimization observations
        if "email" in findings["exposed_pii_fields"] or "phone" in findings["exposed_pii_fields"]:
            findings["data_minimization_notes"].append(
                "Endpoint returns contact information (email/phone) in plain text."
            )
        if "address" in str(findings["sample_structure"]).lower() or "geo" in str(findings["sample_structure"]).lower():
            findings["data_minimization_notes"].append(
                "Endpoint returns detailed physical address and/or GPS geolocation coordinates."
            )

        return findings

    @classmethod
    def _scan_nested_record(cls, record: Any, findings: Dict[str, Any], prefix: str = "") -> None:
        """Recursively scan dict or list for PII indicators and sensitive keys."""
        if isinstance(record, dict):
            for k, v in record.items():
                full_key = f"{prefix}.{k}" if prefix else k
                lower_k = k.lower()

                # Check for suspicious secret-like keys
                for suspicious in cls.SUSPICIOUS_KEY_NAMES:
                    if suspicious in lower_k:
                        findings["suspicious_keys_found"].append(full_key)

                # Check for common PII keys
                if any(pii_term in lower_k for pii_term in ["email", "phone", "address", "geo", "zipcode", "lat", "lng"]):
                    findings["exposed_pii_fields"].add(full_key)

                # Inspect string values for pattern matching
                if isinstance(v, str):
                    if cls.SENSITIVE_PATTERNS["email"].search(v):
                        findings["exposed_pii_fields"].add(f"{full_key} (email-value)")

                # Recurse if nested dict or list
                if isinstance(v, (dict, list)):
                    cls._scan_nested_record(v, findings, full_key)

        elif isinstance(record, list):
            for i, item in enumerate(record[:3]):  # limit recursion breadth
                cls._scan_nested_record(item, findings, f"{prefix}[{i}]")

    @classmethod
    def _extract_keys(cls, obj: Any) -> Any:
        """Extract schema skeleton showing field names and value types."""
        if isinstance(obj, dict):
            return {k: cls._extract_keys(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [cls._extract_keys(obj[0])] if obj else []
        else:
            return type(obj).__name__


class EndpointAuditor:
    """
    Coordinates security checks for a single HTTP response.
    """

    @classmethod
    def audit_response(
        cls,
        endpoint: str,
        method: str,
        status_code: int,
        headers: Dict[str, str],
        body: Any,
        content_type: str,
        response_size: int,
        response_time_ms: float,
    ) -> Dict[str, Any]:
        """
        Runs comprehensive security checks and returns a unified report object.
        """
        header_results = SecurityHeaderChecker.check_headers(headers)
        body_results = ResponseBodyChecker.inspect_body(body)

        # Content-type analysis
        is_json = "application/json" in content_type.lower()

        return {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "content_type": content_type,
            "is_json": is_json,
            "response_size_bytes": response_size,
            "response_time_ms": round(response_time_ms, 2),
            "header_checks": header_results,
            "body_checks": body_results,
            "authentication_required": status_code not in [401, 403] and status_code == 200,
        }
