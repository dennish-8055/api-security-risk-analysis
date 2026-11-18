"""
test_security_checks.py - Unit Test Suite for API Security Checks
Future Interns Cyber Security Task 3 (2026)

This suite rigorously tests header checking, response body inspection,
risk classification, and error handling using mocked HTTP responses
without requiring live internet access.
"""

import socket
import unittest
from unittest.mock import MagicMock, patch
import requests

from src.security_checks import SecurityHeaderChecker, ResponseBodyChecker, EndpointAuditor
from src.risk_classifier import RiskClassifier, Severity, Likelihood, Finding
from src.api_audit import SafeAPIAuditor


class TestSecurityHeaderChecker(unittest.TestCase):
    """Test suite for HTTP response header security validation."""

    def test_all_security_headers_present(self):
        """Verify proper identification when all baseline security headers are present."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "X-Frame-Options": "DENY",
        }
        results = SecurityHeaderChecker.check_headers(headers)

        self.assertEqual(len(results["missing_security_headers"]), 0)
        self.assertIn("Strict-Transport-Security (HSTS)", results["present_security_headers"])
        self.assertIn("X-Content-Type-Options", results["present_security_headers"])
        self.assertIn("Content-Security-Policy (CSP)", results["present_security_headers"])
        self.assertTrue(results["caching_policy"]["has_no_store"])
        self.assertTrue(results["caching_policy"]["has_private"])

    def test_missing_headers_detection(self):
        """Verify accurate reporting when critical security headers are absent."""
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Server": "cloudflare",
        }
        results = SecurityHeaderChecker.check_headers(headers)

        self.assertIn("Strict-Transport-Security (HSTS)", results["missing_security_headers"])
        self.assertIn("Content-Security-Policy (CSP)", results["missing_security_headers"])
        self.assertIn("X-Content-Type-Options", results["missing_security_headers"])
        self.assertEqual(results["information_disclosure"]["server"], "cloudflare")

    def test_information_disclosure_headers(self):
        """Verify detection of backend fingerprinting headers (X-Powered-By, Server)."""
        headers = {
            "X-Powered-By": "Express",
            "Server": "nginx/1.18.0",
        }
        results = SecurityHeaderChecker.check_headers(headers)
        info = results["information_disclosure"]

        self.assertEqual(info.get("x-powered-by"), "Express")
        self.assertEqual(info.get("server"), "nginx/1.18.0")

    def test_rate_limiting_headers_parsing(self):
        """Verify parsing of rate-limiting metadata."""
        headers = {
            "x-ratelimit-limit": "1000",
            "x-ratelimit-remaining": "995",
            "x-ratelimit-reset": "1700000000",
        }
        results = SecurityHeaderChecker.check_headers(headers)
        rate = results["rate_limit_headers"]

        self.assertEqual(rate.get("x-ratelimit-limit"), "1000")
        self.assertEqual(rate.get("x-ratelimit-remaining"), "995")


class TestResponseBodyChecker(unittest.TestCase):
    """Test suite for response body data inspection and PII detection."""

    def test_detect_pii_in_user_profile(self):
        """Verify detection of email, phone, and address/geo coordinates."""
        sample_user = {
            "id": 1,
            "name": "Jane Doe",
            "email": "jane.doe@example.com",
            "phone": "1-555-123-4567",
            "address": {
                "street": "123 Main St",
                "city": "Metropolis",
                "zipcode": "12345",
                "geo": {"lat": "40.7128", "lng": "-74.0060"},
            },
        }
        results = ResponseBodyChecker.inspect_body(sample_user)

        self.assertEqual(results["record_count"], 1)
        # Check PII fields identified
        pii_fields = " ".join(results["exposed_pii_fields"]).lower()
        self.assertIn("email", pii_fields)
        self.assertIn("phone", pii_fields)
        self.assertIn("address", pii_fields)
        self.assertIn("geo", pii_fields)
        self.assertTrue(len(results["data_minimization_notes"]) > 0)

    def test_detect_suspicious_secret_keys(self):
        """Verify alert triggers if secret/password/token keys are returned."""
        leak_data = {
            "id": 10,
            "username": "admin",
            "auth_token": "eyJhbGciOi...",
            "password_hash": "e10adc3949ba59abbe56e057f20f883e",
        }
        results = ResponseBodyChecker.inspect_body(leak_data)

        self.assertIn("auth_token", results["suspicious_keys_found"])
        self.assertIn("password_hash", results["suspicious_keys_found"])

    def test_empty_and_none_body_handling(self):
        """Verify robust handling of empty or None response bodies without crashing."""
        none_result = ResponseBodyChecker.inspect_body(None)
        self.assertEqual(none_result["data_type"], "None")
        self.assertEqual(none_result["record_count"], 0)

        empty_dict_result = ResponseBodyChecker.inspect_body({})
        self.assertEqual(empty_dict_result["record_count"], 1)
        self.assertEqual(len(empty_dict_result["exposed_pii_fields"]), 0)

        empty_list_result = ResponseBodyChecker.inspect_body([])
        self.assertEqual(empty_list_result["record_count"], 0)


class TestRiskClassifier(unittest.TestCase):
    """Test suite for risk classification rules and severity determinations."""

    def test_classification_of_demo_api_audit(self):
        """Verify risk classifier produces expected findings on simulated audit data."""
        mock_audit_data = [
            {
                "endpoint": "/posts",
                "status_code": 200,
                "header_checks": {
                    "missing_security_headers": {
                        "Strict-Transport-Security (HSTS)": {},
                        "Content-Security-Policy (CSP)": {},
                    },
                    "information_disclosure": {"x-powered-by": "Express"},
                    "caching_policy": {"raw_value": "max-age=43200"},
                    "rate_limit_headers": {"x-ratelimit-limit": "3600000"},
                },
                "body_checks": {"exposed_pii_fields": []},
            },
            {
                "endpoint": "/users/1",
                "status_code": 200,
                "header_checks": {
                    "missing_security_headers": {},
                    "information_disclosure": {},
                    "caching_policy": {},
                    "rate_limit_headers": {},
                },
                "body_checks": {
                    "exposed_pii_fields": ["email", "phone", "address.street", "address.geo.lat"]
                },
            },
        ]

        findings = RiskClassifier.evaluate_audit(mock_audit_data)
        severities = {f.finding_id: f.severity for f in findings}
        titles = [f.title for f in findings]

        # Ensure no unjustified HIGH severity is assigned
        for f in findings:
            self.assertNotEqual(
                f.severity,
                Severity.HIGH,
                f"Finding '{f.title}' incorrectly classified as HIGH on public mock data.",
            )

        # Check expected classifications
        self.assertTrue(any("X-Powered-By" in t for t in titles))
        self.assertTrue(any("HSTS" in t for t in titles))
        self.assertTrue(any(f.severity == Severity.NOT_TESTABLE for f in findings))


class TestSafeAPIAuditorMocked(unittest.TestCase):
    """
    Test suite for auditor execution using mocked network transport.
    Guarantees that 100% of HTTP calls are mocked and never contact external hosts.
    """

    def setUp(self):
        """Install strict network blocker to guarantee zero external calls."""
        self._orig_create_connection = socket.create_connection

        def _strict_no_network(*args, **kwargs):
            raise AssertionError(
                "Unmocked network connection attempt detected! "
                "All test requests must be mocked."
            )

        socket.create_connection = _strict_no_network

    def tearDown(self):
        """Restore standard socket behavior after test completion."""
        socket.create_connection = self._orig_create_connection

    @patch("src.api_audit.requests.Session.get")
    def test_successful_mocked_get_request(self, mock_get):
        """Verify SafeAPIAuditor handles a valid 200 OK response correctly without network."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"id": 1, "title": "Test Post"}'
        mock_resp.headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Server": "cloudflare",
            "x-content-type-options": "nosniff",
        }
        mock_resp.json.return_value = {"id": 1, "title": "Test Post"}
        mock_get.return_value = mock_resp

        auditor = SafeAPIAuditor(save_to_disk=False, verbose=False)
        result = auditor.run_safe_request("/posts/1", max_retries=0)

        self.assertIsNotNone(result)
        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["is_json"])
        self.assertEqual(result["endpoint"], "/posts/1")
        mock_get.assert_called_once()

    @patch("src.api_audit.requests.Session.get")
    def test_timeout_handling(self, mock_get):
        """Verify SafeAPIAuditor handles requests.exceptions.Timeout gracefully without crashing."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        auditor = SafeAPIAuditor(save_to_disk=False, verbose=False)
        result = auditor.run_safe_request("/posts", max_retries=0)

        self.assertIsNotNone(result)
        self.assertEqual(result["error"], "RequestTimeout")
        self.assertEqual(result["status_code"], 0)
        mock_get.assert_called_once()

    @patch("src.api_audit.requests.Session.get")
    def test_connection_error_handling(self, mock_get):
        """Verify SafeAPIAuditor handles network disconnection gracefully."""
        mock_get.side_effect = requests.exceptions.ConnectionError("DNS failure")

        auditor = SafeAPIAuditor(save_to_disk=False, verbose=False)
        result = auditor.run_safe_request("/users", max_retries=0)

        self.assertIsNotNone(result)
        self.assertIn("ConnectionError", result["error"])
        self.assertEqual(result["status_code"], 0)
        mock_get.assert_called_once()

    def test_url_boundary_validation(self):
        """Verify auditor rejects requests outside the authorized domain without network calls."""
        auditor = SafeAPIAuditor(save_to_disk=False, verbose=False)
        self.assertTrue(auditor._is_safe_url("https://jsonplaceholder.typicode.com/posts"))
        self.assertFalse(auditor._is_safe_url("https://malicious-external-site.com/steal"))
        self.assertFalse(auditor._is_safe_url("http://attacker.com"))


if __name__ == "__main__":
    unittest.main()
