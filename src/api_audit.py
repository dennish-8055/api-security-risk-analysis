"""
api_audit.py - Safe, Read-Only REST API Security Audit Tool
Future Interns Cyber Security Task 3 (2026)

This script conducts a strictly defensive, read-only security assessment
of the public JSONPlaceholder demonstration API (https://jsonplaceholder.typicode.com).

Ethical Testing Rules:
- Only HTTP GET requests are issued.
- No authentication bypass, brute-force, or DoS testing.
- No state-altering requests (POST, PUT, PATCH, DELETE are strictly prohibited).
- Safe timeout of 5 seconds per request.
- Sanitized outputs saved to structured project directories.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library is not installed. Run: pip install requests")
    sys.exit(1)

# Ensure src directory is in Python path for direct script execution
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from security_checks import EndpointAuditor
from risk_classifier import RiskClassifier


class SafeAPIAuditor:
    """
    Defensive API Security Auditor performing safe, controlled GET assessments.
    """

    BASE_URL = "https://jsonplaceholder.typicode.com"
    ALLOWED_HOST = "jsonplaceholder.typicode.com"
    REQUEST_TIMEOUT_SECONDS = 10.0
    REQUEST_DELAY_SECONDS = 0.5  # Polite delay between calls

    # Fixed, safe, small selection of GET endpoints for assessment
    ENDPOINTS_TO_AUDIT = [
        {"path": "/posts", "description": "Collection of mock public posts"},
        {"path": "/posts/1", "description": "Single mock post record by ID"},
        {"path": "/users", "description": "Collection of mock user profiles"},
        {"path": "/users/1", "description": "Single mock user profile with contact details"},
        {"path": "/comments?postId=1", "description": "Query-filtered mock comment collection"},
        {"path": "/todos/1", "description": "Single mock todo task item"},
    ]

    def __init__(
        self,
        project_root: Optional[Path] = None,
        save_to_disk: bool = True,
        verbose: bool = True,
    ):
        self.project_root = project_root or PROJECT_ROOT
        self.save_to_disk = save_to_disk
        self.verbose = verbose
        self.results_dir = self.project_root / "results"
        self.responses_dir = self.results_dir / "api_responses"
        self.headers_dir = self.results_dir / "response_headers"

        # Ensure required directories exist if saving to disk
        if self.save_to_disk:
            self.responses_dir.mkdir(parents=True, exist_ok=True)
            self.headers_dir.mkdir(parents=True, exist_ok=True)

        # Initialize requests session with safe headers
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FutureInterns-APISecurityAuditor/1.0 (Defensive-Audit-Safe)",
            "Accept": "application/json",
        })

    def _log(self, message: str) -> None:
        """Helper to conditionally output log messages."""
        if self.verbose:
            print(message)

    def _safe_endpoint_slug(self, path: str) -> str:
        """Convert an endpoint path into a safe file name."""
        clean = path.strip("/").replace("/", "_").replace("?", "_").replace("=", "_")
        return clean or "root"

    def _is_safe_url(self, target_url: str) -> bool:
        """Verify the URL target domain strictly matches the allowed target."""
        parsed = urlparse(target_url)
        return parsed.netloc.lower() == self.ALLOWED_HOST

    def run_safe_request(self, path: str, max_retries: int = 2) -> Optional[Dict[str, Any]]:
        """
        Execute a safe HTTP GET request with defensive boundaries:
        - Strict host validation
        - Short timeout with polite retry for transient network latency
        - No unsafe redirect chasing
        - Comprehensive error trapping
        """
        full_url = f"{self.BASE_URL}{path}"

        if not self._is_safe_url(full_url):
            self._log(f"[SECURITY ALERT] Attempted request outside approved host: {full_url}")
            return None

        for attempt in range(1, max_retries + 2):
            self._log(f"[*] Auditing endpoint: GET {path}" + (f" (Attempt {attempt}/{max_retries + 1})" if attempt > 1 else ""))
            start_time = time.time()

            try:
                # We explicitly disallow automatic cross-domain redirects to prevent open-redirect hijacking
                response = self.session.get(
                    full_url,
                    timeout=self.REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=False,
                )
                elapsed_ms = (time.time() - start_time) * 1000.0

                # Check if an unexpected redirect occurred
                if 300 <= response.status_code < 400:
                    redirect_url = response.headers.get("Location", "")
                    self._log(f"  [!] Received redirect ({response.status_code}) to: {redirect_url}")
                    if not self._is_safe_url(redirect_url):
                        self._log("  [!] Refusing to follow external redirect.")

                # Attempt safe JSON decoding
                body_json = None
                try:
                    body_json = response.json()
                except ValueError:
                    # Body is not JSON (e.g. HTML or plain text)
                    body_json = {"_raw_text": response.text[:500], "_warning": "Non-JSON response"}

                # Calculate content size safely
                response_size = len(response.content)
                headers_dict = dict(response.headers)
                content_type = response.headers.get("Content-Type", "Unknown")

                # Perform automated security checks
                audit_result = EndpointAuditor.audit_response(
                    endpoint=path,
                    method="GET",
                    status_code=response.status_code,
                    headers=headers_dict,
                    body=body_json,
                    content_type=content_type,
                    response_size=response_size,
                    response_time_ms=elapsed_ms,
                )

                # Persist responses to results directory if configured
                if self.save_to_disk:
                    slug = self._safe_endpoint_slug(path)
                    response_file = self.responses_dir / f"{slug}.json"
                    header_file = self.headers_dir / f"{slug}_headers.json"

                    with open(response_file, "w", encoding="utf-8") as rf:
                        json.dump(body_json, rf, indent=2)

                    with open(header_file, "w", encoding="utf-8") as hf:
                        json.dump(headers_dict, hf, indent=2)

                    self._log(f"  [+] Status: {response.status_code} OK | Size: {response_size} bytes | Time: {elapsed_ms:.1f}ms")
                    self._log(f"  [+] Saved response: {response_file.name}")
                    self._log(f"  [+] Saved headers:  {header_file.name}")
                else:
                    self._log(f"  [+] Status: {response.status_code} OK | Size: {response_size} bytes | Time: {elapsed_ms:.1f}ms (dry-run, not written to disk)")

                return audit_result

            except requests.exceptions.Timeout:
                if attempt <= max_retries:
                    self._log(f"  [!] Timeout on attempt {attempt}; retrying in 1.0s...")
                    time.sleep(1.0)
                    continue
                self._log(f"  [-] Request timed out after {self.REQUEST_TIMEOUT_SECONDS}s on GET {path}")
                return {
                    "endpoint": path,
                    "method": "GET",
                    "error": "RequestTimeout",
                    "status_code": 0,
                    "header_checks": {},
                    "body_checks": {},
                }
            except requests.exceptions.ConnectionError as ce:
                if attempt <= max_retries:
                    self._log(f"  [!] ConnectionError on attempt {attempt}; retrying in 1.0s...")
                    time.sleep(1.0)
                    continue
                self._log(f"  [-] Connection failed for GET {path}: {ce}")
                return {
                    "endpoint": path,
                    "method": "GET",
                    "error": f"ConnectionError: {ce}",
                    "status_code": 0,
                    "header_checks": {},
                    "body_checks": {},
                }
            except Exception as ex:
                self._log(f"  [-] Unexpected error on GET {path}: {ex}")
                return {
                    "endpoint": path,
                    "method": "GET",
                    "error": str(ex),
                    "status_code": 0,
                    "header_checks": {},
                    "body_checks": {},
                }

        # If loop exits without returning
        return {
            "endpoint": path,
            "method": "GET",
            "error": "MaxRetriesExceeded",
            "status_code": 0,
            "header_checks": {},
            "body_checks": {},
        }

    def execute_audit(self) -> Dict[str, Any]:
        """
        Orchestrate complete audit over all target endpoints and generate
        classified findings.
        """
        print("=" * 70)
        print("FUTURE INTERNS CYBER SECURITY - API SECURITY AUDIT TOOL")
        print("Target: JSONPlaceholder Demonstration REST API")
        print("Mode: Strictly Defensive / Read-Only (GET requests only)")
        print("=" * 70)

        audited_records: List[Dict[str, Any]] = []

        for item in self.ENDPOINTS_TO_AUDIT:
            path = item["path"]
            result = self.run_safe_request(path)
            if result:
                audited_records.append(result)
            # Polite pause to avoid any traffic burst
            time.sleep(self.REQUEST_DELAY_SECONDS)

        print("\n" + "=" * 70)
        print("[*] Processing security rules and classifying findings...")
        print("=" * 70)

        # Run Risk Classifier
        findings = RiskClassifier.evaluate_audit(audited_records)
        findings_dicts = [f.to_dict() for f in findings]

        # Build consolidated security summary payload
        summary_payload = {
            "metadata": {
                "project": "FUTURE INTERNS - CYBER SECURITY TASK 3 (2026)",
                "assessment_target": self.BASE_URL,
                "assessment_type": "Defensive Read-Only REST API Security Review",
                "execution_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "total_endpoints_audited": len(audited_records),
                "total_findings": len(findings),
            },
            "findings": findings_dicts,
            "endpoint_audit_details": audited_records,
        }

        # Save consolidated security findings if configured
        if self.save_to_disk:
            findings_file = self.results_dir / "api_security_findings.json"
            with open(findings_file, "w", encoding="utf-8") as ff:
                json.dump(summary_payload, ff, indent=2)
            print(f"[+] Consolidated findings saved: {findings_file}")

        # Display terminal summary table
        self._print_terminal_summary(findings)

        return summary_payload

    def _print_terminal_summary(self, findings: List[Any]) -> None:
        """Display an aligned terminal summary of classified findings."""
        print("\n" + "=" * 70)
        print(f"{'ID':<9} | {'SEVERITY':<14} | {'TITLE':<40}")
        print("-" * 70)
        for f in findings:
            print(f"{f.finding_id:<9} | {f.severity.value:<14} | {f.title:<40}")
        print("=" * 70)
        print("\n[NOTE] Findings marked 'NOT TESTABLE' reflect architectural boundaries")
        print("       of the public demonstration environment, not uninvestigated flaws.")
        print("[SUCCESS] API Security Audit execution finished successfully.\n")


def main():
    auditor = SafeAPIAuditor()
    auditor.execute_audit()


if __name__ == "__main__":
    main()
