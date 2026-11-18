"""
generate_pdf.py - Professional PDF Report Generator
Future Interns Cyber Security Task 3 (2026)

Compiles the API Security Risk Analysis Report into an enterprise-grade
PDF document with executive cover page, stylized tables, callout boxes,
running headers/footers, and page numbering using ReportLab.
"""

import os
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
OUTPUT_PDF = PROJECT_ROOT / "report" / "API_Security_Risk_Analysis_Report.pdf"


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page count:
    'Page X of Y' in footer, plus running header on subsequent pages.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Do not draw headers/footers on cover page (page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Running Header
        self.drawString(
            54,
            11 * 72 - 36,
            "FUTURE INTERNS (2026) — API SECURITY RISK ANALYSIS REPORT | CONFIDENTIAL",
        )
        self.setStrokeColor(colors.HexColor("#CBD5E0"))
        self.setLineWidth(0.5)
        self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 32, page_str)
        self.drawString(
            54,
            32,
            "Target: https://jsonplaceholder.typicode.com | Strictly Defensive Read-Only Assessment",
        )
        self.line(54, 44, 8.5 * 72 - 54, 44)

        self.restoreState()


def build_pdf_report():
    """Compiles complete professional security assessment PDF."""
    OUTPUT_PDF.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Define custom corporate color palette
    c_primary = colors.HexColor("#0D233A")    # Deep Navy
    c_secondary = colors.HexColor("#1A56DB")  # Cobalt Blue
    c_dark = colors.HexColor("#1E293B")       # Dark Charcoal
    c_muted = colors.HexColor("#64748B")      # Slate Gray
    c_light_bg = colors.HexColor("#F8FAFC")   # Ultra-light background
    c_accent = colors.HexColor("#D97706")     # Amber / Accent
    c_success = colors.HexColor("#059669")    # Emerald

    # Typography styles
    styles.add(ParagraphStyle(
        name="DocTitle",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_primary,
        alignment=1,  # Center
    ))
    styles.add(ParagraphStyle(
        name="DocSubtitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_secondary,
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        name="DocMeta",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=c_muted,
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        name="SecHeading1",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="SecHeading2",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=c_secondary,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="ReportBody",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_dark,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="ReportBullet",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_dark,
        leftIndent=14,
        spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        name="TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=0,
    ))
    styles.add(ParagraphStyle(
        name="TableCell",
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=c_dark,
    ))
    styles.add(ParagraphStyle(
        name="TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=c_dark,
    ))
    styles.add(ParagraphStyle(
        name="CodeText",
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#831843"),
    ))
    styles.add(ParagraphStyle(
        name="CalloutText",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0C4A6E"),
    ))

    story = []

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph("FUTURE INTERNS — CYBER SECURITY (2026)", styles["DocSubtitle"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("API SECURITY RISK ANALYSIS REPORT", styles["DocTitle"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("A Defensive, Read-Only Security Assessment of JSONPlaceholder REST API", styles["DocMeta"]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=2, color=c_secondary, spaceBefore=5, spaceAfter=25))

    # Cover Summary Box
    cover_info = [
        [Paragraph("<b>Target Domain:</b>", styles["TableCellBold"]), Paragraph("https://jsonplaceholder.typicode.com", styles["TableCell"])],
        [Paragraph("<b>Assessment Type:</b>", styles["TableCellBold"]), Paragraph("Read-Only REST API Security Assessment & Header Audit", styles["TableCell"])],
        [Paragraph("<b>Assessment Standard:</b>", styles["TableCellBold"]), Paragraph("OWASP API Security Top 10 (2023) & Shieldfy Checklist", styles["TableCell"])],
        [Paragraph("<b>Auditor Level:</b>", styles["TableCellBold"]), Paragraph("Senior Application Security (AppSec) Engineer / Auditor", styles["TableCell"])],
        [Paragraph("<b>Host Environment:</b>", styles["TableCellBold"]), Paragraph("Windows 11 | Python 3.14.3 | VS Code | GitHub Desktop", styles["TableCell"])],
        [Paragraph("<b>Date of Execution:</b>", styles["TableCellBold"]), Paragraph("November 2026", styles["TableCell"])],
        [Paragraph("<b>Deliverable Scope:</b>", styles["TableCellBold"]), Paragraph("Task 3 Final Technical Assessment Deliverable", styles["TableCell"])],
        [Paragraph("<b>Classification:</b>", styles["TableCellBold"]), Paragraph("CONFIDENTIAL / SECURITY AUDIT REPORT", styles["TableCellBold"])],
    ]
    t_cover = Table(cover_info, colWidths=[1.8 * inch, 4.7 * inch])
    t_cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t_cover)

    story.append(Spacer(1, 30))

    # Executive Callout Banner
    exec_callout = [
        [Paragraph(
            "<b>ETHICAL AUDIT COMPLIANCE STATEMENT:</b><br/>"
            "This assessment was executed strictly under defensive, read-only principles. Only 6 controlled "
            "HTTP GET requests were transmitted with polite delays and a strict 5.0-second timeout. No state-altering "
            "methods (POST, PUT, PATCH, DELETE), fuzzing, brute force, token forgery, or Denial of Service attacks "
            "were conducted. When a security control cannot be tested against this mock service, it is explicitly "
            "designated as <b>NOT TESTABLE WITH SELECTED DEMO API</b>.",
            styles["CalloutText"]
        )]
    ]
    t_callout = Table(exec_callout, colWidths=[6.5 * inch])
    t_callout.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E0F2FE")),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#0284C7")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(t_callout)

    story.append(PageBreak())

    # =========================================================================
    # 2. EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("1. Executive Summary", styles["SecHeading1"]))
    story.append(Paragraph(
        "During November 2026, a defensive, read-only API security risk assessment was conducted against the "
        "public JSONPlaceholder REST demonstration service (https://jsonplaceholder.typicode.com). The purpose was "
        "to evaluate architectural REST patterns, response headers, data minimization, rate limiting, and access "
        "control mechanisms against the OWASP API Security Top 10 (2023) benchmark.",
        styles["ReportBody"]
    ))
    story.append(Paragraph("<b>Key Assessment Takeaways:</b>", styles["ReportBody"]))
    story.append(Paragraph("• <b>Target Architecture:</b> JSONPlaceholder is an intentional open mock API designed for frontend testing; it maintains no private databases or user sessions.", styles["ReportBullet"]))
    story.append(Paragraph("• <b>Defense-in-Depth Opportunities (LOW):</b> Identifies backend framework banner disclosure (<code>x-powered-by: Express</code>), missing HSTS (<code>Strict-Transport-Security</code>), and a 12-hour public cache policy.", styles["ReportBullet"]))
    story.append(Paragraph("• <b>Simulated PII Exposure (INFORMATIONAL):</b> Returning full synthetic addresses, emails, and GPS coordinates demonstrates real-world Excessive Data Exposure (OWASP API3:2023) risks.", styles["ReportBullet"]))
    story.append(Paragraph("• <b>Architectural Boundaries (NOT TESTABLE):</b> Broken Object Level Authorization (BOLA/API1) and injection resistance were designated <b>NOT TESTABLE WITH SELECTED DEMO API</b> due to mock environment constraints and ethical boundaries.", styles["ReportBullet"]))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 3. OBJECTIVES & 4. API OVERVIEW
    # =========================================================================
    story.append(Paragraph("2. Assessment Objectives & Target Overview", styles["SecHeading1"]))
    story.append(Paragraph(
        "<b>Objectives:</b> Validate defensive read-only API auditing techniques, inspect response headers, "
        "evaluate data exposure, review rate-limiting metadata, and deliver an actionable SaaS remediation plan.",
        styles["ReportBody"]
    ))
    story.append(Paragraph(
        "<b>Target API:</b> JSONPlaceholder (https://jsonplaceholder.typicode.com) maintained by Typicode. "
        "Infrastructure is fronted by Cloudflare edge reverse proxies with backend services implemented in Node.js/Express.",
        styles["ReportBody"]
    ))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. SCOPE & 6. TOOLS & 7. METHODOLOGY
    # =========================================================================
    story.append(Paragraph("3. Scope, Tools, & Methodology", styles["SecHeading1"]))
    story.append(Paragraph(
        "Scope was restricted to 6 specific GET endpoints. All operations were orchestrated via a custom Python tool "
        "(<code>src/api_audit.py</code>) incorporating strict host validation and non-redirect chasing. The methodology "
        "spanned 5 phases: Passive Reconnaissance, Tool Development, Controlled Execution, Security Inspection, and "
        "Production SaaS Remediation Modeling.",
        styles["ReportBody"]
    ))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 8. ENDPOINTS TESTED & 9. OBSERVED RESULTS
    # =========================================================================
    story.append(Paragraph("4. Endpoints Tested & Empirical Results", styles["SecHeading1"]))
    story.append(Paragraph(
        "All requests completed with HTTP 200 OK. Empirical metrics captured during execution are summarized below:",
        styles["ReportBody"]
    ))

    endpoint_table_data = [
        [
            Paragraph("Endpoint", styles["TableHeader"]),
            Paragraph("Method", styles["TableHeader"]),
            Paragraph("Status", styles["TableHeader"]),
            Paragraph("Size", styles["TableHeader"]),
            Paragraph("Latency", styles["TableHeader"]),
            Paragraph("Payload Structure", styles["TableHeader"]),
        ],
        [
            Paragraph("/posts", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("27.5 KB", styles["TableCell"]),
            Paragraph("511.5 ms", styles["TableCell"]),
            Paragraph("Array of 100 mock post records", styles["TableCell"]),
        ],
        [
            Paragraph("/posts/1", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("292 B", styles["TableCell"]),
            Paragraph("94.4 ms", styles["TableCell"]),
            Paragraph("Single post entity (4 keys: userId, id, title, body)", styles["TableCell"]),
        ],
        [
            Paragraph("/users", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("5.6 KB", styles["TableCell"]),
            Paragraph("63.7 ms", styles["TableCell"]),
            Paragraph("Array of 10 full user profiles with PII", styles["TableCell"]),
        ],
        [
            Paragraph("/users/1", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("509 B", styles["TableCell"]),
            Paragraph("88.9 ms", styles["TableCell"]),
            Paragraph("Single user profile (email, phone, geo)", styles["TableCell"]),
        ],
        [
            Paragraph("/comments?postId=1", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("1.5 KB", styles["TableCell"]),
            Paragraph("89.3 ms", styles["TableCell"]),
            Paragraph("Array of 5 query-filtered comments", styles["TableCell"]),
        ],
        [
            Paragraph("/todos/1", styles["TableCellBold"]),
            Paragraph("GET", styles["TableCell"]),
            Paragraph("200 OK", styles["TableCell"]),
            Paragraph("83 B", styles["TableCell"]),
            Paragraph("128.2 ms", styles["TableCell"]),
            Paragraph("Single task record with boolean state", styles["TableCell"]),
        ],
    ]
    t_endpoints = Table(endpoint_table_data, colWidths=[1.4 * inch, 0.6 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 2.4 * inch])
    t_endpoints.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_endpoints)

    story.append(PageBreak())

    # =========================================================================
    # 10. AUTHENTICATION & 11. AUTHORIZATION & 12. DATA EXPOSURE
    # =========================================================================
    story.append(Paragraph("5. Core AppSec Domain Evaluations", styles["SecHeading1"]))

    story.append(Paragraph("5.1 Authentication Assessment", styles["SecHeading2"]))
    story.append(Paragraph(
        "All six audited endpoints responded without requiring credentials, API keys, or Bearer tokens. "
        "Because JSONPlaceholder maintains no user accounts or token signing logic, authentication strength is "
        "<b>NOT TESTABLE WITH SELECTED DEMO API</b>. In an enterprise SaaS environment, exposing operational "
        "data without authentication constitutes OWASP API2:2023 - Broken Authentication.",
        styles["ReportBody"]
    ))

    story.append(Paragraph("5.2 Authorization Assessment (BOLA / BFLA)", styles["SecHeading2"]))
    story.append(Paragraph(
        "Endpoints support sequential integer lookup (/users/1, /users/2) across all resources. While structurally "
        "similar to Broken Object Level Authorization (BOLA / OWASP API1), this is benign on mock data. Validating "
        "real BOLA requires testing privilege boundaries between distinct user sessions; since no user tenancy exists, "
        "this is marked <b>NOT TESTABLE WITH SELECTED DEMO API</b>.",
        styles["ReportBody"]
    ))

    story.append(Paragraph("5.3 Data Minimization & Excessive Data Exposure", styles["SecHeading2"]))
    story.append(Paragraph(
        "Querying <code>/users/1</code> returns complete synthetic PII: email (<code>Sincere@april.biz</code>), "
        "phone (<code>1-770-736-8031</code>), address, and GPS coordinates (<code>lat: -37.3159, lng: 81.1496</code>). "
        "In production, returning unmasked PII without Data Transfer Object (DTO) filtering violates OWASP API3:2023 "
        "and data privacy regulations (GDPR/CCPA).",
        styles["ReportBody"]
    ))

    story.append(Paragraph("5.4 Rate Limiting & Input Validation", styles["SecHeading2"]))
    story.append(Paragraph(
        "Headers actively expose <code>x-ratelimit-limit: 3600000</code> and remaining quotas. Under ethical testing rules, "
        "rate limit exhaustion and active injection payloads were strictly prohibited. Both areas are classified as "
        "<b>NOT TESTABLE WITH SELECTED DEMO API</b>.",
        styles["ReportBody"]
    ))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 15. SECURITY HEADERS ASSESSMENT TABLE
    # =========================================================================
    story.append(Paragraph("6. Security Headers Compliance Evaluation", styles["SecHeading1"]))
    story.append(Paragraph(
        "Response headers were inspected across all audited calls against production hardening baselines:",
        styles["ReportBody"]
    ))

    header_table_data = [
        [
            Paragraph("Header Name", styles["TableHeader"]),
            Paragraph("Observed Status", styles["TableHeader"]),
            Paragraph("Expected SaaS Baseline", styles["TableHeader"]),
            Paragraph("Rating", styles["TableHeader"]),
            Paragraph("Security & Operational Context", styles["TableHeader"]),
        ],
        [
            Paragraph("Strict-Transport-Security", styles["TableCellBold"]),
            Paragraph("<b>Absent on all 6 endpoints</b>", styles["TableCell"]),
            Paragraph("max-age=31536000; preload", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("HSTS absent; browsers can attempt unencrypted HTTP fallback", styles["TableCell"]),
        ],
        [
            Paragraph("X-Content-Type-Options", styles["TableCellBold"]),
            Paragraph("<b>Present on all 6:</b> nosniff", styles["TableCell"]),
            Paragraph("nosniff", styles["TableCell"]),
            Paragraph("<font color='#059669'><b>COMPLIANT</b></font>", styles["TableCell"]),
            Paragraph("Properly prevents MIME confusion sniffing in browsers", styles["TableCell"]),
        ],
        [
            Paragraph("Content-Security-Policy", styles["TableCellBold"]),
            Paragraph("<b>Absent on all 6 endpoints</b>", styles["TableCell"]),
            Paragraph("default-src 'none'", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("HTML defense; recommended defense-in-depth on raw JSON tabs", styles["TableCell"]),
        ],
        [
            Paragraph("Cache-Control", styles["TableCellBold"]),
            Paragraph("<b>Present on all 6:</b> max-age=43200", styles["TableCell"]),
            Paragraph("no-store, no-cache, private", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW (Demo)</b></font>", styles["TableCell"]),
            Paragraph("12h public cache is safe for mock data, high-risk for SaaS PII", styles["TableCell"]),
        ],
        [
            Paragraph("X-Powered-By", styles["TableCellBold"]),
            Paragraph("<b>Present on all 6:</b> Express", styles["TableCell"]),
            Paragraph("<i>Suppressed</i>", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("Discloses Node.js/Express backend technology (CWE-200)", styles["TableCell"]),
        ],
        [
            Paragraph("Server", styles["TableCellBold"]),
            Paragraph("<b>Present on all 6:</b> cloudflare", styles["TableCell"]),
            Paragraph("Generic / Obfuscated", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("Edge CDN identification is standard industry practice", styles["TableCell"]),
        ],
        [
            Paragraph("Via", styles["TableCellBold"]),
            Paragraph("<b>Present on /todos/1:</b> 2.0 heroku-router", styles["TableCell"]),
            Paragraph("<i>Suppressed</i>", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("Discloses Heroku backend routing infrastructure", styles["TableCell"]),
        ],
        [
            Paragraph("Access-Control-Allow-Credentials", styles["TableCellBold"]),
            Paragraph("<b>Present on all 6:</b> true", styles["TableCell"]),
            Paragraph("Strict origin whitelist", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("Permits browser frontend demos; must restrict in production", styles["TableCell"]),
        ],
        [
            Paragraph("X-RateLimit-Limit", styles["TableCellBold"]),
            Paragraph("3600000 (5 EPs) / 1000 (/todos/1)", styles["TableCell"]),
            Paragraph("Tiered per tenant/user", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("Transparent rate limit quota metadata exposed in headers", styles["TableCell"]),
        ],
    ]
    t_headers = Table(header_table_data, colWidths=[1.5 * inch, 1.1 * inch, 1.3 * inch, 0.8 * inch, 1.8 * inch])
    t_headers.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_headers)

    story.append(PageBreak())

    # =========================================================================
    # 16. MASTER FINDINGS & RISK CLASSIFICATION TABLE
    # =========================================================================
    story.append(Paragraph("7. Master Risk Classification Table", styles["SecHeading1"]))
    story.append(Paragraph(
        "Consolidated findings categorized by severity, separating verified observations from architectural boundaries:",
        styles["ReportBody"]
    ))

    findings_table_data = [
        [
            Paragraph("ID", styles["TableHeader"]),
            Paragraph("Title", styles["TableHeader"]),
            Paragraph("Affected Endpoint(s)", styles["TableHeader"]),
            Paragraph("Severity", styles["TableHeader"]),
            Paragraph("Empirical Evidence", styles["TableHeader"]),
            Paragraph("Remediation Summary", styles["TableHeader"]),
        ],
        [
            Paragraph("FIND-01", styles["TableCellBold"]),
            Paragraph("Technology Fingerprinting via X-Powered-By", styles["TableCell"]),
            Paragraph("All 6 Endpoints", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("x-powered-by: Express (all 6)", styles["CodeText"]),
            Paragraph("Disable header via app.disable('x-powered-by')", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-02", styles["TableCellBold"]),
            Paragraph("Missing HSTS Transport Security Header", styles["TableCell"]),
            Paragraph("All 6 Endpoints", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("HSTS absent across all 6", styles["TableCell"]),
            Paragraph("Set Strict-Transport-Security: max-age=31536000", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-03", styles["TableCellBold"]),
            Paragraph("Permissive Cache-Control on Data Endpoints", styles["TableCell"]),
            Paragraph("All 6 Endpoints", styles["TableCell"]),
            Paragraph("<font color='#D97706'><b>LOW</b></font>", styles["TableCell"]),
            Paragraph("max-age=43200 (all 6)", styles["CodeText"]),
            Paragraph("Set Cache-Control: no-store, private on SaaS APIs", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-04", styles["TableCellBold"]),
            Paragraph("Simulated Excessive Data Exposure (Synthetic PII)", styles["TableCell"]),
            Paragraph("/users, /users/1", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("Unmasked email, phone, address, geo", styles["TableCell"]),
            Paragraph("Enforce Data Transfer Objects (DTOs) & PII masking", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-05", styles["TableCellBold"]),
            Paragraph("Exposed Rate-Limiting Quota Metadata", styles["TableCell"]),
            Paragraph("All 6 Endpoints", styles["TableCell"]),
            Paragraph("<b>INFO</b>", styles["TableCell"]),
            Paragraph("limit: 3600000 (5 EPs) / 1000 (/todos/1)", styles["CodeText"]),
            Paragraph("Adopt standard IETF RateLimit; enforce token buckets", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-06", styles["TableCellBold"]),
            Paragraph("Object-Level & Functional Authorization", styles["TableCell"]),
            Paragraph("All Endpoints (/posts/1, etc.)", styles["TableCell"]),
            Paragraph("<font color='#64748B'><b>NOT TESTABLE</b></font>", styles["TableCell"]),
            Paragraph("Demo has no auth/tenancy engine", styles["TableCell"]),
            Paragraph("Mandate OAuth 2.0 and contextual ownership checks", styles["TableCell"]),
        ],
        [
            Paragraph("FIND-07", styles["TableCellBold"]),
            Paragraph("Input Validation & Injection Resistance", styles["TableCell"]),
            Paragraph("/comments?postId=1", styles["TableCell"]),
            Paragraph("<font color='#64748B'><b>NOT TESTABLE</b></font>", styles["TableCell"]),
            Paragraph("Ethical read-only scope boundary", styles["TableCell"]),
            Paragraph("Implement strict schema validation & parameterized queries", styles["TableCell"]),
        ],
    ]
    t_findings = Table(findings_table_data, colWidths=[0.6 * inch, 1.6 * inch, 0.8 * inch, 0.9 * inch, 1.2 * inch, 1.4 * inch])
    t_findings.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_findings)

    story.append(Spacer(1, 10))

    # =========================================================================
    # 17. BUSINESS IMPACT & 18. REMEDIATION SUMMARY
    # =========================================================================
    story.append(Paragraph("8. Business Impact & Production SaaS Remediation Plan", styles["SecHeading1"]))
    story.append(Paragraph(
        "<b>Executive Business Impact:</b> In production systems, failing to secure API endpoints leads to catastrophic "
        "business risks: regulatory penalties under GDPR/CCPA for PII leaks (up to 4% global turnover), loss of customer "
        "trust following data exfiltration, and unplanned downtime resulting from unbounded queries and unthrottled scraping.",
        styles["ReportBody"]
    ))
    story.append(Paragraph("<b>Twelve SaaS Production Hardening Recommendations:</b>", styles["ReportBody"]))
    story.append(Paragraph("1. <b>Require Authentication:</b> Protect all non-public routes with OAuth 2.0 / OpenID Connect.", styles["ReportBullet"]))
    story.append(Paragraph("2. <b>Short-Lived Tokens:</b> Issue 15-minute asymmetric JWTs (RS256) with refresh token rotation.", styles["ReportBullet"]))
    story.append(Paragraph("3. <b>Enforce Object Authorization (BOLA):</b> Verify resource ownership on every single request.", styles["ReportBullet"]))
    story.append(Paragraph("4. <b>Data Minimization (BOPLA):</b> Return strict DTO schemas and mask customer PII fields.", styles["ReportBullet"]))
    story.append(Paragraph("5. <b>Rate Limiting:</b> Enforce Redis token buckets returning HTTP 429 and Retry-After headers.", styles["ReportBullet"]))
    story.append(Paragraph("6. <b>Input Validation:</b> Enforce allowlists, Pydantic schemas, and parameterized queries.", styles["ReportBullet"]))
    story.append(Paragraph("7. <b>CORS Hardening:</b> Replace wildcards with strict origin whitelists.", styles["ReportBullet"]))
    story.append(Paragraph("8. <b>HTTPS & Security Headers:</b> Enforce TLS 1.3, HSTS (max-age=31536000), and nosniff.", styles["ReportBullet"]))
    story.append(Paragraph("9. <b>Suppress Fingerprinting:</b> Remove <code>X-Powered-By</code> and internal server banners.", styles["ReportBullet"]))
    story.append(Paragraph("10. <b>Masked Security Logging:</b> Centralize audit trails in SIEM while auto-scrubbing credentials.", styles["ReportBullet"]))
    story.append(Paragraph("11. <b>Sanitized Errors:</b> Adopt RFC 7807 Problem Details; never leak database traces.", styles["ReportBullet"]))
    story.append(Paragraph("12. <b>OpenAPI Governance:</b> Maintain versioned specs and integrate CI/CD security linting.", styles["ReportBullet"]))

    story.append(Spacer(1, 10))

    # =========================================================================
    # 19. LIMITATIONS, 20. CONCLUSION & 21. REFERENCES
    # =========================================================================
    story.append(Paragraph("9. Limitations, Conclusion, & References", styles["SecHeading1"]))
    story.append(Paragraph(
        "<b>Testing Limitations:</b> Strictly read-only GET requests were issued. No credentials, tokens, or injection payloads "
        "were transmitted. Synthetic fixtures prevented real PII disclosure. <b>Conclusion:</b> JSONPlaceholder functions "
        "safely as a public demo API; applying the 12-point remediation blueprint ensures enterprise SaaS security. "
        "<b>References:</b> OWASP API Security Top 10 (2023), Shieldfy Checklist, RFC 6797 (HSTS), RFC 7234 (Caching), RFC 7807 (Errors).",
        styles["ReportBody"]
    ))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated professional PDF report: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf_report()
