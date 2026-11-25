from dataclasses import dataclass
from typing import Any


@dataclass
class RawFinding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_url: str
    evidence: dict[str, Any]


SECURITY_HEADER_RULES = [
    {
        "header": "strict-transport-security",
        "rule_id": "HDR_MISSING_HSTS",
        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
        "severity": "HIGH",
        "description": "Strict-Transport-Security header was not present in the HTTPS response.",
    },
    {
        "header": "content-security-policy",
        "rule_id": "HDR_MISSING_CSP",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "severity": "MEDIUM",
        "description": "Content-Security-Policy header was not set, increasing XSS impact risk.",
    },
    {
        "header": "x-frame-options",
        "rule_id": "HDR_MISSING_XFO",
        "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
        "severity": "MEDIUM",
        "description": "X-Frame-Options header is missing, allowing potential iframe clickjacking.",
    },
    {
        "header": "x-content-type-options",
        "rule_id": "HDR_MISSING_XCTO",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "LOW",
        "description": "X-Content-Type-Options: nosniff header was not found.",
    },
    {
        "header": "referrer-policy",
        "rule_id": "HDR_MISSING_REFERRER",
        "title": "Missing Referrer-Policy Header",
        "severity": "LOW",
        "description": "Referrer-Policy header is not configured.",
    },
]


def analyze_response_headers(url: str, headers: dict[str, str]) -> list[RawFinding]:
    normalized = {k.lower(): v[:200] for k, v in headers.items()}
    findings: list[RawFinding] = []

    for rule in SECURITY_HEADER_RULES:
        if rule["header"] not in normalized:
            findings.append(
                RawFinding(
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    affected_url=url,
                    evidence={
                        "missing_header": rule["header"],
                        "detail": rule["description"],
                    },
                )
            )

    for leak_header in ("server", "x-powered-by"):
        if leak_header in normalized and normalized[leak_header].strip():
            findings.append(
                RawFinding(
                    rule_id=f"INFO_LEAK_{leak_header.upper().replace('-', '_')}",
                    title=f"Technology Stack Exposed via '{leak_header}' Header",
                    severity="LOW",
                    affected_url=url,
                    evidence={
                        "header": leak_header,
                        "exposed_value": normalized[leak_header],
                    },
                )
            )

    return findings