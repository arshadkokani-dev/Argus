from app.scanner.cookie_checks import analyze_cookies
from app.scanner.header_checks import analyze_response_headers


def test_analyze_response_headers_detects_missing_and_leaks():
    headers = {
        "Content-Type": "text/html",
        "Server": "nginx/1.24.0",
        "X-Content-Type-Options": "nosniff",
    }
    findings = analyze_response_headers("https://example.com", headers)
    rule_ids = {f.rule_id for f in findings}

    assert "HDR_MISSING_HSTS" in rule_ids
    assert "HDR_MISSING_CSP" in rule_ids
    assert "HDR_MISSING_XFO" in rule_ids
    assert "HDR_MISSING_REFERRER" in rule_ids
    assert "HDR_MISSING_XCTO" not in rule_ids
    assert "INFO_LEAK_SERVER" in rule_ids


def test_analyze_cookies_detects_insecure_flags():
    cookies = ["session_id=abc123; Path=/; HttpOnly"]
    findings = analyze_cookies("https://example.com", cookies)
    rule_ids = {f.rule_id for f in findings}

    assert "COOKIE_MISSING_SECURE" in rule_ids
    assert "COOKIE_MISSING_SAMESITE" in rule_ids
    assert "COOKIE_MISSING_HTTPONLY" not in rule_ids