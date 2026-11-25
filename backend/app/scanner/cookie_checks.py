from app.scanner.header_checks import RawFinding


def analyze_cookies(url: str, set_cookie_headers: list[str]) -> list[RawFinding]:
    findings: list[RawFinding] = []

    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
        if not parts:
            continue

        cookie_name = parts[0].split("=")[0].strip()[:80]
        flags_lower = {p.lower().split("=")[0].strip() for p in parts[1:]}

        if "secure" not in flags_lower:
            findings.append(
                RawFinding(
                    rule_id="COOKIE_MISSING_SECURE",
                    title=f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                    severity="MEDIUM",
                    affected_url=url,
                    evidence={
                        "cookie_name": cookie_name,
                        "missing_flag": "Secure",
                        "raw_preview": raw_cookie[:150],
                    },
                )
            )

        if "httponly" not in flags_lower:
            findings.append(
                RawFinding(
                    rule_id="COOKIE_MISSING_HTTPONLY",
                    title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                    severity="MEDIUM",
                    affected_url=url,
                    evidence={
                        "cookie_name": cookie_name,
                        "missing_flag": "HttpOnly",
                        "raw_preview": raw_cookie[:150],
                    },
                )
            )

        if "samesite" not in flags_lower:
            findings.append(
                RawFinding(
                    rule_id="COOKIE_MISSING_SAMESITE",
                    title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    severity="LOW",
                    affected_url=url,
                    evidence={
                        "cookie_name": cookie_name,
                        "missing_flag": "SameSite",
                        "raw_preview": raw_cookie[:150],
                    },
                )
            )

    return findings