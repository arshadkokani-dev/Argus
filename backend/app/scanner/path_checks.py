import httpx
from app.scanner.header_checks import RawFinding

SENSITIVE_PATH_SIGNATURES = [
    {
        "path": "/.env",
        "rule_id": "EXPOSED_ENV_FILE",
        "title": "Environment Configuration File (/.env) Publicly Accessible",
        "severity": "CRITICAL",
        "markers": ("DB_PASSWORD=", "SECRET_KEY=", "API_KEY=", "APP_KEY=", "DATABASE_URL="),
    },
    {
        "path": "/.git/HEAD",
        "rule_id": "EXPOSED_GIT_REPOSITORY",
        "title": "Exposed Git Repository Metadata (/.git/HEAD)",
        "severity": "HIGH",
        "markers": ("ref: refs/",),
    },
]


async def check_exposed_paths(base_url: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    clean_base = base_url.rstrip("/")

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        for check in SENSITIVE_PATH_SIGNATURES:
            target_url = f"{clean_base}{check['path']}"
            try:
                response = await client.get(target_url)
                if response.status_code == 200:
                    body_preview = response.text[:500]
                    if any(marker in body_preview for marker in check["markers"]):
                        findings.append(
                            RawFinding(
                                rule_id=check["rule_id"],
                                title=check["title"],
                                severity=check["severity"],
                                affected_url=target_url,
                                evidence={
                                    "status_code": 200,
                                    "matched_signature": True,
                                    "snippet": body_preview[:120],
                                },
                            )
                        )
            except httpx.HTTPError:
                continue

    return findings