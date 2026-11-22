import httpx
from app.models.target import VerificationMethod


async def verify_domain_ownership(
    domain: str,
    expected_token: str,
    method: VerificationMethod,
) -> bool:
    try:
        if method == VerificationMethod.WELL_KNOWN_FILE:
            url = f"https://{domain}/.well-known/argus-verify.txt"
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                response = await client.get(url)
                if response.status_code == 200 and expected_token in response.text:
                    return True
            return False

        if method == VerificationMethod.DNS_TXT:
            # Query Cloudflare DNS-over-HTTPS so no extra C-compiler dependency is needed
            doh_url = f"https://cloudflare-dns.com{domain}&type=TXT"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    doh_url, headers={"Accept": "application/dns-json"}
                )
                if response.status_code == 200:
                    answers = response.json().get("Answer", [])
                    return any(expected_token in ans.get("data", "") for ans in answers)
            return False
    except Exception:
        return False

    return False