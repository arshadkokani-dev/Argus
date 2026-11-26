import socket
import ssl
from datetime import datetime, timezone

from app.scanner.header_checks import RawFinding


def inspect_tls_certificate(hostname: str, port: int = 443) -> list[RawFinding]:
    target_url = f"https://{hostname}"
    findings: list[RawFinding] = []
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                protocol = tls_sock.version()
                cert = tls_sock.getpeercert()

                if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append(
                        RawFinding(
                            rule_id="TLS_WEAK_PROTOCOL",
                            title=f"Deprecated TLS Protocol Enabled ({protocol})",
                            severity="HIGH",
                            affected_url=target_url,
                            evidence={"negotiated_protocol": protocol},
                        )
                    )

                if cert and "notAfter" in cert:
                    expiry_str = cert["notAfter"]
                    expiry_dt = datetime.strptime(
                        expiry_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

                    if days_remaining < 0:
                        findings.append(
                            RawFinding(
                                rule_id="TLS_CERT_EXPIRED",
                                title="TLS Certificate Has Expired",
                                severity="CRITICAL",
                                affected_url=target_url,
                                evidence={
                                    "expires_at": expiry_str,
                                    "days_remaining": days_remaining,
                                },
                            )
                        )
                    elif days_remaining <= 14:
                        findings.append(
                            RawFinding(
                                rule_id="TLS_CERT_EXPIRING_SOON",
                                title=f"TLS Certificate Expiring in {days_remaining} Day(s)",
                                severity="MEDIUM",
                                affected_url=target_url,
                                evidence={
                                    "expires_at": expiry_str,
                                    "days_remaining": days_remaining,
                                },
                            )
                        )

    except ssl.SSLCertVerificationError as exc:
        findings.append(
            RawFinding(
                rule_id="TLS_CERT_INVALID",
                title="Invalid or Untrusted TLS Certificate",
                severity="CRITICAL",
                affected_url=target_url,
                evidence={"error": str(exc)[:200]},
            )
        )
    except (socket.timeout, OSError) as exc:
        findings.append(
            RawFinding(
                rule_id="HTTPS_UNAVAILABLE",
                title="HTTPS Connection Failed or Port 443 Unreachable",
                severity="HIGH",
                affected_url=target_url,
                evidence={"error": str(exc)[:200]},
            )
        )

    return findings