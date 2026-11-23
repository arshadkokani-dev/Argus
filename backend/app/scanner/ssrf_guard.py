import ipaddress
import socket


class SSRFBlockedError(Exception):
    """Raised when a target domain resolves to a private or restricted IP address."""


def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def resolve_and_validate_host(hostname: str) -> list[str]:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve hostname: {hostname}") from exc

    validated_ips: list[str] = []
    for entry in addr_info:
        ip_str = entry[4][0]
        if not is_public_ip(ip_str):
            raise SSRFBlockedError(
                f"Blocked unsafe target IP ({ip_str}) for hostname {hostname}."
            )
        if ip_str not in validated_ips:
            validated_ips.append(ip_str)

    if not validated_ips:
        raise SSRFBlockedError(f"No valid public IP addresses found for {hostname}.")

    return validated_ips