"""Host inventory loading and live TLS probing."""

import json
import socket
import ssl


def load_hosts(path):
    """Load a host inventory JSON file (list of host dicts)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("inventory must contain a host object or a list")


def live_check(host, port=443, timeout=10):
    """Perform a real TLS handshake and return a host dict.

    Uses the standard library only. Raises OSError on connection or
    TLS failure.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            version = tls.version()
    not_after = None
    if cert and "notAfter" in cert:
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        import datetime
        not_after = datetime.datetime.fromtimestamp(
            not_after, datetime.timezone.utc).date().isoformat()
    issuer = ""
    if cert:
        issuer = " / ".join(
            "=".join(part) for rdn in cert.get("issuer", [])
            for part in rdn)
    return {
        "host": host,
        "port": port,
        "cert": {"not_after": not_after, "issuer": issuer,
                 "self_signed": False},
        "protocols": [version] if version else [],
        "ciphers": [cipher[0]] if cipher else [],
    }


def check_host(host):
    """Return findings for one host dict (offline or live-probed)."""
    from .checks import check_one
    return check_one(host)
