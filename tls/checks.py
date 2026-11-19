"""TLS configuration checks for host dicts."""

import datetime

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
                       "MD5")
MODERN_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}


def _days_left(not_after):
    if not not_after:
        return None
    try:
        expiry = datetime.date.fromisoformat(str(not_after))
    except ValueError:
        return None
    return (expiry - datetime.date.today()).days


def check_one(host):
    """Return findings for one host dict."""
    name = host.get("host", "?")
    findings = []
    cert = host.get("cert") or {}

    days = _days_left(cert.get("not_after"))
    if days is None:
        findings.append({
            "check": "cert-unreadable", "severity": "MEDIUM",
            "object": name, "message": f"{name}: certificate expiry unknown",
        })
    elif days < 0:
        findings.append({
            "check": "cert-expired", "severity": "CRITICAL", "object": name,
            "message": f"{name}: certificate expired {-days} day(s) ago",
        })
    elif days < 30:
        findings.append({
            "check": "cert-expiring", "severity": "HIGH", "object": name,
            "message": f"{name}: certificate expires in {days} day(s)",
        })
    elif days < 90:
        findings.append({
            "check": "cert-expiring-soon", "severity": "MEDIUM",
            "object": name,
            "message": f"{name}: certificate expires in {days} day(s)",
        })

    if cert.get("self_signed"):
        findings.append({
            "check": "self-signed-cert", "severity": "HIGH", "object": name,
            "message": f"{name}: self-signed certificate",
        })

    protocols = host.get("protocols") or []
    for proto in protocols:
        if proto in WEAK_PROTOCOLS:
            findings.append({
                "check": "weak-protocol", "severity": "HIGH", "object": name,
                "message": f"{name}: weak protocol {proto} enabled",
            })
    if protocols and not (set(protocols) & MODERN_PROTOCOLS):
        findings.append({
            "check": "no-modern-tls", "severity": "MEDIUM", "object": name,
            "message": f"{name}: no TLS 1.2 or 1.3 offered",
        })

    for cipher in host.get("ciphers") or []:
        upper = str(cipher).upper()
        if any(marker in upper for marker in WEAK_CIPHER_MARKERS):
            findings.append({
                "check": "weak-cipher", "severity": "HIGH", "object": name,
                "message": f"{name}: weak cipher {cipher}",
            })
    return findings


def check_hosts(hosts):
    """Return all findings for a list of host dicts."""
    findings = []
    for host in hosts:
        findings.extend(check_one(host))
    return findings
