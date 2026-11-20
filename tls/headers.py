"""HTTP security-header checks over a live HTTPS connection."""

import http.client
import ssl

MIN_HSTS_MAX_AGE = 31536000  # one year, in seconds


def _max_age(hsts_value):
    for part in hsts_value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def check_headers(host, port=443, timeout=10, path="/"):
    """Fetch response headers and flag missing security headers.

    Raises OSError on connection/TLS failure.
    """
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                       context=context)
    try:
        conn.request("HEAD", path)
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()

    findings = []
    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append({
            "check": "hsts-missing", "severity": "MEDIUM", "object": host,
            "message": f"{host}: no Strict-Transport-Security header",
        })
    else:
        age = _max_age(hsts)
        if age is not None and age < MIN_HSTS_MAX_AGE:
            findings.append({
                "check": "hsts-short", "severity": "LOW", "object": host,
                "message": f"{host}: HSTS max-age {age} is under one year",
            })
    if "x-content-type-options" not in headers:
        findings.append({
            "check": "header-missing", "severity": "LOW", "object": host,
            "message": f"{host}: no X-Content-Type-Options header",
        })
    if "x-frame-options" not in headers \
            and "content-security-policy" not in headers:
        findings.append({
            "check": "header-missing", "severity": "LOW", "object": host,
            "message": f"{host}: no X-Frame-Options or Content-Security-Policy header",
        })
    return findings
