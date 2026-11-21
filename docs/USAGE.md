# Usage

## Auditing an inventory

```bash
python3 run.py hosts.json
python3 run.py hosts.json --json    # machine-readable output
python3 run.py hosts.json --grade   # A–F grade per host
```

Inventory format — a JSON list of host objects:

```json
[
  {
    "host": "bad.acme.example",
    "port": 443,
    "cert": {"not_after": "2026-11-25", "self_signed": false},
    "protocols": ["TLSv1.1", "TLSv1.2"],
    "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384", "DES-CBC3-SHA"]
  }
]
```

## Live checks

```bash
python3 run.py --live example.com
python3 run.py --live example.com --headers example.com
```

`--live` performs a real TLS handshake and reports the negotiated
protocol, cipher, and presented certificate. `--headers` fetches the
HTTPS response headers and checks HSTS and other security headers.
Both need network access and fail closed with a clear error.

## Grading

CRITICAL −40, HIGH −20, MEDIUM −10, LOW −5 from 100: A ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 60, otherwise F.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| cert-expired | CRITICAL | certificate past its not-after date |
| cert-expiring | HIGH | certificate expires in under 30 days |
| self-signed-cert | HIGH | self-signed certificate |
| weak-protocol | HIGH | SSLv3 / TLS 1.0 / TLS 1.1 enabled |
| weak-cipher | HIGH | RC4, DES, 3DES, NULL, EXPORT, or anon cipher |
| cert-expiring-soon | MEDIUM | certificate expires in under 90 days |
| no-modern-tls | MEDIUM | no TLS 1.2 or 1.3 offered |
| cert-unreadable | MEDIUM | certificate expiry unknown |
| hsts-missing | MEDIUM | no Strict-Transport-Security header |
| hsts-short | LOW | HSTS max-age under one year |
| header-missing | LOW | missing X-Content-Type-Options / framing header |

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```
