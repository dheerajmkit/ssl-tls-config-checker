# ssl-tls-config-checker

Audits TLS configurations from a host inventory (JSON) or live with
`--live`: certificate expiry and self-signed status, weak protocols
(SSLv3, TLS 1.0/1.1), weak ciphers (RC4, DES, 3DES, NULL, EXPORT),
and missing modern TLS.

This is a **personal portfolio project** exploring TLS configuration
auditing and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/hosts.json
python3 run.py --live example.com
```

Exit codes: `2` = usage error or unreadable inventory, `1` = at
least one high or critical finding, `0` = no high or critical
findings. Live checks need network access and fail closed with a
clear error when the host is unreachable.

## Day-1 scope

- Offline inventory analysis: JSON host list with certificate,
  protocol, and cipher details.
- Live mode (`--live host[:port]`): real TLS handshake via the
  standard library, reporting the negotiated protocol and cipher
  plus the presented certificate.
- Checks: expired/expiring certificates, self-signed certificates,
  weak protocols, weak ciphers, no modern TLS.
- Text and JSON (`--json`) findings reports with severity counts.
