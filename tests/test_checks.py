"""Unit tests for the TLS checks and grading.

Run from the project root:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tls.checks import check_one
from tls.grading import grade


def host(**overrides):
    base = {"host": "h.example", "port": 443,
            "cert": {"not_after": "2027-06-01", "self_signed": False},
            "protocols": ["TLSv1.2", "TLSv1.3"],
            "ciphers": ["TLS_AES_256_GCM_SHA384"]}
    base.update(overrides)
    return base


class TestChecks(unittest.TestCase):
    def test_clean_host(self):
        self.assertEqual(check_one(host()), [])

    def test_expired_is_critical(self):
        cert = {"not_after": "2020-01-01", "self_signed": False}
        findings = check_one(host(cert=cert))
        self.assertTrue(any(f["check"] == "cert-expired"
                            and f["severity"] == "CRITICAL"
                            for f in findings))

    def test_expiring_soon_is_high(self):
        import datetime
        soon = (datetime.date.today()
                + datetime.timedelta(days=10)).isoformat()
        cert = {"not_after": soon, "self_signed": False}
        findings = check_one(host(cert=cert))
        self.assertTrue(any(f["check"] == "cert-expiring"
                            for f in findings))

    def test_self_signed_is_high(self):
        cert = {"not_after": "2027-06-01", "self_signed": True}
        findings = check_one(host(cert=cert))
        self.assertTrue(any(f["check"] == "self-signed-cert"
                            for f in findings))

    def test_weak_protocol(self):
        findings = check_one(host(protocols=["TLSv1.1", "TLSv1.2"]))
        self.assertTrue(any(f["check"] == "weak-protocol"
                            for f in findings))

    def test_weak_cipher(self):
        findings = check_one(host(ciphers=["RC4-SHA"]))
        self.assertTrue(any(f["check"] == "weak-cipher"
                            for f in findings))

    def test_no_modern_tls(self):
        findings = check_one(host(protocols=["TLSv1.1"]))
        self.assertTrue(any(f["check"] == "no-modern-tls"
                            for f in findings))


class TestGrading(unittest.TestCase):
    def test_clean_is_a(self):
        self.assertEqual(grade([]), "A")

    def test_one_high_is_b(self):
        self.assertEqual(grade([{"severity": "HIGH"}]), "B")

    def test_critical_drops_fast(self):
        self.assertEqual(
            grade([{"severity": "CRITICAL"}, {"severity": "HIGH"}]), "F")


if __name__ == "__main__":
    unittest.main()
