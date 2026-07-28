from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import ipp_pool


def _b64url(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_jwt(claims: dict[str, object]) -> str:
    signature = _b64url({"synthetic": "signature"})
    return f"{_b64url({'alg': 'RS256', 'typ': 'JWT'})}.{_b64url(claims)}.{signature}"


class ProxyPassJwtTests(unittest.TestCase):
    guardian = "https://vpn.mozilla.org"
    now = 2_000_000_000

    def claims(self, **updates: object) -> dict[str, object]:
        claims: dict[str, object] = {
            "sub": "synthetic-test-subject",
            "iss": "vpn.mozilla.org",
            "aud": self.guardian,
            "nbf": self.now - 10,
            "iat": self.now - 10,
            "exp": self.now + 600,
        }
        claims.update(updates)
        return claims

    def validate(self, token: str, **kwargs: object) -> object:
        func = getattr(ipp_pool, "validate_proxy_pass_jwt", None)
        self.assertTrue(callable(func), "validate_proxy_pass_jwt() is required")
        return func(token, self.guardian, now=self.now, **kwargs)

    def assert_invalid(self, token: str, **kwargs: object) -> None:
        try:
            result = self.validate(token, **kwargs)
        except (TypeError, ValueError):
            return
        self.assertFalse(result, "an invalid ProxyPass JWT must be rejected")

    def test_valid_claims_are_accepted(self) -> None:
        self.assertTrue(self.validate(make_jwt(self.claims()), min_ttl=120))

    def test_audience_list_is_supported(self) -> None:
        token = make_jwt(self.claims(aud=["unrelated", self.guardian]))
        self.assertTrue(self.validate(token))

    def test_guardian_trailing_slash_is_normalized(self) -> None:
        func = getattr(ipp_pool, "validate_proxy_pass_jwt", None)
        self.assertTrue(callable(func), "validate_proxy_pass_jwt() is required")
        result = func(
            make_jwt(self.claims()),
            self.guardian + "/",
            now=self.now,
        )
        self.assertTrue(result)

    def test_expired_token_is_rejected(self) -> None:
        self.assert_invalid(make_jwt(self.claims(exp=self.now)))
        self.assert_invalid(make_jwt(self.claims(exp=self.now - 1)))

    def test_future_nbf_is_rejected(self) -> None:
        self.assert_invalid(make_jwt(self.claims(nbf=self.now + 1)))

    def test_minimum_ttl_is_enforced(self) -> None:
        token = make_jwt(self.claims(exp=self.now + 120))
        self.assertTrue(self.validate(token, min_ttl=119))
        self.assert_invalid(token, min_ttl=120)

    def test_wrong_audience_is_rejected(self) -> None:
        self.assert_invalid(make_jwt(self.claims(aud="https://example.invalid")))
        self.assert_invalid(make_jwt(self.claims(aud=["https://example.invalid"])))

    def test_required_time_and_audience_claims_are_enforced(self) -> None:
        for claim in ("exp", "nbf", "aud"):
            with self.subTest(claim=claim):
                claims = self.claims()
                del claims[claim]
                self.assert_invalid(make_jwt(claims))

    def test_malformed_tokens_are_rejected(self) -> None:
        for token in (
            "",
            "not-a-jwt",
            "one.two",
            "one.two.three.four",
            "@@@.@@@.signature",
            f"{_b64url({'alg': 'RS256'})}.{_b64url(['not', 'claims'])}.signature",
        ):
            with self.subTest(token=token):
                self.assert_invalid(token)


class ProxyUsageTests(unittest.TestCase):
    def test_unlimited_quota_requires_no_finite_headers(self) -> None:
        usage = ipp_pool.ProxyUsage.from_headers(
            {"X-Quota-Unlimited": "true", "Retry-After": "30"}
        )
        self.assertTrue(usage.unlimited)
        self.assertIsNone(usage.limit)
        self.assertIsNone(usage.remaining)
        self.assertIsNone(usage.reset)
        self.assertEqual(usage.retry_after, 30)

    def test_finite_quota_is_strictly_parsed(self) -> None:
        usage = ipp_pool.ProxyUsage.from_headers(
            {
                "X-Quota-Limit": "1000",
                "X-Quota-Remaining": "250",
                "X-Quota-Reset": "2026-07-29T00:00:00Z",
            }
        )
        self.assertFalse(usage.unlimited)
        self.assertEqual(usage.limit, 1000)
        self.assertEqual(usage.remaining, 250)
        self.assertEqual(usage.reset, "2026-07-29T00:00:00Z")

    def test_invalid_or_incomplete_quota_is_rejected(self) -> None:
        invalid_headers = (
            {},
            {"X-Quota-Unlimited": "yes"},
            {"X-Quota-Limit": "100", "X-Quota-Remaining": "10"},
            {
                "X-Quota-Limit": "not-an-integer",
                "X-Quota-Remaining": "10",
                "X-Quota-Reset": "2026-07-29T00:00:00Z",
            },
            {
                "X-Quota-Limit": "100",
                "X-Quota-Remaining": "-1",
                "X-Quota-Reset": "2026-07-29T00:00:00Z",
            },
            {
                "X-Quota-Limit": "100",
                "X-Quota-Remaining": "101",
                "X-Quota-Reset": "2026-07-29T00:00:00Z",
            },
            {
                "X-Quota-Limit": "100",
                "X-Quota-Remaining": "10",
                "X-Quota-Reset": "2026-07-29T00:00:00",
            },
        )
        for headers in invalid_headers:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                ipp_pool.ProxyUsage.from_headers(headers)

    def test_error_response_can_omit_quota_headers(self) -> None:
        usage = ipp_pool.ProxyUsage.from_headers(
            {"Retry-After": "15"},
            require_quota=False,
        )
        self.assertIsNone(usage.unlimited)
        self.assertEqual(usage.retry_after, 15)

    def test_guardian_headers_match_current_desktop_shape(self) -> None:
        headers = ipp_pool.guardian_headers("synthetic-access-token")
        self.assertEqual(headers["Authorization"], "Bearer synthetic-access-token")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Cache-Control"], "no-cache")


class AuthorityParserTests(unittest.TestCase):
    def parse(self, value: str, default_port: int | None = None) -> tuple[str, int]:
        func = getattr(ipp_pool, "parse_authority", None)
        self.assertTrue(callable(func), "parse_authority() is required")
        return func(value, default_port=default_port)

    def test_dns_and_ipv4_authorities(self) -> None:
        self.assertEqual(self.parse("example.invalid:8443"), ("example.invalid", 8443))
        self.assertEqual(self.parse("192.0.2.10:443"), ("192.0.2.10", 443))
        self.assertEqual(self.parse("example.invalid", 443), ("example.invalid", 443))

    def test_bracketed_ipv6_authorities(self) -> None:
        self.assertEqual(self.parse("[2001:db8::1]:8443"), ("2001:db8::1", 8443))
        self.assertEqual(self.parse("[::1]", 443), ("::1", 443))

    def test_missing_port_without_default_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.parse("example.invalid")

    def test_ambiguous_unbracketed_ipv6_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.parse("2001:db8::1", 443)

    def test_invalid_authorities_are_rejected(self) -> None:
        values = (
            "",
            ":443",
            "example.invalid:",
            "example.invalid:0",
            "example.invalid:65536",
            "example.invalid:not-a-port",
            "user@example.invalid:443",
            "example.invalid:443\r\nInjected: yes",
            "[::1",
            "::1]:443",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(value, 443)


class AtomicSensitiveWriteTests(unittest.TestCase):
    @staticmethod
    def write_sensitive(path: Path, content: str) -> None:
        ipp_pool.atomic_write_text(path, content, mode=0o600)

    def test_sensitive_write_creates_mode_0600_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "nested" / "secret.txt"
            old_umask = os.umask(0)
            try:
                self.write_sensitive(path, "synthetic secret\n")
            finally:
                os.umask(old_umask)
            self.assertEqual(path.read_text(encoding="utf-8"), "synthetic secret\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_sensitive_overwrite_tightens_existing_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "secret.txt"
            path.write_text("old", encoding="utf-8")
            path.chmod(0o644)
            self.write_sensitive(path, "new")
            self.assertEqual(path.read_text(encoding="utf-8"), "new")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
