from __future__ import annotations

import base64
import unittest
from types import SimpleNamespace

import ipp_pool


def _handler(proxy_authorization: str | None = None) -> SimpleNamespace:
    headers: dict[str, str] = {}
    if proxy_authorization is not None:
        headers["Proxy-Authorization"] = proxy_authorization
    return SimpleNamespace(headers=headers)


def _basic(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


class HttpProxyAuthorizationTests(unittest.TestCase):
    def test_valid_basic_credentials(self) -> None:
        handler = _handler(_basic("synthetic-user", "p:a:ss"))
        self.assertTrue(
            ipp_pool.http_proxy_authorized(handler, "synthetic-user", "p:a:ss")
        )

    def test_wrong_or_missing_credentials(self) -> None:
        self.assertFalse(
            ipp_pool.http_proxy_authorized(
                _handler(_basic("synthetic-user", "wrong")),
                "synthetic-user",
                "expected",
            )
        )
        self.assertFalse(
            ipp_pool.http_proxy_authorized(
                _handler(), "synthetic-user", "expected"
            )
        )

    def test_malformed_basic_header_is_rejected(self) -> None:
        for value in ("Bearer value", "Basic !!!", "Basic", "Basic Zm9v"):
            with self.subTest(value=value):
                self.assertFalse(
                    ipp_pool.http_proxy_authorized(
                        _handler(value), "synthetic-user", "expected"
                    )
                )

    def test_partially_configured_server_auth_fails_closed(self) -> None:
        credential = _handler(_basic("synthetic-user", "expected"))
        self.assertFalse(
            ipp_pool.http_proxy_authorized(credential, "synthetic-user", None)
        )
        self.assertFalse(ipp_pool.http_proxy_authorized(credential, None, "expected"))

    def test_no_configured_auth_allows_request(self) -> None:
        self.assertTrue(ipp_pool.http_proxy_authorized(_handler(), None, None))


if __name__ == "__main__":
    unittest.main()
