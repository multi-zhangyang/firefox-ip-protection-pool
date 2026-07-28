from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

import ipp_pool


class _ListenersStarted(Exception):
    """Stop cmd_run after both aggregate listener calls have been observed."""


class RunListenerPreflightTests(unittest.TestCase):
    def invoke_preflight(self, *arguments: str) -> tuple[int, Mock, Mock, Mock]:
        """Run only CLI validation, with every credential/network access mocked."""
        token_store = Mock()
        token_store.ensure.side_effect = AssertionError(
            "listener validation must run before token access"
        )
        token_builder = Mock(return_value=token_store)
        serverlist = Mock(
            side_effect=AssertionError(
                "listener validation must run before Remote Settings access"
            )
        )
        auth_file = Mock(return_value=(None, None))

        with (
            patch.dict(
                os.environ,
                {
                    "IPP_ADVERTISE_HOST": "",
                    "IPP_LISTEN_USER": "",
                    "IPP_LISTEN_PASS": "",
                },
            ),
            patch.object(ipp_pool, "ensure_dirs"),
            patch.object(ipp_pool, "build_tokens", token_builder),
            patch.object(ipp_pool, "fetch_serverlist", serverlist),
            patch.object(ipp_pool, "parse_listen_auth_file", auth_file),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            result = ipp_pool.main(["run", *arguments])

        return result, token_builder, serverlist, auth_file

    def assert_rejected_before_token_or_network(self, *arguments: str) -> None:
        result, token_builder, serverlist, _auth_file = self.invoke_preflight(
            *arguments
        )
        self.assertEqual(result, 2)
        token_builder.assert_not_called()
        serverlist.assert_not_called()

    def test_socks_aggregate_cannot_expose_an_unauthenticated_loopback_pool(self) -> None:
        for authority in ("0.0.0.0:1090", "192.0.2.10:1090", "proxy.example:1090"):
            with self.subTest(authority=authority):
                self.assert_rejected_before_token_or_network(
                    "--bind",
                    "127.0.0.1",
                    "--rotator",
                    authority,
                    "--http-rotator",
                    "off",
                )

    def test_non_loopback_primary_bind_is_rejected_before_token_or_network(self) -> None:
        for host in ("0.0.0.0", "192.0.2.10", "proxy.example"):
            with self.subTest(host=host):
                self.assert_rejected_before_token_or_network(
                    "--bind",
                    host,
                    "--rotator",
                    "off",
                    "--http-rotator",
                    "off",
                )

    def test_http_aggregate_cannot_expose_an_unauthenticated_loopback_pool(self) -> None:
        for authority in ("0.0.0.0:8080", "192.0.2.10:8080", "proxy.example:8080"):
            with self.subTest(authority=authority):
                self.assert_rejected_before_token_or_network(
                    "--bind",
                    "127.0.0.1",
                    "--rotator",
                    "off",
                    "--http-rotator",
                    authority,
                )

    def test_partial_auth_is_rejected_before_token_or_network(self) -> None:
        for arguments in (
            ("--auth-user", "test-user"),
            ("--auth-pass", "test-password"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_rejected_before_token_or_network(
                    "--bind",
                    "127.0.0.1",
                    "--rotator",
                    "0.0.0.0:1090",
                    "--http-rotator",
                    "off",
                    *arguments,
                )

    def test_invalid_socks_listener_authority_returns_two_before_io(self) -> None:
        for authority in (
            "0.0.0.0",
            "::1:1090",
            "[::1",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:not-a-port",
            "http://127.0.0.1:1090",
        ):
            with self.subTest(authority=authority):
                self.assert_rejected_before_token_or_network(
                    "--rotator",
                    authority,
                    "--http-rotator",
                    "off",
                )

    def test_invalid_http_listener_authority_returns_two_before_io(self) -> None:
        for authority in (
            "127.0.0.1",
            "::1:8080",
            "[::1]8080",
            "127.0.0.1:-1",
            "127.0.0.1:65536",
            "127.0.0.1:not-a-port",
            "https://127.0.0.1:8080",
        ):
            with self.subTest(authority=authority):
                self.assert_rejected_before_token_or_network(
                    "--rotator",
                    "off",
                    "--http-rotator",
                    authority,
                )


class RunListenerStartupTests(unittest.TestCase):
    def run_until_listeners(self, *arguments: str) -> tuple[Mock, Mock, Mock]:
        """Reach aggregate startup without reading files or opening sockets."""
        token_store = Mock()
        token_store.ensure.return_value = "synthetic-token"
        pool = Mock()
        pool.running = [object()]
        pool.start_rotator.return_value = Mock()
        pool.start_http_rotator.side_effect = _ListenersStarted
        pool_factory = Mock(return_value=pool)
        auth_file = Mock(return_value=(None, None))

        with (
            patch.dict(
                os.environ,
                {
                    "IPP_ADVERTISE_HOST": "",
                    "IPP_LISTEN_USER": "",
                    "IPP_LISTEN_PASS": "",
                },
            ),
            patch.object(ipp_pool, "ensure_dirs"),
            patch.object(ipp_pool, "build_tokens", return_value=token_store),
            patch.object(ipp_pool, "fetch_serverlist", return_value=[object()]),
            patch.object(ipp_pool, "parse_listen_auth_file", auth_file),
            patch.object(
                ipp_pool,
                "jwt_summary",
                side_effect=AssertionError("raw JWT summary must not be logged"),
            ),
            patch.object(
                ipp_pool,
                "safe_jwt_summary",
                return_value={"valid": True},
            ),
            patch.object(ipp_pool, "Pool", pool_factory),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(_ListenersStarted):
                ipp_pool.main(["run", *arguments])

        return pool, pool_factory, auth_file

    def test_ipv6_loopback_defaults_use_bracketed_authorities(self) -> None:
        pool, _pool_factory, _auth_file = self.run_until_listeners(
            "--bind",
            "::1",
        )

        pool.start_rotator.assert_called_once_with("[::1]:1090", mode="random")
        pool.start_http_rotator.assert_called_once_with("[::1]:8080", mode="random")

    def test_complete_auth_allows_non_loopback_aggregate_listeners(self) -> None:
        pool, pool_factory, auth_file = self.run_until_listeners(
            "--bind",
            "127.0.0.1",
            "--rotator",
            "0.0.0.0:1090",
            "--http-rotator",
            "proxy.example:8080",
            "--auth-user",
            "test-user",
            "--auth-pass",
            "test-password",
        )

        auth_file.assert_not_called()
        pool_factory.assert_called_once()
        pool_kwargs = pool_factory.call_args.kwargs
        self.assertEqual(pool_kwargs["auth_user"], "test-user")
        self.assertEqual(pool_kwargs["auth_pass"], "test-password")
        pool.start_rotator.assert_called_once_with("0.0.0.0:1090", mode="random")
        pool.start_http_rotator.assert_called_once_with(
            "proxy.example:8080", mode="random"
        )

    def test_complete_auth_allows_a_non_loopback_primary_bind(self) -> None:
        pool, pool_factory, auth_file = self.run_until_listeners(
            "--bind",
            "0.0.0.0",
            "--auth-user",
            "test-user",
            "--auth-pass",
            "test-password",
        )

        auth_file.assert_not_called()
        self.assertEqual(pool_factory.call_args.kwargs["bind"], "0.0.0.0")
        pool.start_rotator.assert_called_once_with("0.0.0.0:1090", mode="random")
        pool.start_http_rotator.assert_called_once_with(
            "0.0.0.0:8080", mode="random"
        )


if __name__ == "__main__":
    unittest.main()
