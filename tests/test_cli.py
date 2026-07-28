from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ipp_pool


def _node(country: str, hostname: str) -> ipp_pool.ExitNode:
    return ipp_pool.ExitNode(
        country=country,
        country_name=country,
        city=f"{country}-CITY",
        city_name=f"{country} Test City",
        hostname=hostname,
        record_id=f"{country.lower()}-test",
    )


class RunCliValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = ipp_pool.build_parser()

    def invoke_run(self, *arguments: str) -> tuple[int, Mock, Mock]:
        token_store = Mock()
        token_store.ensure.side_effect = RuntimeError("synthetic token access")
        token_builder = Mock(return_value=token_store)
        serverlist = Mock()
        with (
            patch.object(ipp_pool, "ensure_dirs"),
            patch.object(ipp_pool, "build_tokens", token_builder),
            patch.object(ipp_pool, "fetch_serverlist", serverlist),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            result = ipp_pool.main(["run", *arguments])
        return result, token_builder, serverlist

    def assert_invalid_before_io(self, *arguments: str) -> None:
        result, token_builder, serverlist = self.invoke_run(*arguments)
        self.assertEqual(
            (result, token_builder.call_count, serverlist.call_count),
            (2, 0, 0),
        )

    def test_run_defaults_to_random_rotation(self) -> None:
        args = self.parser.parse_args(["run"])
        self.assertEqual(args.rotate_mode, "random")

    def test_parser_tracks_current_firefox_version_and_allows_env_override(self) -> None:
        self.assertEqual(
            self.parser.parse_args(["sync"]).firefox_version,
            "155.0a1",
        )
        with patch.dict(os.environ, {"IPP_FIREFOX_VERSION": "156.0b2"}):
            overridden = ipp_pool.build_parser().parse_args(["sync"])
        self.assertEqual(overridden.firefox_version, "156.0b2")

    def test_countries_and_recommended_conflict_before_token_or_network(self) -> None:
        self.assert_invalid_before_io("--countries", "US,DE", "--recommended")

    def test_empty_or_comma_only_countries_fail_before_token_or_network(self) -> None:
        for value in ("", ",", " , , "):
            with self.subTest(value=value):
                self.assert_invalid_before_io("--countries", value)

    def test_rec_country_fails_before_token_or_network(self) -> None:
        for value in ("REC", "US,rec,DE"):
            with self.subTest(value=value):
                self.assert_invalid_before_io("--countries", value)

    def test_non_positive_limit_fails_before_token_or_network(self) -> None:
        for value in ("0", "-1", "-100"):
            with self.subTest(value=value):
                self.assert_invalid_before_io("--limit", value)


class ProbeDefaultSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = [
            _node("REC", "rec.example.invalid"),
            _node("US", "us-a.example.invalid"),
            _node("US", "us-b.example.invalid"),
            _node("DE", "de-a.example.invalid"),
        ]

    def args(self) -> SimpleNamespace:
        return SimpleNamespace(
            country=None,
            serverlist_url="https://settings.example.invalid/records",
            firefox_version="153.0",
            client_country="",
            include_locked=False,
        )

    def test_default_probe_samples_non_rec_countries_fairly(self) -> None:
        token_store = Mock()
        token_store.ensure.return_value = "synthetic-token"
        country_choices: list[list[str]] = []

        def fair_choice(candidates: list[object]) -> object:
            values = list(candidates)
            if values and isinstance(values[0], str):
                country_choices.append(values)
                return "US" if len(country_choices) == 1 else "DE"
            return values[0]

        with (
            patch.object(ipp_pool, "build_tokens", return_value=token_store),
            patch.object(ipp_pool, "fetch_serverlist", return_value=self.nodes),
            patch.object(ipp_pool.random, "choice", side_effect=fair_choice),
            patch.object(
                ipp_pool,
                "jwt_summary",
                side_effect=AssertionError("raw JWT summary must not be logged"),
            ),
            patch.object(
                ipp_pool,
                "safe_jwt_summary",
                return_value={"valid": True},
            ) as safe_summary,
            patch.object(ipp_pool, "probe_node", return_value='{"country":"ZZ"}') as probe,
            patch.object(ipp_pool.subprocess, "check_output") as child_process,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(ipp_pool.cmd_probe(self.args()), 0)
            self.assertEqual(ipp_pool.cmd_probe(self.args()), 0)

        self.assertEqual(country_choices, [["DE", "US"], ["DE", "US"]])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(safe_summary.call_count, 2)
        child_process.assert_not_called()


class ProbeTransportTests(unittest.TestCase):
    def test_probe_uses_bounded_in_process_http_transport(self) -> None:
        node = _node("US", "us-a.example.invalid")
        remote = Mock()
        connector = Mock()
        connector.open_tunnel.return_value = remote
        response = Mock(status=200)
        response.read.return_value = b'{"country":"US"}'

        with patch.object(ipp_pool.http.client, "HTTPResponse", return_value=response):
            payload = ipp_pool.probe_node(node, connector)

        self.assertEqual(payload, '{"country":"US"}')
        connector.open_tunnel.assert_called_once_with(
            node.hostname,
            node.port,
            "ipinfo.io",
            80,
            timeout=25,
        )
        remote.settimeout.assert_called_once_with(25)
        request = remote.sendall.call_args.args[0]
        self.assertIn(b"GET /json HTTP/1.1", request)
        self.assertNotIn(b"Proxy-Authorization", request)
        response.read.assert_called_once_with(ipp_pool.MAX_PROBE_RESPONSE + 1)
        response.close.assert_called_once()
        remote.close.assert_called_once()

    def test_probe_rejects_oversized_response_and_closes_tunnel(self) -> None:
        node = _node("US", "us-a.example.invalid")
        remote = Mock()
        connector = Mock()
        connector.open_tunnel.return_value = remote
        response = Mock(status=200)
        response.read.return_value = b"x" * (ipp_pool.MAX_PROBE_RESPONSE + 1)

        with (
            patch.object(ipp_pool.http.client, "HTTPResponse", return_value=response),
            self.assertRaisesRegex(OSError, "size limit"),
        ):
            ipp_pool.probe_node(node, connector)

        response.close.assert_called_once()
        remote.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
