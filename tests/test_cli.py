from __future__ import annotations

import io
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
            patch.object(ipp_pool, "jwt_summary", return_value={"valid": True}),
            patch.object(ipp_pool.shutil, "which", return_value="/usr/bin/curl"),
            patch.object(
                ipp_pool.subprocess,
                "check_output",
                return_value='{"country":"ZZ"}',
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(ipp_pool.cmd_probe(self.args()), 0)
            self.assertEqual(ipp_pool.cmd_probe(self.args()), 0)

        self.assertEqual(country_choices, [["DE", "US"], ["DE", "US"]])


if __name__ == "__main__":
    unittest.main()
