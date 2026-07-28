from __future__ import annotations

import unittest

import ipp_pool


def _server(
    hostname: str,
    *,
    port: int = 2499,
    protocols: list[dict[str, object]] | None = None,
    quarantined: bool = False,
) -> dict[str, object]:
    value: dict[str, object] = {
        "hostname": hostname,
        "port": port,
        "quarantined": quarantined,
    }
    if protocols is not None:
        value["protocols"] = protocols
    return value


def _record(
    record_id: str,
    country: str,
    hostname: str,
    *,
    filter_expression: str = 'env.country != "CN"',
    port: int = 2499,
    protocols: list[dict[str, object]] | None = None,
    quarantined: bool = False,
) -> dict[str, object]:
    return {
        "id": record_id,
        "code": country,
        "name": {
            "US": "United States",
            "REC": "Recommended Location",
            "DE": "Germany",
            "MX": "Mexico",
            "FR": "France",
        }.get(country, country),
        "filter_expression": filter_expression,
        "schema": 1,
        "cities": [
            {
                "code": f"{country}-CITY",
                "name": f"{country} Test City",
                "servers": [
                    _server(
                        hostname,
                        port=port,
                        protocols=protocols,
                        quarantined=quarantined,
                    )
                ],
            }
        ],
    }


CONNECT = {"protocol": "connect", "scheme": "https"}
MASQUE = {"protocol": "masque", "scheme": "https"}


def synthetic_serverlist() -> dict[str, list[dict[str, object]]]:
    """Return records that exercise current and version-gated Firefox formats."""
    return {
        "data": [
            _record(
                "us-modern",
                "US",
                "us-modern.example.invalid",
                filter_expression=(
                    'env.version|versionCompare("151.0a1") >= 0 '
                    '&& env.country != "CN"'
                ),
                port=443,
                protocols=[MASQUE, CONNECT],
            ),
            _record(
                "rec-anycast",
                "REC",
                "shared-anycast.example.invalid",
            ),
            _record(
                "us-legacy",
                "US",
                "shared-anycast.example.invalid",
                filter_expression=(
                    'env.version|versionCompare("151.0a1") < 0 '
                    '&& env.country != "CN"'
                ),
            ),
            _record(
                "de-connect",
                "DE",
                "de-connect.example.invalid",
                port=443,
                protocols=[MASQUE, CONNECT],
            ),
            _record(
                "mx-masque-only",
                "MX",
                "mx-masque.example.invalid",
                port=443,
                protocols=[MASQUE],
            ),
            _record(
                "fr-quarantined",
                "FR",
                "fr-quarantined.example.invalid",
                port=443,
                protocols=[CONNECT],
                quarantined=True,
            ),
        ]
    }


class FilterExpressionTests(unittest.TestCase):
    def evaluate(self, expression: str | None, version: str, country: str) -> bool:
        func = getattr(ipp_pool, "evaluate_filter_expression", None)
        self.assertTrue(callable(func), "evaluate_filter_expression() is required")
        return func(expression, version, country)

    def test_empty_expression_is_eligible(self) -> None:
        self.assertTrue(self.evaluate("", "153.0", "DE"))
        self.assertTrue(self.evaluate(None, "153.0", "DE"))

    def test_modern_version_gate(self) -> None:
        expression = (
            'env.version|versionCompare("151.0a1") >= 0 '
            '&& env.country != "CN"'
        )
        self.assertTrue(self.evaluate(expression, "153.0", "DE"))
        self.assertTrue(self.evaluate(expression, "151.0a1", "DE"))
        self.assertFalse(self.evaluate(expression, "150.0", "DE"))
        self.assertFalse(self.evaluate(expression, "153.0", "CN"))

    def test_legacy_version_gate(self) -> None:
        expression = (
            'env.version|versionCompare("151.0a1") < 0 '
            '&& env.country != "CN"'
        )
        self.assertTrue(self.evaluate(expression, "150.0.1", "US"))
        self.assertFalse(self.evaluate(expression, "151.0a1", "US"))
        self.assertFalse(self.evaluate(expression, "153.0", "US"))

    def test_country_equality_and_inequality(self) -> None:
        self.assertTrue(self.evaluate('env.country == "US"', "153.0", "US"))
        self.assertFalse(self.evaluate('env.country == "US"', "153.0", "DE"))
        self.assertTrue(self.evaluate('env.country != "CN"', "153.0", "DE"))

    def test_unknown_or_executable_syntax_fails_closed(self) -> None:
        self.assertFalse(self.evaluate("env.unsupported == true", "153.0", "DE"))
        self.assertFalse(
            self.evaluate('__import__("os").system("false")', "153.0", "DE")
        )


class ServerListTests(unittest.TestCase):
    def parse(
        self,
        *,
        version: str,
        country: str = "DE",
        include_locked: bool = False,
    ) -> list[ipp_pool.ExitNode]:
        return ipp_pool.parse_serverlist(
            synthetic_serverlist(),
            firefox_version=version,
            client_country=country,
            include_locked=include_locked,
        )

    @staticmethod
    def by_id(nodes: list[ipp_pool.ExitNode]) -> dict[str, ipp_pool.ExitNode]:
        return {node.record_id: node for node in nodes}

    def test_firefox_153_selects_modern_us_record(self) -> None:
        nodes = self.by_id(self.parse(version="153.0"))
        self.assertIn("us-modern", nodes)
        self.assertNotIn("us-legacy", nodes)
        self.assertFalse(nodes["us-modern"].locked)
        self.assertTrue(nodes["us-modern"].supported)
        self.assertIsNone(nodes["us-modern"].unsupported_reason)
        self.assertEqual(nodes["us-modern"].port, 443)
        self.assertEqual(nodes["us-modern"].protocol, "connect")
        self.assertEqual(nodes["us-modern"].scheme, "https")

    def test_firefox_150_selects_legacy_us_record(self) -> None:
        nodes = self.by_id(self.parse(version="150.0"))
        self.assertIn("us-legacy", nodes)
        self.assertNotIn("us-modern", nodes)
        self.assertEqual(nodes["us-legacy"].protocol, "connect")
        self.assertEqual(nodes["us-legacy"].scheme, "https")
        self.assertEqual(nodes["us-legacy"].port, 2499)

    def test_rec_is_preserved_as_an_independent_record(self) -> None:
        nodes = self.by_id(self.parse(version="150.0"))
        self.assertIn("rec-anycast", nodes)
        self.assertIn("us-legacy", nodes)
        self.assertEqual(nodes["rec-anycast"].country, "REC")
        self.assertEqual(nodes["us-legacy"].country, "US")
        self.assertEqual(nodes["rec-anycast"].hostname, nodes["us-legacy"].hostname)

    def test_connect_is_preferred_when_masque_is_listed_first(self) -> None:
        nodes = self.by_id(self.parse(version="153.0"))
        node = nodes["de-connect"]
        self.assertEqual(node.port, 443)
        self.assertEqual(node.protocol, "connect")
        self.assertEqual(node.scheme, "https")
        self.assertFalse(node.locked)
        self.assertTrue(node.supported)
        self.assertIsNone(node.unsupported_reason)

    def test_masque_only_node_is_retained_but_marked_unsupported(self) -> None:
        nodes = self.by_id(self.parse(version="153.0"))
        self.assertIn("mx-masque-only", nodes)
        node = nodes["mx-masque-only"]
        self.assertFalse(node.locked)
        self.assertFalse(node.supported)
        self.assertTrue(node.unsupported_reason)
        self.assertIn("masque", node.unsupported_reason.lower())
        self.assertEqual(node.protocol, "masque")
        self.assertEqual(node.scheme, "https")

    def test_include_locked_exposes_filter_incompatible_records(self) -> None:
        nodes = self.by_id(self.parse(version="153.0", include_locked=True))
        self.assertIn("us-legacy", nodes)
        self.assertTrue(nodes["us-legacy"].locked)
        self.assertIn("mx-masque-only", nodes)
        self.assertFalse(nodes["mx-masque-only"].locked)
        self.assertFalse(nodes["mx-masque-only"].supported)
        self.assertEqual(nodes["mx-masque-only"].protocol, "masque")
        self.assertEqual(nodes["mx-masque-only"].scheme, "https")

    def test_quarantined_node_is_never_eligible(self) -> None:
        normal = self.by_id(self.parse(version="153.0"))
        diagnostic = self.by_id(self.parse(version="153.0", include_locked=True))
        self.assertNotIn("fr-quarantined", normal)
        self.assertNotIn("fr-quarantined", diagnostic)

    def test_country_filter_can_lock_every_record(self) -> None:
        self.assertEqual(self.parse(version="153.0", country="CN"), [])
        diagnostic = self.by_id(
            self.parse(version="153.0", country="CN", include_locked=True)
        )
        self.assertTrue(diagnostic)
        self.assertTrue(all(node.locked for node in diagnostic.values()))
        self.assertNotIn("fr-quarantined", diagnostic)


if __name__ == "__main__":
    unittest.main()
