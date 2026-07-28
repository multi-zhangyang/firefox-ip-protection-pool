from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import ipp_pool

from tests.test_serverlist import synthetic_serverlist


class _FakeServer:
    def __init__(self, address: tuple[str, int], handler: object) -> None:
        self.address = address
        self.handler = handler

    def serve_forever(self) -> None:
        return

    def shutdown(self) -> None:
        return

    def server_close(self) -> None:
        return


class _FakeThread:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs

    def start(self) -> None:
        return


class _FakePortMap:
    def __init__(self, path: object, socks_base: int, http_base: int) -> None:
        self.socks_base = socks_base
        self.http_base = http_base

    def assign(
        self, nodes: list[ipp_pool.ExitNode]
    ) -> dict[str, tuple[int, int]]:
        return {
            node.stable_id: (self.socks_base + index, self.http_base + index)
            for index, node in enumerate(nodes)
        }


class PoolSelectionTests(unittest.TestCase):
    @staticmethod
    def parsed_nodes(
        *, version: str = "153.0", include_locked: bool = False
    ) -> list[ipp_pool.ExitNode]:
        return ipp_pool.parse_serverlist(
            synthetic_serverlist(),
            firefox_version=version,
            client_country="DE",
            include_locked=include_locked,
        )

    def start(
        self,
        nodes: list[ipp_pool.ExitNode],
        *,
        countries: set[str] | None = None,
        recommended: bool = False,
    ) -> list[ipp_pool.RunningNode]:
        with (
            patch.object(ipp_pool, "PortMap", _FakePortMap, create=True),
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
        ):
            pool = ipp_pool.Pool(
                tokens=Mock(),
                nodes=nodes,
                bind="127.0.0.1",
                enable_socks=True,
                enable_http=False,
                advertise_host="127.0.0.1",
            )
            with patch.object(pool, "export"):
                return pool.start(countries=countries, recommended=recommended)

    @staticmethod
    def ids(running: list[ipp_pool.RunningNode]) -> list[str]:
        return [item.node.record_id for item in running]

    def test_explicit_country_filter_is_strict_and_excludes_rec(self) -> None:
        running = self.start(self.parsed_nodes(), countries={"DE"})
        self.assertEqual(self.ids(running), ["de-connect"])

    def test_normal_all_mode_excludes_rec_and_unsupported_nodes(self) -> None:
        running = self.start(self.parsed_nodes())
        ids = self.ids(running)
        self.assertNotIn("rec-anycast", ids)
        self.assertNotIn("mx-masque-only", ids)
        self.assertIn("us-modern", ids)
        self.assertIn("de-connect", ids)

    def test_recommended_mode_uses_only_rec(self) -> None:
        running = self.start(self.parsed_nodes(), recommended=True)
        self.assertEqual(self.ids(running), ["rec-anycast"])

    def test_recommended_mode_does_not_fall_back_to_country_nodes(self) -> None:
        nodes = [node for node in self.parsed_nodes() if node.country != "REC"]
        running = self.start(nodes, recommended=True)
        self.assertEqual(running, [])

    def test_locked_and_quarantined_nodes_are_not_started(self) -> None:
        nodes = self.parsed_nodes(include_locked=True)
        running = self.start(nodes)
        ids = self.ids(running)
        self.assertNotIn("us-legacy", ids)
        self.assertNotIn("fr-quarantined", ids)


if __name__ == "__main__":
    unittest.main()
