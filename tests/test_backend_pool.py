from __future__ import annotations

import unittest
from collections import Counter
from unittest.mock import Mock, patch

import ipp_pool


def make_node(country: str, index: int = 0) -> ipp_pool.ExitNode:
    country_key = country.lower()
    return ipp_pool.ExitNode(
        country=country,
        country_name=f"Country {country}",
        city=f"C{index:02d}",
        city_name=f"City {index}",
        hostname=f"{country_key}-{index}.example.test",
        port=443 + index,
        record_id=f"{country_key}-{index}",
    )


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


class BackendPoolTests(unittest.TestCase):
    def test_rr_primary_covers_all_fifteen_countries_in_fifteen_requests(self) -> None:
        countries = [f"C{index:02d}" for index in range(15)]
        pool = ipp_pool.BackendPool([make_node(country) for country in countries])

        primaries = [pool.candidates(3)[0].country for _ in range(15)]

        self.assertEqual(primaries, countries)
        self.assertEqual(set(primaries), set(countries))

    def test_rr_primary_covers_three_countries_in_three_requests(self) -> None:
        countries = ["AA", "BB", "CC"]
        pool = ipp_pool.BackendPool([make_node(country) for country in countries])

        primaries = [pool.candidates(3)[0].country for _ in range(3)]

        self.assertEqual(primaries, countries)

    def test_random_candidates_do_not_repeat_a_node(self) -> None:
        nodes = [
            make_node(country, index)
            for country in ("AA", "BB", "CC")
            for index in range(3)
        ]
        pool = ipp_pool.BackendPool(nodes, mode="random")

        candidates = pool.candidates(len(nodes))

        self.assertEqual(len(candidates), len(nodes))
        self.assertEqual(
            len({candidate.stable_id for candidate in candidates}), len(nodes)
        )

    def test_rr_primary_weight_is_per_country_not_per_node(self) -> None:
        nodes = [make_node("AA", index) for index in range(7)]
        nodes.extend([make_node("BB"), make_node("CC")])
        pool = ipp_pool.BackendPool(nodes)

        counts = Counter(pool.candidates(1)[0].country for _ in range(30))

        self.assertEqual(counts, {"AA": 10, "BB": 10, "CC": 10})

    def test_random_primary_samples_countries_not_flat_nodes(self) -> None:
        nodes = [make_node("AA", index) for index in range(7)]
        nodes.extend([make_node("BB"), make_node("CC")])
        pool = ipp_pool.BackendPool(nodes, mode="random")

        with (
            patch.object(
                ipp_pool.random, "sample", return_value=["BB", "CC", "AA"]
            ) as sample,
            patch.object(
                ipp_pool.random, "choice", side_effect=lambda group: group[0]
            ),
        ):
            primary = pool.candidates(1)[0]

        self.assertEqual(primary.country, "BB")
        sample.assert_called_once_with(["AA", "BB", "CC"], 3)

    def test_rr_rotates_nodes_within_the_selected_country(self) -> None:
        nodes = [make_node("AA", index) for index in range(3)]
        pool = ipp_pool.BackendPool(nodes)

        record_ids = [pool.candidates(1)[0].record_id for _ in range(4)]

        self.assertEqual(record_ids, ["aa-0", "aa-1", "aa-2", "aa-0"])

    def test_zero_attempts_returns_no_candidates(self) -> None:
        pool = ipp_pool.BackendPool([make_node("AA")])

        self.assertEqual(pool.candidates(0), [])

    def test_attempts_above_node_count_returns_every_node_once(self) -> None:
        nodes = [make_node("AA", 0), make_node("AA", 1), make_node("BB", 0)]
        pool = ipp_pool.BackendPool(nodes)

        candidates = pool.candidates(100)

        self.assertEqual(len(candidates), len(nodes))
        self.assertEqual(
            {candidate.stable_id for candidate in candidates},
            {node.stable_id for node in nodes},
        )

    def test_empty_pool_raises_for_candidates_and_next(self) -> None:
        pool = ipp_pool.BackendPool([])

        with self.assertRaisesRegex(RuntimeError, "no backends"):
            pool.candidates()
        with self.assertRaisesRegex(RuntimeError, "no backends"):
            pool.next()

    def test_invalid_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported rotation mode"):
            ipp_pool.BackendPool([make_node("AA")], mode="weighted")

    def test_next_delegates_to_one_candidate_request(self) -> None:
        node = make_node("AA")
        pool = ipp_pool.BackendPool([node])

        with patch.object(pool, "candidates", return_value=[node]) as candidates:
            selected = pool.next()

        self.assertIs(selected, node)
        candidates.assert_called_once_with(attempts=1)

    def test_rotators_exclude_recommended_anycast_nodes(self) -> None:
        nodes = [make_node("REC"), make_node("AA"), make_node("BB")]
        pool = ipp_pool.Pool(tokens=Mock(), nodes=nodes)
        pool.running = [
            ipp_pool.RunningNode(node=node, socks="127.0.0.1:1", http=None)
            for node in nodes
        ]

        with (
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool, "ThreadedHTTPProxy", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export"),
        ):
            socks_server = pool.start_rotator("127.0.0.1:1090")
            http_server = pool.start_http_rotator("127.0.0.1:8080")

        for server in (socks_server, http_server):
            backend_countries = [
                node.country for node in server.handler.pool.nodes
            ]
            self.assertEqual(backend_countries, ["AA", "BB"])
            self.assertNotIn("REC", backend_countries)


if __name__ == "__main__":
    unittest.main()
