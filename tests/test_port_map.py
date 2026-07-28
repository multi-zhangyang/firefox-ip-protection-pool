from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import ipp_pool

from tests.test_serverlist import synthetic_serverlist


class PortMapTests(unittest.TestCase):
    @staticmethod
    def nodes() -> list[ipp_pool.ExitNode]:
        return ipp_pool.parse_serverlist(
            synthetic_serverlist(),
            firefox_version="153.0",
            client_country="DE",
        )

    def test_assignments_are_unique_and_start_at_configured_bases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            assigned = ipp_pool.PortMap(path, 21000, 31000).assign(nodes)

            self.assertEqual(len(assigned), len(nodes))
            self.assertEqual(len({node.stable_id for node in nodes}), len(nodes))
            self.assertEqual(set(assigned), {node.stable_id for node in nodes})
            socks_ports = [ports[0] for ports in assigned.values()]
            http_ports = [ports[1] for ports in assigned.values()]
            self.assertEqual(len(socks_ports), len(set(socks_ports)))
            self.assertEqual(len(http_ports), len(set(http_ports)))
            self.assertGreaterEqual(min(socks_ports), 21000)
            self.assertGreaterEqual(min(http_ports), 31000)

    def test_reordering_nodes_does_not_change_existing_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            first = ipp_pool.PortMap(path, 21000, 31000).assign(nodes)
            second = ipp_pool.PortMap(path, 21000, 31000).assign(reversed(nodes))
            self.assertEqual(second, first)

    def test_inserting_a_node_preserves_existing_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            port_map = ipp_pool.PortMap(path, 21000, 31000)
            original = port_map.assign(nodes[:2])
            expanded = port_map.assign(nodes)

            for stable_id, ports in original.items():
                self.assertEqual(expanded[stable_id], ports)

    def test_removing_a_node_does_not_renumber_survivors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            port_map = ipp_pool.PortMap(path, 21000, 31000)
            original = port_map.assign(nodes)
            survivors = nodes[1:]
            reduced = port_map.assign(survivors)

            self.assertEqual(set(reduced), {node.stable_id for node in survivors})
            for node in survivors:
                self.assertEqual(reduced[node.stable_id], original[node.stable_id])

    def test_persisted_schema_contains_identity_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            ipp_pool.PortMap(path, 21000, 31000).assign(nodes)
            payload = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(payload["version"], 1)
            self.assertEqual(payload["socks_base"], 21000)
            self.assertEqual(payload["http_base"], 31000)
            self.assertEqual(set(payload["assignments"]), {n.stable_id for n in nodes})
            for node in nodes:
                entry = payload["assignments"][node.stable_id]
                self.assertEqual(entry["country"], node.country)
                self.assertEqual(entry["city"], node.city)
                self.assertEqual(entry["hostname"], node.hostname)
                self.assertIsInstance(entry["socks"], int)
                self.assertIsInstance(entry["http"], int)

    def test_base_change_reallocates_within_the_new_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()
            old = ipp_pool.PortMap(path, 21000, 31000).assign(nodes)
            try:
                new = ipp_pool.PortMap(path, 22000, 32000).assign(nodes)
            except ValueError:
                return

            self.assertNotEqual(new, old)
            self.assertTrue(all(socks >= 22000 for socks, _ in new.values()))
            self.assertTrue(all(http >= 32000 for _, http in new.values()))
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["socks_base"], 22000)
            self.assertEqual(payload["http_base"], 32000)

    def test_conflicting_persisted_ports_are_not_returned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            nodes = self.nodes()[:2]
            assignments = {
                node.stable_id: {
                    "socks": 21000,
                    "http": 31000,
                    "country": node.country,
                    "city": node.city,
                    "hostname": node.hostname,
                }
                for node in nodes
            }
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "socks_base": 21000,
                        "http_base": 31000,
                        "assignments": assignments,
                    }
                ),
                encoding="utf-8",
            )

            try:
                repaired = ipp_pool.PortMap(path, 21000, 31000).assign(nodes)
            except ValueError:
                return
            self.assertEqual(len({ports[0] for ports in repaired.values()}), len(nodes))
            self.assertEqual(len({ports[1] for ports in repaired.values()}), len(nodes))


if __name__ == "__main__":
    unittest.main()
