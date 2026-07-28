from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import ipp_pool


class _FakeServer:
    instances: list["_FakeServer"] = []

    def __init__(self, address: tuple[str, int], handler: object) -> None:
        self.address = address
        self.handler = handler
        self.shutdown_calls = 0
        self.close_calls = 0
        _FakeServer.instances.append(self)

    def serve_forever(self) -> None:
        return

    def shutdown(self) -> None:
        self.shutdown_calls += 1

    def server_close(self) -> None:
        self.close_calls += 1


class _FakeThread:
    instances: list["_FakeThread"] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.join_calls = 0
        _FakeThread.instances.append(self)

    def start(self) -> None:
        return

    def join(self, timeout: float | None = None) -> None:
        self.join_calls += 1

    def is_alive(self) -> bool:
        return True


class _FakePortMap:
    def __init__(self, path: Path, socks_base: int, http_base: int) -> None:
        self.socks_base = socks_base
        self.http_base = http_base

    def assign(self, nodes: list[ipp_pool.ExitNode]) -> dict[str, tuple[int, int]]:
        return {
            node.stable_id: (self.socks_base + index, self.http_base + index)
            for index, node in enumerate(nodes)
        }


class PoolLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeServer.instances.clear()
        _FakeThread.instances.clear()
        self.node = ipp_pool.ExitNode(
            country="DE",
            country_name="Germany",
            city="MUC",
            city_name="Munich",
            hostname="de.example.test",
            port=443,
            record_id="de-test",
        )

    def make_pool(self) -> ipp_pool.Pool:
        return ipp_pool.Pool(
            tokens=Mock(),
            nodes=[self.node],
            bind="127.0.0.1",
            socks_base=42000,
            http_base=43000,
            advertise_host="proxy.example.test",
            enable_socks=True,
            enable_http=True,
        )

    def test_rotator_start_refreshes_export_after_start_export(self) -> None:
        pool = self.make_pool()
        observed: list[str | None] = []

        def capture_export() -> None:
            observed.append(pool.rotator_socks)

        with (
            patch.object(ipp_pool, "PortMap", _FakePortMap),
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool, "ThreadedHTTPProxy", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export", side_effect=capture_export),
        ):
            pool.start()
            socks = pool.start_rotator("127.0.0.1:44090")

        self.assertIs(pool.rotator_socks_server, socks)
        self.assertEqual(observed, [None, "127.0.0.1:44090"])
        self.assertEqual(pool.rotator_socks, "127.0.0.1:44090")

    def test_http_rotator_is_exported_after_it_binds(self) -> None:
        pool = self.make_pool()
        observed: list[str | None] = []

        def capture_export() -> None:
            observed.append(pool.rotator_http)

        with (
            patch.object(ipp_pool, "PortMap", _FakePortMap),
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool, "ThreadedHTTPProxy", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export", side_effect=capture_export),
        ):
            pool.start()
            http = pool.start_http_rotator("127.0.0.1:44080")

        self.assertIs(pool.rotator_http_server, http)
        self.assertEqual(observed, [None, "127.0.0.1:44080"])
        self.assertEqual(pool.rotator_http, "127.0.0.1:44080")

    def test_stop_closes_rotators_and_backend_servers_idempotently(self) -> None:
        pool = self.make_pool()
        with (
            patch.object(ipp_pool, "PortMap", _FakePortMap),
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool, "ThreadedHTTPProxy", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export"),
        ):
            pool.start()
            pool.start_rotator("127.0.0.1:44090")
            pool.start_http_rotator("127.0.0.1:44080")

        servers = list(_FakeServer.instances)
        threads = list(_FakeThread.instances)
        self.assertEqual(len(servers), 4)  # two backends plus two rotators
        pool.stop()

        self.assertTrue(pool._stop.is_set())
        self.assertEqual(pool.running, [])
        self.assertIsNone(pool.rotator_socks_server)
        self.assertIsNone(pool.rotator_http_server)
        self.assertIsNone(pool.rotator_socks)
        self.assertIsNone(pool.rotator_http)
        self.assertTrue(all(server.shutdown_calls == 1 for server in servers))
        self.assertTrue(all(server.close_calls == 1 for server in servers))
        self.assertTrue(all(thread.join_calls == 1 for thread in threads))

        # A signal can arrive twice; the second stop must not call methods on
        # already-closed sockets.
        pool.stop()
        self.assertTrue(all(server.shutdown_calls == 1 for server in servers))
        self.assertTrue(all(server.close_calls == 1 for server in servers))
        self.assertTrue(all(thread.join_calls == 1 for thread in threads))

    def test_failed_export_does_not_leave_rotator_bound(self) -> None:
        pool = self.make_pool()
        with (
            patch.object(ipp_pool, "PortMap", _FakePortMap),
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool, "ThreadedHTTPProxy", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export", side_effect=OSError("disk full")),
        ):
            # Pool.start() export is intentionally allowed to fail here; the
            # rotator path must still clean up if its own export fails.
            with self.assertRaises(OSError):
                pool.start()
        # A failed export happens after the backend sockets are bound. Keep
        # the unit test from leaving real sockets behind.
        pool.stop()

        # start() itself did not bind a rotator. Verify the cleanup path by
        # installing a running backend and invoking start_rotator directly.
        pool = self.make_pool()
        pool.running = [
            ipp_pool.RunningNode(self.node, "proxy.example.test:42000", None)
        ]
        with (
            patch.object(ipp_pool, "ThreadedSocksServer", _FakeServer),
            patch.object(ipp_pool.threading, "Thread", _FakeThread),
            patch.object(pool, "export", side_effect=OSError("disk full")),
        ):
            with self.assertRaises(OSError):
                pool.start_rotator("127.0.0.1:44090")
        self.assertIsNone(pool.rotator_socks_server)
        self.assertIsNone(pool.rotator_socks)
        bound = _FakeServer.instances[-1]
        self.assertEqual(bound.shutdown_calls, 1)
        self.assertEqual(bound.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
