from __future__ import annotations

import io
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock

import ipp_pool


class _CountingReader(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


def _headers(*pairs: tuple[str, str]) -> Message:
    headers = Message()
    for name, value in pairs:
        headers[name] = value
    return headers


def _request_handler(
    path: str,
    *,
    method: str = "GET",
    headers: Message | None = None,
    body: bytes = b"",
) -> SimpleNamespace:
    return SimpleNamespace(
        path=path,
        command=method,
        headers=headers or Message(),
        rfile=_CountingReader(body),
    )


def _split_request(request: bytes) -> tuple[list[str], bytes]:
    head, body = request.split(b"\r\n\r\n", 1)
    return head.decode("iso-8859-1").split("\r\n"), body


class ForwardRequestFramingTests(unittest.TestCase):
    def test_chunked_transfer_encoding_is_rejected_without_reading_body(self) -> None:
        handler = _request_handler(
            "http://example.test/upload",
            method="POST",
            headers=_headers(("Transfer-Encoding", "chunked")),
            body=b"4\r\ntest\r\n0\r\n\r\n",
        )

        with self.assertRaises(NotImplementedError):
            ipp_pool._prepare_forward_request(handler)

        self.assertEqual(handler.rfile.read_sizes, [])

    def test_identical_duplicate_content_lengths_read_the_body_once(self) -> None:
        handler = _request_handler(
            "http://example.test/upload",
            method="POST",
            headers=_headers(
                ("Content-Length", "4"),
                ("Content-Length", "4"),
            ),
            body=b"data",
        )

        host, port, request = ipp_pool._prepare_forward_request(handler)
        _, forwarded_body = _split_request(request)

        self.assertEqual((host, port), ("example.test", 80))
        self.assertEqual(handler.rfile.read_sizes, [4])
        self.assertEqual(forwarded_body, b"data")

    def test_conflicting_content_lengths_are_rejected_without_reading_body(self) -> None:
        handler = _request_handler(
            "http://example.test/upload",
            method="POST",
            headers=_headers(
                ("Content-Length", "4"),
                ("Content-Length", "5"),
            ),
            body=b"data!",
        )

        with self.assertRaises(ValueError):
            ipp_pool._prepare_forward_request(handler)

        self.assertEqual(handler.rfile.read_sizes, [])

    def test_negative_and_oversized_content_lengths_are_rejected_early(self) -> None:
        lengths = ("-1", str(ipp_pool.MAX_FORWARD_BODY + 1))
        for length in lengths:
            with self.subTest(length=length):
                handler = _request_handler(
                    "http://example.test/upload",
                    method="POST",
                    headers=_headers(("Content-Length", length)),
                    body=b"unused",
                )

                with self.assertRaises(ValueError):
                    ipp_pool._prepare_forward_request(handler)

                self.assertEqual(handler.rfile.read_sizes, [])

    def test_short_body_is_rejected(self) -> None:
        handler = _request_handler(
            "http://example.test/upload",
            method="POST",
            headers=_headers(("Content-Length", "5")),
            body=b"data",
        )

        with self.assertRaises(ValueError):
            ipp_pool._prepare_forward_request(handler)

        self.assertEqual(handler.rfile.read_sizes, [5])

    def test_ipv6_non_default_port_uses_bracketed_host_header(self) -> None:
        handler = _request_handler("http://[2001:db8::1]:8080/path?q=1")

        host, port, request = ipp_pool._prepare_forward_request(handler)
        lines, body = _split_request(request)

        self.assertEqual((host, port), ("2001:db8::1", 8080))
        self.assertEqual(lines[0], "GET /path?q=1 HTTP/1.1")
        self.assertIn("Host: [2001:db8::1]:8080", lines)
        self.assertEqual(body, b"")

    def test_ipv6_default_port_omits_port_but_keeps_brackets(self) -> None:
        handler = _request_handler("http://[2001:db8::2]/")

        host, port, request = ipp_pool._prepare_forward_request(handler)
        lines, _ = _split_request(request)

        self.assertEqual((host, port), ("2001:db8::2", 80))
        self.assertIn("Host: [2001:db8::2]", lines)

    def test_non_default_port_replaces_the_client_host_header(self) -> None:
        handler = _request_handler(
            "http://origin.example.test:8081/resource",
            headers=_headers(("Host", "untrusted.example.test")),
        )

        host, port, request = ipp_pool._prepare_forward_request(handler)
        lines, _ = _split_request(request)

        self.assertEqual((host, port), ("origin.example.test", 8081))
        self.assertEqual(
            [line for line in lines if line.lower().startswith("host:")],
            ["Host: origin.example.test:8081"],
        )

    def test_connection_tokens_and_hop_by_hop_headers_are_removed(self) -> None:
        handler = _request_handler(
            "http://example.test/resource",
            headers=_headers(
                ("Connection", "keep-alive, X-Private-Hop"),
                ("Keep-Alive", "timeout=5"),
                ("X-Private-Hop", "remove-me"),
                ("Proxy-Authorization", "Basic synthetic"),
                ("Proxy-Connection", "keep-alive"),
                ("TE", "trailers"),
                ("Trailer", "X-Checksum"),
                ("Upgrade", "websocket"),
                ("X-End-To-End", "keep-me"),
            ),
        )

        _, _, request = ipp_pool._prepare_forward_request(handler)
        lines, _ = _split_request(request)
        forwarded_headers = [line for line in lines[1:] if line]
        names = [line.split(":", 1)[0].lower() for line in forwarded_headers]

        for removed in (
            "keep-alive",
            "x-private-hop",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "upgrade",
        ):
            with self.subTest(header=removed):
                self.assertNotIn(removed, names)
        self.assertIn("X-End-To-End: keep-me", forwarded_headers)
        self.assertEqual(
            [line for line in forwarded_headers if line.lower().startswith("connection:")],
            ["Connection: close"],
        )


class _RemoteSocket:
    def __init__(self, *, send_error: OSError | None = None) -> None:
        self.send_error = send_error
        self.sent: list[bytes] = []
        self.close_calls = 0

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if self.send_error is not None:
            raise self.send_error

    def recv(self, size: int) -> bytes:
        return b""

    def close(self) -> None:
        self.close_calls += 1


class _Connector:
    def __init__(self, *outcomes: object) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[str, int, str, int]] = []

    def open_tunnel(
        self,
        exit_host: str,
        exit_port: int,
        destination_host: str,
        destination_port: int,
    ) -> _RemoteSocket:
        self.calls.append(
            (exit_host, exit_port, destination_host, destination_port)
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[return-value]


class _ClientConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class RotatingHttpReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = [
            ipp_pool.ExitNode(
                country="DE",
                country_name="Germany",
                city=f"T{i}",
                city_name=f"Test {i}",
                hostname=f"exit-{i}.example.test",
                port=443,
                record_id=f"test-{i}",
            )
            for i in range(1, 4)
        ]

    def _handler(self, connector: _Connector) -> ipp_pool.RotatingHTTPHandler:
        handler = object.__new__(ipp_pool.RotatingHTTPHandler)
        handler.path = "http://destination.example.test/submit"
        handler.command = "POST"
        handler.headers = _headers(("Content-Length", "4"))
        handler.rfile = _CountingReader(b"data")
        handler.connection = _ClientConnection()
        handler.auth_user = None
        handler.auth_pass = None
        handler.connector = connector
        handler.pool = Mock()
        handler.pool.candidates.return_value = self.nodes
        handler.send_error = Mock()
        return handler

    def test_tunnel_failover_sends_the_prepared_request_only_once(self) -> None:
        remote = _RemoteSocket()
        connector = _Connector(OSError("first tunnel unavailable"), remote)
        handler = self._handler(connector)

        handler._proxy_http()

        self.assertEqual(len(connector.calls), 2)
        self.assertEqual(handler.rfile.read_sizes, [4])
        self.assertEqual(len(remote.sent), 1)
        self.assertEqual(_split_request(remote.sent[0])[1], b"data")
        handler.send_error.assert_not_called()

    def test_request_is_not_replayed_after_a_tunnel_may_have_received_bytes(self) -> None:
        first = _RemoteSocket(send_error=OSError("write outcome is unknown"))
        second = _RemoteSocket()
        connector = _Connector(first, second)
        handler = self._handler(connector)

        handler._proxy_http()

        self.assertEqual(handler.rfile.read_sizes, [4])
        self.assertEqual(len(connector.calls), 1)
        self.assertEqual(len(first.sent), 1)
        self.assertEqual(second.sent, [])
        handler.send_error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
