from __future__ import annotations

import json
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from refresh_state import (
    empty_refresh_state,
    load_refresh_state,
    record_refresh_state,
    retry_delay,
)


class RefreshStateTests(unittest.TestCase):
    def test_missing_or_corrupt_state_fails_closed_to_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "refresh-state.json"
            self.assertEqual(load_refresh_state(path), empty_refresh_state())
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(load_refresh_state(path), empty_refresh_state())

    def test_success_and_failure_history_survives_reload_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "refresh-state.json"
            record_refresh_state(
                path,
                "success",
                now=1000,
                http_status=200,
                proxy_pass_expires_at=1600,
            )
            record_refresh_state(
                path,
                "rate_limited",
                now=1100,
                http_status=429,
                next_attempt_at=1400,
            )

            state = load_refresh_state(path)
            self.assertEqual(state["result"], "rate_limited")
            self.assertEqual(state["last_success_at"], 1000)
            self.assertEqual(state["proxy_pass_expires_at"], 1600)
            self.assertEqual(state["next_attempt_at"], 1400)
            self.assertEqual(state["consecutive_failures"], 1)
            self.assertEqual(state["generation"], 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            serialized = path.read_text(encoding="utf-8").lower()
            for forbidden in ("token", "email", "password", "authorization", "cookie"):
                self.assertNotIn(forbidden, serialized)

    def test_invalid_untrusted_fields_are_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "refresh-state.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "result": "made-up",
                        "last_attempt_at": "tomorrow",
                        "consecutive_failures": -10,
                        "http_status": 999,
                        "generation": False,
                        "secret": "must-not-be-copied",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(load_refresh_state(path), empty_refresh_state())

    def test_transient_retry_delay_is_exponential_and_bounded(self) -> None:
        self.assertEqual(retry_delay(0), 5)
        self.assertEqual(retry_delay(1), 10)
        self.assertEqual(retry_delay(4), 80)
        self.assertEqual(retry_delay(99), 300)

    def test_concurrent_read_modify_write_keeps_every_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "refresh-state.json"

            def writer() -> None:
                for _ in range(20):
                    record_refresh_state(path, "success")

            threads = [threading.Thread(target=writer) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(load_refresh_state(path)["generation"], 160)


if __name__ == "__main__":
    unittest.main()
