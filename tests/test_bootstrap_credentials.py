from __future__ import annotations

import json
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import login_and_bootstrap
import refresh_tokens
from refresh_state import load_refresh_state


UID = "0123456789abcdef0123456789abcdef"
SESSION_TOKEN = "0123456789abcdef" * 4


class BootstrapCredentialPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tokens = self.root / "tokens"
        self.data = self.root / "data"
        self.logs = self.root / "logs"
        for directory in (self.tokens, self.data, self.logs):
            directory.mkdir()

    def publish(self) -> None:
        login_and_bootstrap.persist_bootstrap_credentials(
            session_token=SESSION_TOKEN,
            email="renewal@example.invalid",
            uid=UID,
            proxy_pass="new-proxy-pass",
            expires_at=time.time() + 600,
            http_status=200,
            token_dir=self.tokens,
        )

    def test_publication_waits_for_an_inflight_refresh_then_wins(self) -> None:
        started = threading.Event()
        errors: list[BaseException] = []
        rejected_marker = self.tokens / "rejected_proxy_pass.sha256"
        rejected_marker.write_text("a" * 64 + "\n", encoding="ascii")

        def publish_in_thread() -> None:
            started.set()
            try:
                self.publish()
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with refresh_tokens.refresh_lock(self.tokens, blocking=True):
            thread = threading.Thread(target=publish_in_thread)
            thread.start()
            self.assertTrue(started.wait(1))
            thread.join(0.1)
            self.assertTrue(thread.is_alive())
            self.assertFalse((self.tokens / "renewal_credentials.json").exists())

        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(
            json.loads(
                (self.tokens / "renewal_credentials.json").read_text(encoding="utf-8")
            ),
            {
                "schema": 1,
                "email": "renewal@example.invalid",
                "uid": UID,
                "session_token": SESSION_TOKEN,
            },
        )
        self.assertFalse((self.tokens / "session_token.txt").exists())
        self.assertFalse((self.tokens / "account_meta.json").exists())
        state = load_refresh_state(self.tokens / "refresh_state.json")
        self.assertEqual(state["result"], "success")
        self.assertEqual(state["http_status"], 200)
        self.assertFalse(rejected_marker.exists())
        for name in ("renewal_credentials.json", "proxy_pass.jwt"):
            mode = stat.S_IMODE((self.tokens / name).stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_cleanup_removes_legacy_full_browser_storage(self) -> None:
        storage = self.data / "ff_storage.json"
        storage.write_text("legacy browser credentials", encoding="utf-8")
        oauth_cache = self.tokens / "fxa_token.txt"
        oauth_cache.write_text("legacy OAuth token", encoding="utf-8")

        with (
            patch.object(login_and_bootstrap, "TOKENS", self.tokens),
            patch.object(login_and_bootstrap, "DATA", self.data),
            patch.object(login_and_bootstrap, "LOGS", self.logs),
        ):
            login_and_bootstrap.cleanup_legacy_credential_cache()

        # A failed bootstrap must not erase the only legacy recovery material.
        self.assertTrue(storage.exists())
        self.assertFalse(oauth_cache.exists())

        with (
            patch.object(login_and_bootstrap, "TOKENS", self.tokens),
            patch.object(login_and_bootstrap, "DATA", self.data),
            patch.object(login_and_bootstrap, "LOGS", self.logs),
        ):
            login_and_bootstrap.cleanup_legacy_credential_cache(
                remove_browser_storage=True
            )

        self.assertFalse(storage.exists())


if __name__ == "__main__":
    unittest.main()
