from __future__ import annotations

import io
import json
import stat
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import import_credentials
import renewal_credentials
from refresh_state import load_refresh_state, record_refresh_state, refresh_lock


class CredentialImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tokens = self.root / "tokens"
        self.source = self.root / "fxa-renewal-credentials.json"
        self.email = "desktop@example.invalid"
        self.uid = "a" * 32
        self.session_token = "b" * 64

    def write_bundle(self, **updates: object) -> Path:
        value: dict[str, object] = {
            "schema": import_credentials.BUNDLE_SCHEMA,
            "email": self.email,
            "uid": self.uid,
            "session_token": self.session_token,
        }
        value.update(updates)
        self.source.write_text(json.dumps(value), encoding="utf-8")
        self.source.chmod(0o600)
        return self.source

    def test_import_publishes_only_minimal_renewal_inputs_with_mode_0600(self) -> None:
        source = self.write_bundle()
        rejected = self.tokens / "rejected_proxy_pass.sha256"
        rejected.parent.mkdir()
        rejected.write_text("c" * 64 + "\n", encoding="ascii")
        (self.tokens / "session_token.txt").write_text(
            "superseded-session\n", encoding="utf-8"
        )
        (self.tokens / "account_meta.json").write_text(
            json.dumps(
                {"email": "superseded@example.invalid", "uid": "superseded-uid"}
            ),
            encoding="utf-8",
        )
        record_refresh_state(
            self.tokens / "refresh_state.json",
            "reauth_required",
            next_attempt_at=9999999999,
        )

        bundle = import_credentials.load_bundle(str(source))
        published = import_credentials.publish_bundle(bundle, self.tokens)

        canonical = self.tokens / renewal_credentials.FILENAME
        self.assertEqual(
            json.loads(canonical.read_text(encoding="utf-8")),
            {
                "schema": renewal_credentials.SCHEMA_VERSION,
                "email": self.email,
                "uid": self.uid,
                "session_token": self.session_token,
            },
        )
        self.assertEqual(
            renewal_credentials.load_renewal_credentials(self.tokens),
            {
                "email": self.email,
                "uid": self.uid,
                "session_token": self.session_token,
            },
        )
        self.assertFalse((self.tokens / "session_token.txt").exists())
        self.assertFalse((self.tokens / "account_meta.json").exists())
        self.assertFalse(rejected.exists())
        state = load_refresh_state(self.tokens / "refresh_state.json")
        self.assertEqual(state["result"], "credentials_imported")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertIsNone(state["next_attempt_at"])
        self.assertEqual(published.generation, state["generation"])
        self.assertEqual(
            published.canonical_marker,
            import_credentials._canonical_marker(canonical),
        )
        for name in (renewal_credentials.FILENAME, "refresh_state.json"):
            self.assertEqual(
                stat.S_IMODE((self.tokens / name).stat().st_mode),
                0o600,
            )

    def test_unknown_fields_are_rejected_without_writing_credentials(self) -> None:
        source = self.write_bundle(oauthTokens={"private": "must-not-import"})

        with self.assertRaisesRegex(
            import_credentials.CredentialImportError,
            "missing or unexpected fields",
        ):
            import_credentials.load_bundle(str(source))

        self.assertFalse(self.tokens.exists())

    def test_import_waits_for_an_inflight_refresh_writer(self) -> None:
        bundle = import_credentials.load_bundle(str(self.write_bundle()))
        started = threading.Event()
        errors: list[BaseException] = []

        def publish() -> None:
            started.set()
            try:
                import_credentials.publish_bundle(bundle, self.tokens)
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with refresh_lock(self.tokens, blocking=True):
            thread = threading.Thread(target=publish)
            thread.start()
            self.assertTrue(started.wait(1))
            thread.join(0.1)
            self.assertTrue(thread.is_alive())
            self.assertFalse(
                (self.tokens / renewal_credentials.FILENAME).exists()
            )

        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue((self.tokens / renewal_credentials.FILENAME).exists())

    def test_group_or_world_readable_bundle_is_rejected(self) -> None:
        source = self.write_bundle()
        source.chmod(0o644)

        with self.assertRaisesRegex(
            import_credentials.CredentialImportError,
            "permissions are too broad",
        ):
            import_credentials.load_bundle(str(source))

    def test_cli_verifies_then_deletes_source_without_printing_secrets(self) -> None:
        source = self.write_bundle()
        stdout = io.StringIO()
        stderr = io.StringIO()

        def successful_refresh(*args: object, **kwargs: object) -> SimpleNamespace:
            record_refresh_state(
                self.tokens / "refresh_state.json",
                "success",
                proxy_pass_expires_at=time.time() + 900,
            )
            return SimpleNamespace(returncode=0)

        with (
            patch.object(import_credentials, "TOKENS", self.tokens),
            patch.object(
                import_credentials.subprocess,
                "run",
                side_effect=successful_refresh,
            ) as run,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = import_credentials.main([str(source), "--delete-source"])

        self.assertEqual(exit_code, 0)
        self.assertFalse(source.exists())
        self.assertTrue((self.tokens / renewal_credentials.FILENAME).exists())
        self.assertEqual(
            load_refresh_state(self.tokens / "refresh_state.json")["result"],
            "success",
        )
        run.assert_called_once_with(
            [
                import_credentials.sys.executable,
                str(import_credentials.ROOT / "refresh_tokens.py"),
                "--force",
            ],
            check=False,
        )
        output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(self.email, output)
        self.assertNotIn(self.uid, output)
        self.assertNotIn(self.session_token, output)

    def test_failed_verification_keeps_the_transfer_bundle(self) -> None:
        source = self.write_bundle()
        with (
            patch.object(import_credentials, "TOKENS", self.tokens),
            patch.object(import_credentials, "VERIFY_BUSY_TIMEOUT_SECONDS", 0),
            patch.object(
                import_credentials.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=75),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = import_credentials.main([str(source), "--delete-source"])

        self.assertEqual(exit_code, 75)
        self.assertTrue(source.exists())

    def test_helper_start_failure_is_sanitized_and_keeps_source(self) -> None:
        source = self.write_bundle()
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(import_credentials, "TOKENS", self.tokens),
            patch.object(
                import_credentials.subprocess,
                "run",
                side_effect=OSError("synthetic-sensitive-process-detail"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = import_credentials.main([str(source), "--delete-source"])

        self.assertEqual(exit_code, 1)
        self.assertTrue(source.exists())
        output = stdout.getvalue() + stderr.getvalue()
        self.assertIn("renewal check could not start", output)
        self.assertNotIn("synthetic-sensitive-process-detail", output)
        self.assertNotIn(self.email, output)
        self.assertNotIn(self.uid, output)
        self.assertNotIn(self.session_token, output)

    def test_busy_helper_adopts_one_concurrent_success_without_retrying_force(self) -> None:
        source = self.write_bundle()
        owner_finished = threading.Event()

        def busy_helper(*args: object, **kwargs: object) -> SimpleNamespace:
            record_refresh_state(
                self.tokens / "refresh_state.json",
                "in_progress",
            )

            def finish_as_lock_owner() -> None:
                time.sleep(0.02)
                record_refresh_state(
                    self.tokens / "refresh_state.json",
                    "success",
                    proxy_pass_expires_at=time.time() + 900,
                )
                owner_finished.set()

            threading.Thread(target=finish_as_lock_owner, daemon=True).start()
            return SimpleNamespace(returncode=75)

        with (
            patch.object(import_credentials, "TOKENS", self.tokens),
            patch.object(import_credentials, "VERIFY_BUSY_TIMEOUT_SECONDS", 1.0),
            patch.object(import_credentials, "VERIFY_STATE_POLL_SECONDS", 0.005),
            patch.object(
                import_credentials.subprocess,
                "run",
                side_effect=busy_helper,
            ) as run,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = import_credentials.main([str(source), "--delete-source"])

        self.assertEqual(exit_code, 0)
        self.assertTrue(owner_finished.wait(1))
        self.assertFalse(source.exists())
        self.assertEqual(run.call_count, 1)
        state = load_refresh_state(self.tokens / "refresh_state.json")
        self.assertEqual(state["result"], "success")
        self.assertEqual(state["generation"], 1)

    def test_busy_helper_reports_concurrent_terminal_failure_without_retry(self) -> None:
        source = self.write_bundle()

        def failed_lock_owner(*args: object, **kwargs: object) -> SimpleNamespace:
            record_refresh_state(
                self.tokens / "refresh_state.json",
                "reauth_required",
                next_attempt_at=time.time() + 300,
            )
            return SimpleNamespace(returncode=75)

        with (
            patch.object(import_credentials, "TOKENS", self.tokens),
            patch.object(
                import_credentials.subprocess,
                "run",
                side_effect=failed_lock_owner,
            ) as run,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = import_credentials.main([str(source), "--delete-source"])

        self.assertEqual(exit_code, 1)
        self.assertTrue(source.exists())
        self.assertEqual(run.call_count, 1)

    def test_concurrent_wait_rejects_a_later_credential_publication(self) -> None:
        first = import_credentials.publish_bundle(
            import_credentials.load_bundle(str(self.write_bundle())),
            self.tokens,
        )
        renewal_credentials.write_renewal_credentials(
            self.tokens,
            email="replacement@example.invalid",
            uid="c" * 32,
            session_token="d" * 64,
        )
        record_refresh_state(
            self.tokens / "refresh_state.json",
            "success",
        )

        with self.assertRaisesRegex(
            import_credentials.CredentialVerificationError,
            "replaced by another import",
        ):
            import_credentials._wait_for_concurrent_verification(
                first,
                self.tokens,
                timeout=0,
            )

    def test_legacy_cleanup_failure_leaves_canonical_credentials_blocked(self) -> None:
        self.tokens.mkdir()
        (self.tokens / "session_token.txt").mkdir()
        bundle = import_credentials.load_bundle(str(self.write_bundle()))

        with self.assertRaisesRegex(
            import_credentials.CredentialImportError,
            "legacy credentials could not be removed",
        ):
            import_credentials.publish_bundle(bundle, self.tokens)

        self.assertTrue((self.tokens / renewal_credentials.FILENAME).is_file())
        state = load_refresh_state(self.tokens / "refresh_state.json")
        self.assertEqual(state["result"], "credentials_imported")
        self.assertIsNone(state["next_attempt_at"])


class DesktopExporterTests(unittest.TestCase):
    def test_exporter_is_offline_and_uses_the_minimal_bundle_schema(self) -> None:
        page = (
            Path(import_credentials.ROOT) / "tools" / "firefox-credential-export.html"
        ).read_text(encoding="utf-8")

        self.assertIn("connect-src 'none'", page)
        self.assertIn(import_credentials.BUNDLE_SCHEMA, page)
        self.assertIn("signedInUser.json", page)
        self.assertIn("parsed.version !== 1", page)
        self.assertIn("session_token", page)
        self.assertIn("account.device", page)
        self.assertNotIn("https://", page)
        self.assertNotIn("http://", page)
        self.assertNotRegex(page, r"<script\s+[^>]*src=")


if __name__ == "__main__":
    unittest.main()
