from __future__ import annotations

import base64
import email.message
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ipp_pool
import refresh_tokens
from refresh_state import record_refresh_state


def _segment(value: dict[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(expires_at: float, subject: str = "synthetic-subject") -> str:
    now = int(time.time())
    return ".".join(
        (
            _segment({"alg": "RS256", "typ": "JWT"}),
            _segment(
                {
                    "sub": subject,
                    "aud": "https://vpn.mozilla.org",
                    "iat": now - 1,
                    "nbf": now - 1,
                    "exp": int(expires_at),
                    "iss": "https://vpn.mozilla.org",
                }
            ),
            base64.urlsafe_b64encode(b"synthetic-signature")
            .decode("ascii")
            .rstrip("="),
        )
    )


class TokenRefreshLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.token_dir = Path(self.temporary.name)

    def store(self, **kwargs) -> ipp_pool.TokenStore:
        return ipp_pool.TokenStore(token_dir=self.token_dir, **kwargs)

    def enable_session_refresh(self) -> None:
        (self.token_dir / "session_token.txt").write_text(
            "synthetic-session\n", encoding="utf-8"
        )
        (self.token_dir / "account_meta.json").write_text(
            json.dumps(
                {
                    "email": "test@example.invalid",
                    "uid": "synthetic-uid",
                }
            ),
            encoding="utf-8",
        )

    def test_last_good_remains_usable_inside_the_proactive_refresh_window(self) -> None:
        last_good = _token(time.time() + 60)
        store = self.store(proxy_pass=last_good)

        self.assertTrue(store.should_refresh())
        self.assertTrue(store.is_usable())
        self.assertEqual(store.ensure(), last_good)

    def test_explicit_proxy_pass_wins_over_existing_disk_cache_at_startup(self) -> None:
        disk_token = _token(time.time() + 600, "disk")
        explicit_token = _token(time.time() + 900, "explicit")
        (self.token_dir / "proxy_pass.jwt").write_text(
            disk_token + "\n", encoding="utf-8"
        )

        store = self.store(proxy_pass=explicit_token)

        self.assertEqual(store.current(), explicit_token)

    def test_atomic_external_replacement_is_detected_even_with_older_mtime(self) -> None:
        original = _token(time.time() + 600, "original")
        replacement = _token(time.time() + 900, "replacement")
        proxy_path = self.token_dir / "proxy_pass.jwt"
        proxy_path.write_text(original + "\n", encoding="utf-8")
        store = self.store()
        old_mtime = proxy_path.stat().st_mtime
        temporary = self.token_dir / ".replacement"
        temporary.write_text(replacement + "\n", encoding="utf-8")
        os.utime(temporary, (old_mtime - 10, old_mtime - 10))
        os.replace(temporary, proxy_path)

        self.assertEqual(store.current(), replacement)

    def test_slow_refresh_does_not_block_reads_of_a_usable_last_good(self) -> None:
        last_good = _token(time.time() + 60, "old")
        replacement = _token(time.time() + 600, "new")
        self.enable_session_refresh()
        store = self.store(proxy_pass=last_good)
        started = threading.Event()
        release = threading.Event()

        def helper(*_args, **_kwargs):
            started.set()
            self.assertTrue(release.wait(2))
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            return SimpleNamespace(returncode=0)

        errors: list[Exception] = []

        def renew() -> None:
            try:
                store.refresh()
            except Exception as exc:  # pragma: no cover - assertion reports the value
                errors.append(exc)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper):
            thread = threading.Thread(target=renew)
            thread.start()
            self.assertTrue(started.wait(1))
            self.assertEqual(store.ensure(), last_good)
            release.set()
            thread.join(2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(store.current(), replacement)

    def test_concurrent_callers_share_one_successful_helper_refresh(self) -> None:
        replacement = _token(time.time() + 600)
        self.enable_session_refresh()
        store = self.store()
        entered = threading.Event()
        release = threading.Event()

        def helper(*_args, **_kwargs):
            entered.set()
            self.assertTrue(release.wait(2))
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            return SimpleNamespace(returncode=0)

        results: list[str] = []
        errors: list[Exception] = []

        def ensure() -> None:
            try:
                results.append(store.ensure())
            except Exception as exc:  # pragma: no cover - assertion reports the value
                errors.append(exc)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper) as run:
            threads = [threading.Thread(target=ensure) for _ in range(8)]
            for thread in threads:
                thread.start()
            self.assertTrue(entered.wait(1))
            release.set()
            for thread in threads:
                thread.join(2)

        self.assertEqual(errors, [])
        self.assertEqual(results, [replacement] * 8)
        self.assertEqual(run.call_count, 1)

    def test_concurrent_callers_share_failure_backoff(self) -> None:
        store = self.store(fxa_token="synthetic-fxa-access")
        errors: list[Exception] = []

        def ensure() -> None:
            try:
                store.ensure()
            except Exception as exc:
                errors.append(exc)

        with (
            patch.object(
                ipp_pool.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError("synthetic outage"),
            ) as urlopen,
            patch.object(ipp_pool.time, "sleep"),
        ):
            threads = [threading.Thread(target=ensure) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)

        self.assertEqual(len(errors), 8)
        self.assertEqual(urlopen.call_count, 3)
        self.assertGreater(store.status()["retry_at"], time.time())

    def test_force_refresh_quarantines_rejected_token_and_only_runs_once(self) -> None:
        rejected = _token(time.time() + 600, "rejected")
        replacement = _token(time.time() + 900, "replacement")
        (self.token_dir / "proxy_pass.jwt").write_text(
            rejected + "\n", encoding="utf-8"
        )
        self.enable_session_refresh()
        store = self.store()

        def helper(command, **kwargs):
            self.assertIn("--force", command)
            self.assertEqual(
                kwargs["timeout"], ipp_pool.REFRESH_HELPER_TIMEOUT_SECONDS
            )
            # The old file is not unlinked: deleting it after a read would
            # race another process atomically publishing a replacement.
            self.assertEqual(
                (self.token_dir / "proxy_pass.jwt").read_text(encoding="utf-8").strip(),
                rejected,
            )
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            record_refresh_state(
                self.token_dir / "refresh_state.json",
                "success",
                proxy_pass_expires_at=time.time() + 900,
            )
            return SimpleNamespace(returncode=0)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper) as run:
            self.assertEqual(
                store.refresh(force=True, rejected_token=rejected), replacement
            )
            self.assertEqual(
                store.refresh(force=True, rejected_token=rejected), replacement
            )

        self.assertEqual(run.call_count, 1)
        self.assertNotEqual(store.current(), rejected)
        self.assertEqual(store.status()["refresh_state"]["generation"], 1)
        self.assertFalse((self.token_dir / "rejected_proxy_pass.sha256").exists())

    def test_helper_supervisor_budget_exceeds_all_bounded_inner_requests(self) -> None:
        # authorize_code, trade_code, and destroy_token can each be repeated
        # once by PyFxA for clock-skew correction.  Guardian has its own total
        # retry budget.  The subprocess timeout must leave room for all six
        # bounded FxA requests plus Guardian work.
        worst_case_inner = refresh_tokens.HTTP_RETRY_BUDGET + 6 * sum(
            refresh_tokens.FXA_HTTP_TIMEOUT
        )
        self.assertGreater(
            ipp_pool.REFRESH_HELPER_TIMEOUT_SECONDS,
            worst_case_inner,
        )

    def test_rejected_token_stays_quarantined_across_process_restart(self) -> None:
        rejected = _token(time.time() + 600, "rejected")
        (self.token_dir / "proxy_pass.jwt").write_text(
            rejected + "\n", encoding="utf-8"
        )
        self.enable_session_refresh()
        store = self.store()

        with patch.object(
            ipp_pool.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=1),
        ):
            with self.assertRaises(RuntimeError):
                store.refresh(force=True, rejected_token=rejected)

        marker = self.token_dir / "rejected_proxy_pass.sha256"
        self.assertTrue(marker.exists())
        self.assertNotIn(rejected, marker.read_text(encoding="ascii"))
        restarted = self.store()
        self.assertIsNone(restarted.current())
        self.assertFalse(restarted.is_usable())

        replacement = _token(time.time() + 900, "replacement")
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "transient_error",
            next_attempt_at=time.time() - 1,
        )

        def helper(command, **_kwargs):
            self.assertIn("--force", command)
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            record_refresh_state(
                self.token_dir / "refresh_state.json",
                "success",
                http_status=200,
                proxy_pass_expires_at=time.time() + 900,
            )
            return SimpleNamespace(returncode=0)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper):
            self.assertEqual(restarted.refresh(), replacement)

    def test_session_helper_failure_never_uses_direct_fallback(self) -> None:
        self.enable_session_refresh()
        store = self.store(fxa_token="synthetic-fxa-access")

        with (
            patch.object(
                ipp_pool.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=1),
            ),
            patch.object(ipp_pool.urllib.request, "urlopen") as urlopen,
        ):
            with self.assertRaises(RuntimeError):
                store.refresh()

        urlopen.assert_not_called()
        self.assertEqual(store.status()["refresh_state"]["result"], "transient_error")

    def test_helper_busy_exit_does_not_overwrite_the_lock_owner_state(self) -> None:
        self.enable_session_refresh()
        store = self.store(fxa_token="synthetic-fxa-access")

        with (
            patch.object(
                ipp_pool.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=75),
            ),
            patch.object(ipp_pool.urllib.request, "urlopen") as urlopen,
        ):
            with self.assertRaises(RuntimeError):
                store.refresh()

        urlopen.assert_not_called()
        status = store.status()
        self.assertEqual(status["refresh_state"]["result"], "never")
        self.assertGreater(status["retry_at"], time.time())

    def test_persisted_backoff_is_loaded_without_exposing_credentials(self) -> None:
        next_attempt = time.time() + 300
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "rate_limited",
            http_status=429,
            next_attempt_at=next_attempt,
        )
        self.enable_session_refresh()
        store = self.store(fxa_token="do-not-leak-this-access-token")

        with patch.object(ipp_pool.urllib.request, "urlopen") as urlopen:
            with self.assertRaises(RuntimeError):
                store.refresh()

        urlopen.assert_not_called()
        status = store.status()
        self.assertTrue(status["automatic_renewal_ready"])
        self.assertEqual(status["last_status"], 429)
        self.assertEqual(status["refresh_state"]["result"], "rate_limited")
        self.assertNotIn("do-not-leak", json.dumps(status))

    def test_external_cooldown_written_after_start_is_honored(self) -> None:
        self.enable_session_refresh()
        store = self.store()
        next_attempt = time.time() + 300
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "rate_limited",
            http_status=429,
            next_attempt_at=next_attempt,
        )

        with patch.object(ipp_pool.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                store.refresh()

        run.assert_not_called()
        status = store.status()
        self.assertEqual(status["refresh_state"]["result"], "rate_limited")
        self.assertAlmostEqual(status["retry_at"], next_attempt, delta=1)

    def test_rate_limited_state_pauses_new_tunnels_even_with_valid_pass(self) -> None:
        valid_token = _token(time.time() + 600)
        store = self.store(proxy_pass=valid_token)
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "rate_limited",
            http_status=429,
            next_attempt_at=time.time() + 300,
        )

        with patch.object(ipp_pool.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "renewal is paused"):
                store.ensure()

        run.assert_not_called()

    def test_expired_rate_limit_forces_revalidation_even_when_pass_is_fresh(self) -> None:
        current = _token(time.time() + 600, "current")
        replacement = _token(time.time() + 900, "replacement")
        (self.token_dir / "proxy_pass.jwt").write_text(
            current + "\n", encoding="utf-8"
        )
        self.enable_session_refresh()
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "rate_limited",
            http_status=429,
            next_attempt_at=time.time() - 1,
        )
        store = self.store()

        def helper(command, **_kwargs):
            self.assertIn("--force", command)
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            record_refresh_state(
                self.token_dir / "refresh_state.json",
                "success",
                http_status=200,
                proxy_pass_expires_at=time.time() + 900,
            )
            return SimpleNamespace(returncode=0)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper) as run:
            self.assertEqual(store.ensure(), replacement)

        run.assert_called_once()

    def test_worker_refresh_revalidates_expired_block_even_with_fresh_pass(self) -> None:
        current = _token(time.time() + 600, "current")
        replacement = _token(time.time() + 900, "replacement")
        (self.token_dir / "proxy_pass.jwt").write_text(
            current + "\n", encoding="utf-8"
        )
        self.enable_session_refresh()
        record_refresh_state(
            self.token_dir / "refresh_state.json",
            "rate_limited",
            http_status=429,
            next_attempt_at=time.time() - 1,
        )
        store = self.store()

        def helper(command, **_kwargs):
            self.assertIn("--force", command)
            # A cooldown must not be cleared merely because the old cache is
            # still fresh; only a real helper success may publish success.
            self.assertEqual(
                store.status()["refresh_state"]["result"], "rate_limited"
            )
            (self.token_dir / "proxy_pass.jwt").write_text(
                replacement + "\n", encoding="utf-8"
            )
            record_refresh_state(
                self.token_dir / "refresh_state.json",
                "success",
                http_status=200,
                proxy_pass_expires_at=time.time() + 900,
            )
            return SimpleNamespace(returncode=0)

        with patch.object(ipp_pool.subprocess, "run", side_effect=helper) as run:
            self.assertEqual(store.refresh(), replacement)

        run.assert_called_once()
        self.assertEqual(store.status()["refresh_state"]["result"], "success")

    def test_malformed_quota_headers_do_not_discard_429_retry_after(self) -> None:
        headers = email.message.Message()
        headers["Retry-After"] = "120"
        headers["X-Quota-Unlimited"] = "false"
        headers["X-Quota-Limit"] = "not-an-integer"
        headers["X-Quota-Remaining"] = "0"
        headers["X-Quota-Reset"] = "2030-01-01T00:00:00Z"
        error = urllib.error.HTTPError(
            "https://vpn.mozilla.org/api/v1/fpn/token",
            429,
            "rate limited",
            headers,
            None,
        )
        store = self.store(fxa_token="synthetic-fxa-access")

        with (
            patch.object(ipp_pool.urllib.request, "urlopen", side_effect=error),
            self.assertWarns(UserWarning),
        ):
            with self.assertRaises(RuntimeError):
                store.refresh()

        status = store.status()
        self.assertEqual(status["last_status"], 429)
        self.assertEqual(status["refresh_state"]["result"], "rate_limited")
        remaining = status["retry_at"] - time.time()
        self.assertGreater(remaining, 115)
        self.assertLessEqual(remaining, 120)

    def test_direct_429_uses_quota_reset_when_retry_after_is_missing(self) -> None:
        reset_at = time.time() + 180
        headers = email.message.Message()
        headers["X-Quota-Reset"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(reset_at)
        )
        error = urllib.error.HTTPError(
            "https://vpn.mozilla.org/api/v1/fpn/token",
            429,
            "rate limited",
            headers,
            None,
        )
        store = self.store(fxa_token="synthetic-fxa-access")

        with patch.object(ipp_pool.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError):
                store.refresh()

        status = store.status()
        self.assertEqual(status["refresh_state"]["result"], "rate_limited")
        self.assertAlmostEqual(status["retry_at"], reset_at, delta=2)

    def test_direct_429_without_valid_headers_uses_exponential_backoff(self) -> None:
        error = urllib.error.HTTPError(
            "https://vpn.mozilla.org/api/v1/fpn/token",
            429,
            "rate limited",
            email.message.Message(),
            None,
        )
        store = self.store(fxa_token="synthetic-fxa-access")
        before = time.time()

        with patch.object(ipp_pool.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError):
                store.refresh()

        retry_at = store.status()["retry_at"]
        self.assertGreaterEqual(retry_at, before + 4.5)
        self.assertLessEqual(retry_at, time.time() + 5.5)

    def test_pool_stop_wakes_and_joins_named_refresh_worker(self) -> None:
        tokens = Mock()
        tokens.should_refresh.return_value = False
        pool = ipp_pool.Pool(
            tokens=tokens,
            nodes=[],
            port_map_file=self.token_dir / "port-map.json",
        )
        worker = pool.start_refresh_worker(interval=60, logger=lambda _message: None)

        self.assertTrue(worker.is_alive())
        self.assertEqual(worker.thread.name, "token-refresh-worker")
        pool.stop()
        self.assertFalse(worker.is_alive())

    def test_worker_success_log_omits_the_jwt_subject(self) -> None:
        stop = threading.Event()
        tokens = Mock()
        tokens.should_refresh.return_value = True
        token = _token(time.time() + 600, "private-account-subject")

        def refreshed() -> str:
            stop.set()
            return token

        tokens.refresh.side_effect = refreshed
        messages: list[str] = []
        worker = ipp_pool.TokenRefreshWorker(
            tokens,
            stop,
            interval=60,
            logger=messages.append,
        ).start()
        if worker.thread is not None:
            worker.thread.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(messages), 1)
        self.assertNotIn("private-account-subject", messages[0])

    def test_token_refresh_cli_accepts_force(self) -> None:
        args = ipp_pool.build_parser().parse_args(["token-refresh", "--force"])
        self.assertTrue(args.force)


if __name__ == "__main__":
    unittest.main()
