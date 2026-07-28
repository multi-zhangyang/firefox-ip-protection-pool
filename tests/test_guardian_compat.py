from __future__ import annotations

import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fxa.errors import ClientError

import refresh_tokens
import refresh_state
from refresh_state import load_refresh_state, record_refresh_state


def _b64url(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_proxy_pass(*, expires_at: int) -> str:
    now = int(time.time())
    claims = {
        "sub": "synthetic-subject",
        "aud": refresh_tokens.GUARDIAN,
        "iat": now - 10,
        "nbf": now - 10,
        "exp": expires_at,
        "iss": "vpn.mozilla.org",
    }
    return f"{_b64url({'alg': 'RS256'})}.{_b64url(claims)}.{_b64url({'sig': True})}"


def response(status: int, *, token: str | None = None, headers: dict[str, str] | None = None) -> Mock:
    result = Mock(status_code=status, headers=headers or {})
    result.json.return_value = {"token": token} if token is not None else {}
    return result


class GuardianRequestHeaderTests(unittest.TestCase):
    def test_all_guardian_methods_receive_current_desktop_headers(self) -> None:
        for method, path in (
            ("GET", "/api/v1/fpn/token"),
            ("HEAD", "/api/v1/fpn/token"),
            ("GET", "/api/v1/fpn/status"),
            ("POST", "/api/v1/fpn/activate"),
        ):
            with self.subTest(method=method, path=path):
                response = Mock(status_code=200)
                with patch.object(
                    refresh_tokens.requests,
                    "request",
                    return_value=response,
                ) as request:
                    returned = refresh_tokens.guardian_request(
                        method,
                        path,
                        headers={"Authorization": "Bearer synthetic-access-token"},
                        label="synthetic",
                    )

                self.assertIs(returned, response)
                sent_headers = request.call_args.kwargs["headers"]
                self.assertEqual(
                    sent_headers["Authorization"],
                    "Bearer synthetic-access-token",
                )
                self.assertEqual(sent_headers["Accept"], "application/json")
                self.assertEqual(sent_headers["Content-Type"], "application/json")
                self.assertEqual(sent_headers["Cache-Control"], "no-cache")
                self.assertEqual(sent_headers["Pragma"], "no-cache")

    def test_429_is_returned_without_retry(self) -> None:
        rate_limited = response(429, headers={"Retry-After": "60"})
        with (
            patch.object(refresh_tokens.requests, "request", return_value=rate_limited) as request,
            patch.object(refresh_tokens.time, "sleep") as sleep,
        ):
            returned = refresh_tokens.guardian_request(
                "GET",
                "/api/v1/fpn/token",
                headers={"Authorization": "Bearer synthetic-access-token"},
                label="synthetic",
            )
        self.assertIs(returned, rate_limited)
        request.assert_called_once()
        sleep.assert_not_called()

    def test_5xx_retry_after_outside_budget_is_not_slept_or_retried(self) -> None:
        unavailable = response(503, headers={"Retry-After": "31"})
        with (
            patch.object(refresh_tokens.requests, "request", return_value=unavailable) as request,
            patch.object(refresh_tokens.time, "sleep") as sleep,
        ):
            returned = refresh_tokens.guardian_request(
                "GET",
                "/api/v1/fpn/token",
                headers={"Authorization": "Bearer synthetic-access-token"},
                label="synthetic",
            )
        self.assertIs(returned, unavailable)
        request.assert_called_once()
        sleep.assert_not_called()

    def test_network_error_retries_within_budget(self) -> None:
        recovered = response(200)
        with (
            patch.object(
                refresh_tokens.requests,
                "request",
                side_effect=[refresh_tokens.requests.ConnectionError("synthetic outage"), recovered],
            ) as request,
            patch.object(refresh_tokens.time, "sleep") as sleep,
        ):
            returned = refresh_tokens.guardian_request(
                "GET",
                "/api/v1/fpn/token",
                headers={"Authorization": "Bearer synthetic-access-token"},
                label="synthetic",
            )
        self.assertIs(returned, recovered)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(1.0)


class RefreshHelperLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.tokens = root / "tokens"
        self.logs = root / "logs"
        self.state_file = self.tokens / "refresh_state.json"
        self.tokens.mkdir()
        self.patches = (
            patch.object(refresh_tokens, "TOKENS", self.tokens),
            patch.object(refresh_tokens, "LOGS", self.logs),
            patch.object(refresh_tokens, "REFRESH_STATE_FILE", self.state_file),
        )
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def run_helper(self, guardian_response: Mock, *args: str) -> tuple[int, Mock, Mock]:
        (self.tokens / "session_token.txt").write_text(
            "synthetic-session-token\n", encoding="utf-8"
        )
        oauth = Mock()
        oauth.authorize_token.return_value = "synthetic-access-token"
        stretched = Mock(v1="synthetic-stretched-password")
        with (
            patch.object(
                refresh_tokens,
                "load_account",
                return_value={
                    "email": "synthetic@example.invalid",
                    "uid": "synthetic-uid",
                },
            ),
            patch.object(refresh_tokens, "APIClient", return_value=Mock()),
            patch.object(refresh_tokens, "StretchedPassword", return_value=stretched),
            patch.object(refresh_tokens, "FxSession", return_value=Mock()),
            patch.object(refresh_tokens, "OAuthClient", return_value=oauth),
            patch.object(
                refresh_tokens.requests,
                "request",
                return_value=guardian_response,
            ) as request,
        ):
            exit_code = refresh_tokens.main(list(args))
        return exit_code, oauth, request

    def test_fxa_clients_disable_adapter_retries_and_bound_each_request(self) -> None:
        session = Mock()
        client = Mock()
        with (
            patch.object(refresh_tokens.requests, "Session", return_value=session),
            patch.object(refresh_tokens, "APIClient", return_value=client) as api_client,
        ):
            returned = refresh_tokens.bounded_fxa_api_client(
                "https://oauth.accounts.firefox.com/v1"
            )

        self.assertIs(returned, client)
        api_client.assert_called_once_with(
            "https://oauth.accounts.firefox.com/v1",
            session=session,
        )
        self.assertEqual(client.timeout, refresh_tokens.FXA_HTTP_TIMEOUT)

    def test_legacy_browser_storage_is_never_used_as_refresh_credentials(self) -> None:
        legacy_data = Path(self.temp.name) / "data"
        legacy_data.mkdir()
        (legacy_data / "ff_storage.json").write_text(
            json.dumps(
                {
                    "origins": [
                        {
                            "localStorage": [
                                {
                                    "name": "__fxa_storage.accounts",
                                    "value": json.dumps(
                                        {
                                            "account": {
                                                "email": "legacy@example.invalid",
                                                "uid": "legacy-uid",
                                                "sessionToken": "legacy-session",
                                            }
                                        }
                                    ),
                                }
                            ]
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        with patch.object(refresh_tokens, "ROOT", Path(self.temp.name)):
            with self.assertRaisesRegex(SystemExit, "account_meta.json"):
                refresh_tokens.load_account()

    def test_oauth_429_has_its_own_soft_rate_limit_state(self) -> None:
        (self.tokens / "session_token.txt").write_text(
            "synthetic-session-token\n", encoding="utf-8"
        )
        oauth = Mock()
        oauth.authorize_token.side_effect = ClientError(
            {"code": 429, "errno": 114, "message": "synthetic rate limit"}
        )
        with (
            patch.object(
                refresh_tokens,
                "load_account",
                return_value={
                    "email": "synthetic@example.invalid",
                    "uid": "synthetic-uid",
                },
            ),
            patch.object(refresh_tokens, "APIClient", return_value=Mock()),
            patch.object(
                refresh_tokens,
                "StretchedPassword",
                return_value=Mock(v1="synthetic-stretched-password"),
            ),
            patch.object(refresh_tokens, "FxSession", return_value=Mock()),
            patch.object(refresh_tokens, "OAuthClient", return_value=oauth),
            patch.object(refresh_tokens.requests, "request") as guardian_request,
        ):
            exit_code = refresh_tokens.main(["--force"])

        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        guardian_request.assert_not_called()
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "oauth_rate_limited")
        self.assertEqual(state["http_status"], 429)
        self.assertGreater(state["next_attempt_at"], time.time())

    def test_success_is_atomic_persisted_and_oauth_is_destroyed(self) -> None:
        now = int(time.time())
        token = make_proxy_pass(expires_at=now + 600)
        legacy = self.tokens / "fxa_token.txt"
        legacy.write_text("legacy-access-token\n", encoding="utf-8")

        exit_code, oauth, request = self.run_helper(response(200, token=token), "--force")

        self.assertEqual(exit_code, 0)
        self.assertEqual((self.tokens / "proxy_pass.jwt").read_text(encoding="utf-8"), token + "\n")
        self.assertFalse(legacy.exists())
        oauth.destroy_token.assert_called_once_with("synthetic-access-token")
        request.assert_called_once()
        self.assertTrue(request.call_args.args[1].endswith("/api/v1/fpn/token"))
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "success")
        self.assertEqual(state["http_status"], 200)
        self.assertEqual(state["proxy_pass_expires_at"], float(now + 600))
        serialized_state = self.state_file.read_text(encoding="utf-8")
        self.assertNotIn("synthetic-access-token", serialized_state)
        self.assertNotIn("synthetic@example.invalid", serialized_state)

    def test_freshness_boundary_is_120_seconds(self) -> None:
        now = int(time.time())
        current = make_proxy_pass(expires_at=now + 121)
        (self.tokens / "proxy_pass.jwt").write_text(current + "\n", encoding="utf-8")
        with (
            patch.object(refresh_tokens, "load_account") as load_account,
            patch.object(refresh_tokens.requests, "request") as request,
        ):
            exit_code = refresh_tokens.main([])
        self.assertEqual(exit_code, 0)
        load_account.assert_not_called()
        request.assert_not_called()
        self.assertEqual(load_refresh_state(self.state_file)["result"], "fresh")

        replacement = make_proxy_pass(expires_at=now + 600)
        (self.tokens / "proxy_pass.jwt").write_text(
            make_proxy_pass(expires_at=int(time.time()) + 120) + "\n",
            encoding="utf-8",
        )
        exit_code, _, request = self.run_helper(response(200, token=replacement))
        self.assertEqual(exit_code, 0)
        request.assert_called_once()

    def test_force_bypasses_freshness(self) -> None:
        now = time.time()
        current = make_proxy_pass(expires_at=int(now) + 600)
        replacement = make_proxy_pass(expires_at=int(now) + 900)
        (self.tokens / "proxy_pass.jwt").write_text(current + "\n", encoding="utf-8")

        exit_code, _, request = self.run_helper(response(200, token=replacement), "--force")

        self.assertEqual(exit_code, 0)
        request.assert_called_once()
        self.assertEqual((self.tokens / "proxy_pass.jwt").read_text(encoding="utf-8"), replacement + "\n")

    def test_force_does_not_bypass_persisted_cooldown(self) -> None:
        now = time.time()
        record_refresh_state(
            self.state_file,
            "rate_limited",
            now=now,
            http_status=429,
            next_attempt_at=now + 600,
        )
        with (
            patch.object(refresh_tokens, "load_account") as load_account,
            patch.object(refresh_tokens.requests, "request") as request,
        ):
            exit_code = refresh_tokens.main(["--force"])
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        load_account.assert_not_called()
        request.assert_not_called()

    def test_persisted_next_attempt_is_respected(self) -> None:
        now = time.time()
        record_refresh_state(
            self.state_file,
            "rate_limited",
            now=now,
            http_status=429,
            next_attempt_at=now + 600,
        )
        with (
            patch.object(refresh_tokens, "load_account") as load_account,
            patch.object(refresh_tokens.requests, "request") as request,
        ):
            exit_code = refresh_tokens.main([])
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        load_account.assert_not_called()
        request.assert_not_called()
        self.assertEqual(load_refresh_state(self.state_file)["result"], "rate_limited")

    def test_429_is_persisted_once_and_oauth_is_destroyed(self) -> None:
        before = time.time()
        exit_code, oauth, request = self.run_helper(
            response(429, headers={"Retry-After": "60"}),
            "--force",
        )
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        request.assert_called_once()
        oauth.destroy_token.assert_called_once_with("synthetic-access-token")
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "rate_limited")
        self.assertEqual(state["http_status"], 429)
        self.assertGreaterEqual(state["next_attempt_at"], before + 59)
        self.assertLessEqual(state["next_attempt_at"], time.time() + 61)

    def test_429_uses_quota_reset_before_exponential_backoff(self) -> None:
        reset_at = time.time() + 180
        reset = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(reset_at))
        exit_code, _, request = self.run_helper(
            response(429, headers={"X-Quota-Reset": reset}),
            "--force",
        )
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        request.assert_called_once()
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "rate_limited")
        self.assertAlmostEqual(state["next_attempt_at"], reset_at, delta=2)

    def test_429_retry_after_takes_precedence_over_quota_reset(self) -> None:
        before = time.time()
        reset = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(before + 180),
        )
        exit_code, _, request = self.run_helper(
            response(
                429,
                headers={
                    "Retry-After": "60",
                    "X-Quota-Reset": reset,
                },
            ),
            "--force",
        )
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        request.assert_called_once()
        state = load_refresh_state(self.state_file)
        self.assertGreaterEqual(state["next_attempt_at"], before + 59.9)
        self.assertLessEqual(state["next_attempt_at"], time.time() + 60.1)

    def test_429_with_invalid_cooldown_headers_uses_exponential_backoff(self) -> None:
        before = time.time()
        exit_code, _, request = self.run_helper(
            response(
                429,
                headers={
                    "Retry-After": "-1",
                    "X-Quota-Reset": "not-a-timestamp",
                },
            ),
            "--force",
        )
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        request.assert_called_once()
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "rate_limited")
        self.assertGreaterEqual(state["next_attempt_at"], before + 4.9)
        self.assertLessEqual(state["next_attempt_at"], time.time() + 5.1)

    def test_exhausted_5xx_retries_destroy_oauth_token(self) -> None:
        with patch.object(refresh_tokens.time, "sleep") as sleep:
            exit_code, oauth, request = self.run_helper(response(503), "--force")

        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        self.assertEqual(request.call_count, refresh_tokens.HTTP_ATTEMPTS)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1.0, 2.0])
        oauth.destroy_token.assert_called_once_with("synthetic-access-token")
        state = load_refresh_state(self.state_file)
        self.assertEqual(state["result"], "transient_error")
        self.assertEqual(state["http_status"], 503)

    def test_background_refresh_never_activates_on_auth_or_protocol_errors(self) -> None:
        expected = {
            401: "reauth_required",
            403: "no_entitlement",
            404: "protocol_error",
        }
        for status, result in expected.items():
            with self.subTest(status=status):
                self.state_file.unlink(missing_ok=True)
                exit_code, oauth, request = self.run_helper(response(status), "--force")
                self.assertEqual(exit_code, 1)
                request.assert_called_once()
                self.assertNotIn("/activate", request.call_args.args[1])
                oauth.destroy_token.assert_called_once_with("synthetic-access-token")
                state = load_refresh_state(self.state_file)
                self.assertEqual(state["result"], result)
                self.assertEqual(state["http_status"], status)

    def test_too_short_new_pass_does_not_replace_last_good(self) -> None:
        now = int(time.time())
        old_token = make_proxy_pass(expires_at=now + 60)
        short_token = make_proxy_pass(expires_at=now + 120)
        proxy_path = self.tokens / "proxy_pass.jwt"
        proxy_path.write_text(old_token + "\n", encoding="utf-8")

        exit_code, oauth, _ = self.run_helper(response(200, token=short_token), "--force")

        self.assertEqual(exit_code, 1)
        self.assertEqual(proxy_path.read_text(encoding="utf-8"), old_token + "\n")
        self.assertEqual(load_refresh_state(self.state_file)["result"], "protocol_error")
        oauth.destroy_token.assert_called_once_with("synthetic-access-token")

    def test_lock_conflict_returns_tempfail_without_network(self) -> None:
        with (
            patch.object(refresh_state.fcntl, "flock", side_effect=BlockingIOError),
            patch.object(refresh_tokens.requests, "request") as request,
        ):
            exit_code = refresh_tokens.main([])
        self.assertEqual(exit_code, refresh_tokens.EX_TEMPFAIL)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
