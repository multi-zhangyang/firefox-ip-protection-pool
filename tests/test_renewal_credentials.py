from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import renewal_credentials
from renewal_credentials import (
    RenewalCredentialsError,
    load_renewal_credentials,
    write_renewal_credentials,
)


EMAIL = "renewal@example.invalid"
UID = "0123456789abcdef0123456789abcdef"
SESSION_TOKEN = "0123456789abcdef" * 4


class RenewalCredentialStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tokens = Path(self.temporary.name) / "tokens"
        self.tokens.mkdir()

    def write_legacy(
        self,
        *,
        email: str = "legacy@example.invalid",
        uid: str = "legacy-account-uid",
        session_token: str = "legacy-session-token",
    ) -> None:
        (self.tokens / "account_meta.json").write_text(
            json.dumps({"email": email, "uid": uid}),
            encoding="utf-8",
        )
        (self.tokens / "session_token.txt").write_text(
            session_token + "\n",
            encoding="utf-8",
        )

    def test_canonical_write_and_read_uses_private_mode(self) -> None:
        path = write_renewal_credentials(
            self.tokens,
            email=EMAIL,
            uid=UID.upper(),
            session_token=SESSION_TOKEN.upper(),
        )

        self.assertEqual(path, self.tokens / "renewal_credentials.json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8")),
            {
                "schema": 1,
                "email": EMAIL,
                "uid": UID,
                "session_token": SESSION_TOKEN,
            },
        )
        self.assertEqual(
            load_renewal_credentials(self.tokens),
            {
                "email": EMAIL,
                "uid": UID,
                "session_token": SESSION_TOKEN,
            },
        )

    def test_canonical_record_takes_precedence_over_legacy_files(self) -> None:
        self.write_legacy()
        write_renewal_credentials(
            self.tokens,
            email=EMAIL,
            uid=UID,
            session_token=SESSION_TOKEN,
        )

        self.assertEqual(load_renewal_credentials(self.tokens)["email"], EMAIL)
        self.assertEqual(load_renewal_credentials(self.tokens)["uid"], UID)
        self.assertEqual(
            load_renewal_credentials(self.tokens)["session_token"],
            SESSION_TOKEN,
        )

    def test_invalid_canonical_record_does_not_fall_back_to_legacy_files(self) -> None:
        self.write_legacy()
        canonical = self.tokens / "renewal_credentials.json"
        canonical.write_text("{not-json\n", encoding="utf-8")
        canonical.chmod(0o600)

        with self.assertRaisesRegex(RenewalCredentialsError, "not valid UTF-8 JSON"):
            load_renewal_credentials(self.tokens)

    def test_legacy_files_remain_readable_when_canonical_is_absent(self) -> None:
        self.write_legacy()

        self.assertEqual(
            load_renewal_credentials(self.tokens),
            {
                "email": "legacy@example.invalid",
                "uid": "legacy-account-uid",
                "session_token": "legacy-session-token",
            },
        )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is unavailable")
    def test_canonical_symlink_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "outside.json"
        target.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "email": EMAIL,
                    "uid": UID,
                    "session_token": SESSION_TOKEN,
                }
            ),
            encoding="utf-8",
        )
        target.chmod(0o600)
        (self.tokens / "renewal_credentials.json").symlink_to(target)

        with self.assertRaisesRegex(RenewalCredentialsError, "not a safe regular file"):
            load_renewal_credentials(self.tokens)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes are unavailable")
    def test_canonical_record_with_broad_permissions_is_rejected(self) -> None:
        path = write_renewal_credentials(
            self.tokens,
            email=EMAIL,
            uid=UID,
            session_token=SESSION_TOKEN,
        )
        path.chmod(0o644)

        with self.assertRaisesRegex(RenewalCredentialsError, "permissions must be 0600"):
            load_renewal_credentials(self.tokens)

    def test_failed_replace_preserves_the_previous_canonical_record(self) -> None:
        path = write_renewal_credentials(
            self.tokens,
            email=EMAIL,
            uid=UID,
            session_token=SESSION_TOKEN,
        )
        original = path.read_bytes()

        with patch.object(
            renewal_credentials.os,
            "replace",
            side_effect=OSError("synthetic replace failure"),
        ):
            with self.assertRaisesRegex(OSError, "synthetic replace failure"):
                write_renewal_credentials(
                    self.tokens,
                    email="replacement@example.invalid",
                    uid="f" * 32,
                    session_token="e" * 64,
                )

        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(load_renewal_credentials(self.tokens)["email"], EMAIL)
        self.assertEqual(list(self.tokens.glob(".renewal_credentials.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
