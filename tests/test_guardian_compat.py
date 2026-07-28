from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import refresh_tokens


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


if __name__ == "__main__":
    unittest.main()
