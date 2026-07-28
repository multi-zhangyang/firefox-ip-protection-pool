from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class RunServiceScriptTests(unittest.TestCase):
    def test_startup_refresh_uses_the_token_store_state_machine(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "run_service.sh"
            shutil.copy2(repository / "run_service.sh", script)
            invocation_log = root / "python-invocations.txt"
            fake_python = root / "fake-python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$IPP_TEST_LOG\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "IPP_PYTHON": str(fake_python),
                    "IPP_TEST_LOG": str(invocation_log),
                    "IPP_REFRESH_BEFORE_START": "1",
                }
            )

            completed = subprocess.run(
                [str(script)],
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            invocations = invocation_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(invocations[0], "ipp_pool.py token-refresh")
            self.assertTrue(invocations[1].startswith("ipp_pool.py run "))
            self.assertNotIn("refresh_tokens.py", "\n".join(invocations))


if __name__ == "__main__":
    unittest.main()
