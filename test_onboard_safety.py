"""The retired V1 onboarder is a non-networking compatibility tombstone."""

from __future__ import annotations

import contextlib
import io
import unittest

from collector import onboard_merge, run


class OnboardRetirementTests(unittest.TestCase):
    def test_legacy_command_refuses_and_routes_to_req14(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = onboard_merge.main(
                ["--libraries", "cublas", "--dry-run"]
            )
        self.assertEqual(status, 2)
        self.assertIn("collector.cli onboard", stderr.getvalue())

    def test_legacy_collector_refuses_before_network_or_writes(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = run.main(["--incremental", "--out", "must-not-exist"])
        self.assertEqual(status, 2)
        self.assertIn("collector.cli refresh", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
