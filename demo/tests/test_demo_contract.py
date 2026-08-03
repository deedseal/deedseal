# SPDX-License-Identifier: CC-BY-4.0
"""Contract tests for the demonstration target.

The seed ships with one passing test. A supervised run extends this file
in exactly the bounded way its signed work grant authorizes, and the run
passport binds the resulting bytes.
"""

import unittest


class DemoContractTests(unittest.TestCase):
    def test_seed_is_present(self):
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
