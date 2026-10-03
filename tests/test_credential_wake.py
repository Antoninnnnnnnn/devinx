"""A turn held because every credential is blocked resumes as soon as one is
usable again, including one logged in while it waited."""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import devinx  # noqa: E402


class CredentialWakeTests(unittest.TestCase):
    def setUp(self):
        self.a = {"name": "a", "key": "ka", "blocked_until": time.time() + 3600}
        for p in (mock.patch.object(devinx, "_accounts", [self.a]),
                  mock.patch.object(devinx, "_maybe_rescan", lambda: None)):
            p.start()
            self.addCleanup(p.stop)

    def test_no_wake_while_every_credential_is_blocked(self):
        self.assertFalse(devinx._credential_back())

    def test_a_new_login_wakes_the_held_turn(self):
        def rescan():
            devinx._accounts.append({"name": "b", "key": "kb", "blocked_until": 0.0})
        with mock.patch.object(devinx, "_maybe_rescan", rescan):
            turn = devinx.Turn(budget=60)
            t0 = time.time()
            turn.sleep(30, wake=devinx._credential_back)
            self.assertLess(time.time() - t0, 2)

    def test_an_excluded_login_does_not_wake_it(self):
        devinx._accounts.append({"name": "f", "key": "kf", "blocked_until": 0.0,
                                 "excluded": "plan gratuit"})
        self.assertFalse(devinx._credential_back())

    def test_sleep_without_wake_is_unchanged(self):
        turn = devinx.Turn(budget=60)
        t0 = time.time()
        turn.sleep(0.6)
        self.assertGreaterEqual(time.time() - t0, 0.5)


if __name__ == "__main__":
    unittest.main()
