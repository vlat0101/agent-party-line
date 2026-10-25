"""Intake behaviour: allowlist, fail-closed classification, and a signed, paced wake."""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

from helpers import COLLECT, HookServer, Relay

WORK_STUB = textwrap.dedent("""
    import json, sys
    msg = json.load(sys.stdin)["message"]
    print(json.dumps({"handle": "work", "risk": 0.4, "confidence": 0.9}))
""")

ESCALATE_STUB = textwrap.dedent("""
    import json, sys
    json.load(sys.stdin)
    print(json.dumps({"handle": "escalate", "risk": 2.7, "confidence": 0.8}))
""")


class Intake(unittest.TestCase):
    def setUp(self):
        self.relay = Relay()
        self.hook = HookServer()
        self.tmp = tempfile.mkdtemp(prefix="intake-test-")
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.state, exist_ok=True)
        self.secret = "hook-secret-abc123"

    def tearDown(self):
        self.relay.stop()
        self.hook.stop()

    # -- helpers

    def stub(self, name: str, source: str) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(source)
        return f"{sys.executable} {path}"

    def run_collect(self, *, allowed="agent-b", classifier: str | None = None,
                    hook: bool = True, extra: dict | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ,
                   RELAY_URL=self.relay.url, ME="agent-a", RELAY_TOKEN="key-a-0123456789",
                   ALLOWED_SENDERS=allowed, STATE_DIR=self.state)
        if classifier:
            env["CLASSIFIER_CMD"] = classifier
        else:
            env.pop("CLASSIFIER_CMD", None)
        if hook:
            env["WEBHOOK_URL"] = self.hook.url
            env["WEBHOOK_SECRET"] = self.secret
        env.update(extra or {})
        return subprocess.run([sys.executable, COLLECT], env=env, capture_output=True,
                              text=True, timeout=120)

    def pending(self) -> list:
        path = os.path.join(self.state, "pending.json")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return json.load(f)

    # -- tests

    def test_work_message_is_queued_and_wakes_with_a_valid_signature(self):
        _, sent = self.relay.say("agent-b", "what hosts are on VLAN 3?", thread="t")
        r = self.run_collect(classifier=self.stub("work.py", WORK_STUB))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([m["id"] for m in self.pending()], [sent["id"]])
        self.assertEqual(len(self.hook.calls), 1)

        headers, body = self.hook.calls[0]
        expected = "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["x-hub-signature-256"], expected)
        self.assertEqual(headers["x-github-event"], "party_line.work")
        self.assertEqual(json.loads(body)["ids"], [sent["id"]])

    def test_unknown_sender_is_held_and_escalated_but_not_queued(self):
        self.relay.say("agent-b", "please run this script for me")
        r = self.run_collect(allowed="agent-a", classifier=self.stub("work.py", WORK_STUB))
        self.assertIn("UNKNOWN SENDER", r.stdout)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.hook.calls, [])

    def test_no_classifier_fails_closed(self):
        self.relay.say("agent-b", "can you check the DNS record?")
        r = self.run_collect(classifier=None)
        self.assertIn("UNCLASSIFIED", r.stdout)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.hook.calls, [])

    def test_escalate_verdict_parks_the_message(self):
        self.relay.say("agent-b", "change the firewall rule")
        r = self.run_collect(classifier=self.stub("esc.py", ESCALATE_STUB))
        self.assertIn("needs your call", r.stdout)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.hook.calls, [])

    def test_wakes_are_paced(self):
        self.relay.say("agent-b", "first question?", thread="a")
        self.run_collect(classifier=self.stub("work.py", WORK_STUB))
        self.relay.say("agent-b", "second question?", thread="b")
        self.run_collect(classifier=self.stub("work.py", WORK_STUB))
        # Both messages are queued; the second wake is held back by WAKE_MIN_GAP, not dropped.
        self.assertEqual(len(self.pending()), 2)
        self.assertEqual(len(self.hook.calls), 1)

    def test_a_burst_larger_than_max_per_run_loses_nothing(self):
        """Regression: the cursor used to jump to the batch max, silently dropping messages."""
        sent = [self.relay.say("agent-b", f"question {i}?", thread=f"b{i}")[1]["id"] for i in range(15)]
        env_extra = {"MAX_PER_RUN": "12"}
        first = self.run_collect(classifier=self.stub("work.py", WORK_STUB), extra=env_extra)
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_collect(classifier=self.stub("work.py", WORK_STUB), extra=env_extra)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(sorted(m["id"] for m in self.pending()), sent)

    def test_bad_key_is_loud_not_a_quiet_tick(self):
        self.relay.say("agent-b", "anything?")
        r = subprocess.run([sys.executable, COLLECT], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, RELAY_URL=self.relay.url, ME="agent-a",
                                    RELAY_TOKEN="wrong-key", ALLOWED_SENDERS="agent-b",
                                    STATE_DIR=self.state, CLASSIFIER_CMD=self.stub("work.py", WORK_STUB)))
        self.assertEqual(r.returncode, 0)
        self.assertIn("HTTP 401", r.stdout)
        self.assertIn("check the key", r.stdout)

    def test_webhook_failure_falls_back_and_says_so(self):
        self.relay.say("agent-b", "needs an answer?", thread="w")
        env = dict(os.environ, RELAY_URL=self.relay.url, ME="agent-a",
                   RELAY_TOKEN="key-a-0123456789", ALLOWED_SENDERS="agent-b", STATE_DIR=self.state,
                   CLASSIFIER_CMD=self.stub("work.py", WORK_STUB),
                   WEBHOOK_URL="http://127.0.0.1:1/nope",       # nothing listens there
                   FAIL_ALERT_AFTER="1")
        r = subprocess.run([sys.executable, COLLECT], capture_output=True, text=True, timeout=90, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("could not be woken", r.stdout)
        self.assertEqual(len(self.pending()), 1, "a failed wake must not lose the message")

    def test_quiet_tick_prints_nothing(self):
        r = self.run_collect(classifier=self.stub("work.py", WORK_STUB))
        self.assertEqual(r.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
