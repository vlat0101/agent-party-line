"""Relay behaviour that the design depends on. If one of these fails, the trust boundary is broken."""

import unittest

from helpers import KEYS as _KEYS
from helpers import Relay


class RelayAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.relay = Relay()

    @classmethod
    def tearDownClass(cls):
        cls.relay.stop()

    def test_health_needs_a_key(self):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(self.relay.url + "/health")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 401)

    def test_health_counts_senders(self):
        self.relay.say("agent-a", "hello")
        body = self.relay.get("/health", "agent-a")
        self.assertTrue(body["ok"])
        self.assertIn("agent-a", body["senders"])

    def test_identity_comes_from_the_key_not_the_payload(self):
        code, body = self.relay.say("agent-a", "I am definitely agent-b", claimed="agent-b")
        self.assertEqual(code, 403)
        self.assertEqual(body["you_are"], "agent-a")

    def test_say_then_since(self):
        code, sent = self.relay.say("agent-a", "line one", thread="t-1")
        self.assertEqual(code, 200)
        got = self.relay.get(f"/since?id={sent['id'] - 1}", "agent-b")
        self.assertTrue(any(m["id"] == sent["id"] for m in got["messages"]))

    def test_bad_id_is_a_400_not_a_500(self):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(self.relay.url + "/since?id=notanumber")
        req.add_header("Authorization", f"Bearer {_KEYS['agent-a']}")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_empty_text_is_rejected(self):
        code, _ = self.relay.say("agent-a", "   ")
        self.assertEqual(code, 400)


class RelayBrakes(unittest.TestCase):
    def setUp(self):
        self.relay = Relay()

    def tearDown(self):
        self.relay.stop()

    def test_thread_brake_stops_a_runaway_conversation(self):
        thread = "runaway"
        codes = [self.relay.say("agent-a", f"message {i}", thread=thread)[0] for i in range(8)]
        self.assertEqual(codes, [200] * 8)
        code, body = self.relay.say("agent-a", "one too many", thread=thread)
        self.assertEqual(code, 429)
        self.assertIn("escalate to the human", body["error"])

    def test_brake_applies_to_both_sides(self):
        thread = "shared"
        for i in range(8):
            self.relay.say("agent-a" if i % 2 else "agent-b", f"m{i}", thread=thread)
        # The side that was mid-reply is refused too — a missing answer may be the brake.
        code, _ = self.relay.say("agent-b", "reply", thread=thread)
        self.assertEqual(code, 429)


if __name__ == "__main__":
    unittest.main()
