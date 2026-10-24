#!/usr/bin/env python3
"""Party line — minimal bidirectional message relay for agent-to-agent chat.

Design constraints:
  * either agent may be outbound-only or not-always-awake -> a shared log beats webhooks
  * readers poll -> /since returns immediately, long-poll is optional
  * messages from another agent are UNTRUSTED INPUT (same class as a fetched web page).
    This service stores and forwards text. It never executes anything.

Endpoints (all require Authorization: Bearer <token>):
  GET  /health                        -> {"ok":true,"messages":N,"senders":{...}}
  POST /say   {"from","text","thread"}-> {"id":N,"thread":"..."}
  GET  /since?id=N&for=NAME&wait=SEC  -> {"messages":[...],"next":M}

Bind: tailscale0 address only (never 0.0.0.0). LAN exposure is a bug.
"""
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STATE_DIR = os.environ.get("PARTYLINE_STATE", "./state")
STORE = os.path.join(STATE_DIR, "partyline.jsonl")
LOG = os.path.join(STATE_DIR, "partyline.log")
KEYS_FILE = os.environ.get("PARTYLINE_KEYS", "./secrets/partyline.keys.json")

# Bind to the private interface only — never 0.0.0.0. LAN exposure is a bug.
BIND_IP = os.environ.get("PARTYLINE_BIND", "127.0.0.1")
PORT = int(os.environ.get("PARTYLINE_PORT", "8650"))

MAXLEN = int(os.environ.get("PARTYLINE_MAXLEN", "8000"))        # per message
MAX_THREAD = int(os.environ.get("PARTYLINE_MAX_THREAD", "8"))   # exchanges, then escalate to the human
RATE_PER_MIN = int(os.environ.get("PARTYLINE_RATE_PER_MIN", "30"))  # per sender
MAX_WAIT = int(os.environ.get("PARTYLINE_MAX_WAIT", "25"))      # long-poll ceiling

_lock = threading.Lock()
_rate: dict[str, list[float]] = {}


def log(msg: str) -> None:
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {msg}\n")
    except OSError:
        pass


def keys() -> dict:
    """{"sender": "<secret>"} — re-read per request so rotation needs no restart."""
    with open(KEYS_FILE) as f:
        return json.load(f)


def identify(presented: str) -> str | None:
    """A sender's identity comes from the CREDENTIAL, never from the payload.

    Each side holds only its own key, so neither can send a message that appears
    to come from the other. Constant-time compare against every key.
    """
    if not presented:
        return None
    for sender, key in keys().items():
        if secrets.compare_digest(presented, str(key)):
            return sender
    return None


def read_msgs() -> list[dict]:
    out: list[dict] = []
    try:
        with open(STORE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return out


def append_msg(rec: dict) -> int:
    with _lock:
        msgs = read_msgs()
        rec["id"] = (msgs[-1]["id"] + 1) if msgs else 1
        rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(STORE, "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec["id"]


def rate_ok(sender: str) -> bool:
    now = time.time()
    window = [t for t in _rate.get(sender, []) if now - t < 60]
    if len(window) >= RATE_PER_MIN:
        _rate[sender] = window
        return False
    window.append(now)
    _rate[sender] = window
    return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "partylline/1"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _identity(self) -> str | None:
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return None
        return identify(hdr[7:].strip())

    def do_GET(self) -> None:
        who = self._identity()
        if who is None:
            self._send(401, {"error": "unauthorised"})
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            msgs = read_msgs()
            senders: dict[str, int] = {}
            for m in msgs:
                senders[m.get("from", "?")] = senders.get(m.get("from", "?"), 0) + 1
            self._send(200, {"ok": True, "messages": len(msgs), "senders": senders,
                             "bind": f"{BIND_IP}:{PORT}"})
            return
        if u.path == "/since":
            since = int((q.get("id") or ["0"])[0])
            wait = min(int((q.get("wait") or ["0"])[0]), MAX_WAIT)
            deadline = time.time() + wait
            while True:
                msgs = [m for m in read_msgs() if m["id"] > since]
                if msgs or time.time() >= deadline:
                    break
                time.sleep(0.5)
            self._send(200, {"messages": msgs,
                             "next": msgs[-1]["id"] if msgs else since})
            return
        self._send(404, {"error": "no such route"})

    def do_POST(self) -> None:
        who = self._identity()
        if who is None:
            self._send(401, {"error": "unauthorised"})
            return
        if urlparse(self.path).path != "/say":
            self._send(404, {"error": "no such route"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "bad json"})
            return

        claimed = str(body.get("from") or "").strip()[:32]
        text = str(body.get("text") or "").strip()
        thread = str(body.get("thread") or "").strip()[:64]

        # The credential is the identity. A payload may repeat it, never contradict it.
        if claimed and claimed != who:
            log(f"IDENTITY MISMATCH: key={who} claimed={claimed} refused")
            self._send(403, {"error": "identity mismatch — the credential decides who you are",
                             "you_are": who})
            return
        sender = who

        if not sender or not text:
            self._send(400, {"error": "'from' and 'text' are required"})
            return
        if len(text) > MAXLEN:
            self._send(413, {"error": f"message over {MAXLEN} chars", "len": len(text)})
            return
        if not rate_ok(sender):
            self._send(429, {"error": f"rate limit {RATE_PER_MIN}/min for {sender}"})
            return

        if thread:
            prior = [m for m in read_msgs() if m.get("thread") == thread]
            if len(prior) >= MAX_THREAD:
                log(f"THREAD BRAKE {thread} ({len(prior)} messages) - escalate to the human")
                self._send(429, {"error": "thread limit reached - escalate to the human",
                                 "thread": thread, "messages": len(prior)})
                return
        else:
            thread = f"t{int(time.time())}-{secrets.token_hex(2)}"

        mid = append_msg({"from": sender, "text": text, "thread": thread})
        log(f"say id={mid} from={sender} thread={thread} len={len(text)}")
        self._send(200, {"id": mid, "thread": thread})

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - signature from base class
        log("http " + format % args)


def main() -> None:
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    log(f"partyline starting on {BIND_IP}:{PORT}")
    srv = ThreadingHTTPServer((BIND_IP, PORT), Handler)
    srv.daemon_threads = True
    log("partyline ready")
    srv.serve_forever()


if __name__ == "__main__":
    main()
