"""Shared test fixtures: run the relay on a free local port, and a fake webhook receiver."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELAY = os.path.join(ROOT, "relay", "partyline.py")
COLLECT = os.path.join(ROOT, "intake", "collect.py")

KEYS = {"agent-a": "key-a-0123456789", "agent-b": "key-b-0123456789"}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Relay:
    """A relay process on 127.0.0.1:<free port> with a throwaway state dir."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="partyline-test-")
        self.port = free_port()
        self.keys = os.path.join(self.tmp, "keys.json")
        with open(self.keys, "w") as f:
            json.dump(KEYS, f)
        env = dict(os.environ, PARTYLINE_BIND="127.0.0.1", PARTYLINE_PORT=str(self.port),
                   PARTYLINE_STATE=os.path.join(self.tmp, "state"), PARTYLINE_KEYS=self.keys)
        self.proc = subprocess.Popen([sys.executable, RELAY], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._await_up()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _await_up(self, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.get("/health", "agent-a")
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("relay did not start")

    def get(self, path: str, sender: str) -> dict:
        req = urllib.request.Request(self.url + path)
        req.add_header("Authorization", f"Bearer {KEYS[sender]}")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())

    def say(self, sender: str, text: str, thread: str = "", claimed: str = "") -> tuple[int, dict]:
        body = json.dumps({"text": text, "thread": thread, **({"from": claimed} if claimed else {})}).encode()
        req = urllib.request.Request(self.url + "/say", data=body, method="POST")
        req.add_header("Authorization", f"Bearer {KEYS[sender]}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class HookServer:
    """Accepts webhook POSTs and records (headers, body)."""

    def __init__(self):
        self.port = free_port()
        self.calls: list[tuple[dict, bytes]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                outer.calls.append(({k.lower(): v for k, v in self.headers.items()},
                                    self.rfile.read(n)))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):  # silence
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def stop(self) -> None:
        self.srv.shutdown()
