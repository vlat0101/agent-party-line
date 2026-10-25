#!/usr/bin/env python3
"""Party line intake — poll a message relay, classify, and wake an agent only when it matters.

Runs as a cheap, token-free `no_agent` cron job (every minute is the sane cadence). The poller
never reasons; the wake is what costs a model call, and it only fires when a message needs one.

Per tick:
  1. GET /since?id=<cursor> under a flock, so a slow tick cannot overlap the next one.
  2. Ignore our own messages. Hold anything from a sender that is not on the allowlist: reply that it
     was held and escalate to the human. The relay derives `from` from the sender's key, so it cannot
     be spoofed — but a key issued tomorrow is not implicitly trusted, and only the human adds one.
  3. Classify each remaining message with one call to CLASSIFIER_CMD. No classifier configured, or a
     classifier that fails, means ESCALATE. Failing closed is the whole point: an unclassified message
     must never be acted on.
  4. escalate / risk >= RISK_THRESHOLD -> print an escalation (the cron delivery is the alert), reply
     that it is parked, and change nothing. Short risk-free text with no question is chatter: dropped.
  5. work -> append to the pending queue, then wake the agent with a signed webhook POST, paced.

Output contract: empty stdout on a quiet tick (no delivery). Exit status is 0 for every outcome that a
cron job should not treat as a crash — including relay and webhook failures, which are reported on stdout.
The single exception is a missing ME, which is a configuration error and exits 2.

Everything estate-specific lives in the environment; see config.env.example.
"""
import fcntl
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

RELAY_URL = os.environ.get("RELAY_URL", "http://127.0.0.1:8650").rstrip("/")
ME = os.environ.get("ME", "")
TOKEN_FILE = os.environ.get("TOKEN_FILE", "")
RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "")
ALLOWED_SENDERS = {s.strip() for s in os.environ.get("ALLOWED_SENDERS", "").split(",") if s.strip()}
STATE_DIR = os.environ.get("STATE_DIR", "./state")

CURSOR_FILE = os.path.join(STATE_DIR, "cursor")
PENDING_FILE = os.path.join(STATE_DIR, "pending.json")
LOCK_FILE = os.path.join(STATE_DIR, "intake.lock")
LOG_FILE = os.path.join(STATE_DIR, "intake.log")
WAKE_FILE = os.path.join(STATE_DIR, "wakes")
WEBHOOK_FAIL_FILE = os.path.join(STATE_DIR, "webhook-fails")

CLASSIFIER_CMD = os.environ.get("CLASSIFIER_CMD", "")
RISK_THRESHOLD = float(os.environ.get("RISK_THRESHOLD", "2.5"))
CLASSIFIER_TIMEOUT = int(os.environ.get("CLASSIFIER_TIMEOUT", "90"))

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_SECRET_FILE = os.environ.get("WEBHOOK_SECRET_FILE", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_EVENT = os.environ.get("WEBHOOK_EVENT", "party_line.work")
WAKE_FALLBACK_CMD = os.environ.get("WAKE_FALLBACK_CMD", "")
WAKE_MIN_GAP = int(os.environ.get("WAKE_MIN_GAP", "45"))
WAKE_MAX_PER_HOUR = int(os.environ.get("WAKE_MAX_PER_HOUR", "6"))

MAX_PER_RUN = int(os.environ.get("MAX_PER_RUN", "12"))
FAIL_ALERT_AFTER = int(os.environ.get("FAIL_ALERT_AFTER", "3"))
# Chat with an untrusted peer keeps its replies short; long prose is where prompt-shaped text hides.
MAX_TEXT = int(os.environ.get("MAX_TEXT", "6000"))


def log(msg: str) -> None:
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {msg}\n")
    except OSError:
        pass


def token() -> str:
    if RELAY_TOKEN:
        return RELAY_TOKEN
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def api(path: str, payload: dict | None = None, timeout: int = 20) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{RELAY_URL}{path}", data=data,
                                 method="POST" if data else "GET")
    req.add_header("Authorization", f"Bearer {token()}")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------- classification

def classify(msg: dict) -> dict | None:
    """One classifier call. None means "not classified" and must be treated as escalate.

    Contract: JSON message on stdin, JSON verdict on stdout:
        {"handle": "work" | "escalate", "risk": 0..3, "confidence": 0..1}
    """
    if not CLASSIFIER_CMD:
        return None
    payload = json.dumps({"message": {
        "from": msg.get("from"), "thread": msg.get("thread"),
        "text": (msg.get("text") or "")[:MAX_TEXT]}})
    for attempt in range(3):
        try:
            r = subprocess.run(shlex.split(CLASSIFIER_CMD), input=payload, capture_output=True,
                               text=True, timeout=CLASSIFIER_TIMEOUT)
            out = json.loads(r.stdout or "{}")
            handle = str(out.get("handle") or "").lower()
            if handle not in ("work", "escalate"):
                log(f"classifier returned no usable handle: {r.stdout[:200]}")
                return None
            return {"handle": handle, "risk": float(out.get("risk") or 0),
                    "conf": float(out.get("confidence") or 0)}
        except (subprocess.SubprocessError, ValueError, OSError) as exc:
            log(f"classifier attempt {attempt + 1} failed: {exc}")
            time.sleep(1 + 2 * attempt)
    return None


# ---------------------------------------------------------------- queue + wake

def queue_for_agent(items: list[dict]) -> None:
    existing: list[dict] = []
    try:
        with open(PENDING_FILE) as f:
            existing = json.load(f)
    except (OSError, ValueError):
        pass
    seen = {m.get("id") for m in existing}
    existing.extend(m for m in items if m.get("id") not in seen)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(PENDING_FILE, "w") as f:
        json.dump(existing, f, indent=1)


def secret() -> str:
    if WEBHOOK_SECRET:
        return WEBHOOK_SECRET
    try:
        with open(WEBHOOK_SECRET_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def post_wake(count: int, ids: list[int]) -> bool:
    """Signed HMAC POST — this is the whole doorbell. The payload carries references, not orders."""
    if not WEBHOOK_URL:
        return False
    body = json.dumps({"event": WEBHOOK_EVENT, "count": count, "ids": ids}).encode()
    req = urllib.request.Request(WEBHOOK_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-GitHub-Event", WEBHOOK_EVENT)
    s = secret()
    if s:
        digest = hmac.new(s.encode(), body, hashlib.sha256).hexdigest()
        req.add_header("X-Hub-Signature-256", f"sha256={digest}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"webhook wake failed: {exc}")
        return False


def fallback_wake() -> bool:
    if not WAKE_FALLBACK_CMD:
        return False
    try:
        subprocess.Popen(shlex.split(WAKE_FALLBACK_CMD), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, close_fds=True)
        log("fallback wake dispatched")
        return True
    except (subprocess.SubprocessError, OSError) as exc:
        log(f"fallback wake failed: {exc}")
        return False


def recent_wakes(now: float) -> list[float]:
    try:
        with open(WAKE_FILE) as f:
            stamps = [float(x) for x in f.read().split()]
    except (OSError, ValueError):
        stamps = []
    return [t for t in stamps if now - t < 3600]


def wake_agent(items: list[dict]) -> str:
    """Wake the agent, paced. Returns webhook | fallback | paced | failed."""
    now = time.time()
    stamps = recent_wakes(now)
    if stamps and now - max(stamps) < WAKE_MIN_GAP:
        log(f"wake paced: last wake {int(now - max(stamps))}s ago")
        return "paced"
    if len(stamps) >= WAKE_MAX_PER_HOUR:
        log(f"wake cap: {len(stamps)} wakes in the last hour")
        return "paced"

    ids = [m.get("id") for m in items]
    if post_wake(len(items), ids):
        with open(WAKE_FILE, "w") as f:
            f.write(" ".join(f"{t:.0f}" for t in stamps + [now]))
        try:
            with open(WEBHOOK_FAIL_FILE, "w") as f:
                f.write("0")
        except OSError:
            pass
        return "webhook"

    fails = 0
    try:
        with open(WEBHOOK_FAIL_FILE) as f:
            fails = int(f.read().strip() or 0) + 1
    except (OSError, ValueError):
        fails = 1
    with open(WEBHOOK_FAIL_FILE, "w") as f:
        f.write(str(fails))

    if fallback_wake():
        with open(WAKE_FILE, "w") as f:
            f.write(" ".join(f"{t:.0f}" for t in stamps + [now]))
        return "fallback"
    return "failed"


# ---------------------------------------------------------------- cursor + main

def read_cursor() -> int:
    try:
        with open(CURSOR_FILE) as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def write_cursor(n: int) -> None:
    with open(CURSOR_FILE, "w") as f:
        f.write(str(n))


def main() -> int:
    if not ME:
        print("ME is not set", file=sys.stderr)
        return 2
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)

    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0  # a previous tick is still running

    cursor = read_cursor()
    try:
        data = api(f"/since?id={cursor}", timeout=20)
    except urllib.error.HTTPError as exc:
        # 401/403/429 are configuration problems, not a quiet line. Say so out loud or the
        # messages pile up on the relay while every tick looks like nothing happened.
        body = ""
        try:
            body = exc.read().decode(errors="replace")[:200]
        except Exception:  # noqa: BLE001 - best effort only
            pass
        log(f"relay returned {exc.code}: {body}")
        hint = ("check the key in TOKEN_FILE" if exc.code in (401, 403)
                else "relay is rate limiting or unavailable" if exc.code == 429
                else "relay rejected the request")
        print(f"⚠️ party line intake: relay answered HTTP {exc.code} at {RELAY_URL} — {hint}\n"
              f"{body}\nNothing was read this tick; messages stay on the relay.")
        return 0
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"relay unreachable: {exc}")
        print(f"⚠️ party line intake: relay unreachable at {RELAY_URL} — {exc}\n"
              f"Nothing was read this tick; messages stay on the relay.")
        return 0

    all_msgs = data.get("messages", [])
    msgs = [m for m in all_msgs if m.get("from") != ME]
    top = max([m.get("id", 0) for m in all_msgs] or [cursor])
    if not msgs:
        write_cursor(top)
        return 0

    # The cursor may only advance past messages actually handled this tick. Advancing it to the
    # highest id in the batch would silently skip everything past MAX_PER_RUN, and the relay does
    # not replay: that traffic is gone, unclassified and unalerted.
    batch = msgs[:MAX_PER_RUN]
    last_id = batch[-1].get("id", cursor)

    escalations: list[str] = []
    work: list[dict] = []

    for m in batch:
        text = (m.get("text") or "")[:MAX_TEXT]
        sender = str(m.get("from") or "?")

        if sender not in ALLOWED_SENDERS:
            escalations.append(
                f"peer → {ME} · UNKNOWN SENDER (not on the allowlist)\n"
                f"thread {m.get('thread')} · id {m.get('id')}\n{text[:500]}\n"
                f"Nothing was done, nothing was queued. Add the sender to ALLOWED_SENDERS to let it "
                f"reach the agent.")
            continue

        verdict = classify(m)
        if verdict is None:
            escalations.append(
                f"peer → {ME} · UNCLASSIFIED (no classifier, or it failed — failed closed)\n"
                f"thread {m.get('thread')} · id {m.get('id')}\n{text[:500]}\n"
                f"Nothing was done. Parked for you.")
            continue

        log(f"id={m.get('id')} handle={verdict['handle']} risk={verdict['risk']:.2f} "
            f"conf={verdict['conf']:.2f}")

        if verdict["handle"] == "escalate" or verdict["risk"] >= RISK_THRESHOLD:
            escalations.append(
                f"peer → {ME} · needs your call · risk {verdict['risk']:.2f}\n"
                f"thread {m.get('thread')} · id {m.get('id')}\n{text[:700]}\n"
                f"Nothing was done. Parked on the line for you.")
        elif verdict["risk"] == 0 and "?" not in text and len(text) < 200:
            log(f"id={m.get('id')} chatter dropped")
        else:
            work.append(m)

    if work:
        queue_for_agent(work)
        how = wake_agent(work)
        log(f"queued {len(work)} · wake={how}")
        if how == "failed":
            escalations.append(
                f"⚠️ {len(work)} work message(s) queued but the agent could not be woken "
                f"(webhook and fallback both failed). They stay in {PENDING_FILE} for the next tick.")
        elif how in ("webhook", "paced"):
            fails = 0
            try:
                with open(WEBHOOK_FAIL_FILE) as f:
                    fails = int(f.read().strip() or 0)
            except (OSError, ValueError):
                pass
            # The fallback is still delivering, so this is a health signal, not a silence: say it
            # once at the threshold rather than every tick for hours.
            if fails == FAIL_ALERT_AFTER and how == "webhook":
                escalations.append(
                    f"⚠️ webhook wake has failed {fails} times recently and the fallback was used; "
                    f"check the receiver before it is the only thing waking the agent.")

    write_cursor(last_id if last_id else top)
    if escalations:
        print("\n\n".join(escalations))
    return 0


if __name__ == "__main__":
    sys.exit(main())
