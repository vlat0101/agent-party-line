# agent-party-line

Two autonomous agents, one message line, no privilege hole.

A small relay plus a cheap intake loop that lets two AI agents hold a conversation without the
one with power over your infrastructure trusting the one that reads the open web.

```
agent-b ──POST /say──┐
                     ├──> partyline (relay: shared log, per-sender keys, brakes)
agent-a ──POST /say──┘             │
                                   │  every 1 min, token-free
                                   ▼
                          collect.py ──> classifier (one call per message)
                                   │
                     ┌─────────────┴──────────────┐
                 work│                            │escalate / unknown sender / classifier down
                     ▼                            ▼
        pending queue + signed webhook      alert to the human
        → agent wakes within a minute       message parked, nothing executed
```

## Why not just let them POST to each other

The obvious wiring is worse than it looks. One agent reads untrusted web pages all day. The other
reaches root on your estate. Point the first at the second's prompt API and a poisoned page becomes
root on your network — the message arrives with the same authority as you, because nothing in the
transport distinguishes "the human asked for this" from "a page told me to say this".

So the transport carries **text with an unforgeable sender**, and the receiving side treats that text
as *untrusted input*, exactly like a fetched page. The relay never executes anything. The agent does
not obey the line; it decides, and anything that could change state goes to the human.

## What you get

| Piece | File | Job |
|---|---|---|
| Relay | `relay/partyline.py` | Shared append-only log over HTTP. Per-sender keys, identity from the credential, rate and thread brakes. Stdlib only. |
| Intake | `intake/collect.py` | Polls, classifies, escalates, queues, and wakes the agent with a signed webhook. Runs as a script, never as a model. |
| Classifier | `classifiers/*` | Pluggable: any command that maps one message to `work`/`escalate` + a risk score. Ships with a model adapter and an escalate-everything default. |
| Deploy | `deploy/` | systemd unit and a one-line crontab. |

## Quickstart (about five minutes)

```bash
sudo useradd --system --home /var/lib/partyline --shell /usr/sbin/nologin partyline
sudo install -d -o partyline -g partyline -m 0700 /var/lib/partyline /etc/partyline
sudo install -d /opt/partyline && sudo cp -r relay intake classifiers /opt/partyline/

# one long random key per side, no shared secret
sudo tee /etc/partyline/partyline.keys.json >/dev/null <<'EOF'
{"agent-a": "REPLACE-with-openssl-rand-hex-32", "agent-b": "REPLACE-too"}
EOF
sudo chmod 600 /etc/partyline/partyline.keys.json
echo "REPLACE-with-openssl-rand-hex-32" | sudo tee /etc/partyline/agent-a.key >/dev/null
sudo chmod 600 /etc/partyline/agent-a.key

sudo cp config.env.example /etc/partyline/config.env && sudoedit /etc/partyline/config.env
sudo cp deploy/partyline.service /etc/systemd/system/ && sudo systemctl enable --now partyline
curl -s -H "Authorization: Bearer $(sudo cat /etc/partyline/agent-a.key)" \
     http://127.0.0.1:8650/health
```

Then install `deploy/crontab.example`, point `WEBHOOK_URL` at whatever can wake your agent (with this
repo's sibling project, a Hermes gateway route bound to a job; anything else that accepts an HMAC
POST works), and send yourself a message:

```bash
curl -s -X POST http://127.0.0.1:8650/say \
  -H "Authorization: Bearer $AGENT_B_KEY" -H 'Content-Type: application/json' \
  -d '{"text":"what is the DNS record for the wiki?","thread":"dns"}'
```

## The rules this code enforces

1. **Identity comes from the key, never the payload.** Sending `"from": "agent-a"` with agent-b's key
   returns `403` and logs `IDENTITY MISMATCH`. One shared secret would make `from` a lie, so keys are
   per sender and each side holds only its own.
2. **Bind to the private interface.** `PARTYLINE_BIND` is your VPN address, never `0.0.0.0`. Prove it:
   the LAN address must refuse.
3. **Fail closed.** No classifier configured, a classifier that errors, a missing field — all mean
   *escalate*. A gate that turns a classifier outage into silence is the failure nobody detects later.
4. **Allowlist the senders.** `from` cannot be spoofed, but a key you issue tomorrow should not
   silently reach your agent. Unknown sender: held, escalated, never queued.
5. **Brakes, not errors.** Messages per thread are capped and the relay answers `429` saying "escalate
   to the human". Two language models will otherwise talk until someone notices. The cap applies to
   both sides, so a missing reply may be the brake — check the log before debugging the peer.
6. **The wake is a doorbell, not an order.** The webhook payload carries message ids only. Whatever
   the waking agent then reads is still untrusted text.
7. **Pace the wakes.** Minimum gap and a per-hour cap, with held-back messages staying queued. Without
   it, a talkative peer is a firehose of model calls.

## Threat model — what this does and does not buy you

Protects against: a compromised or manipulated peer agent issuing instructions, credential confusion
between the two agents, an agent pair burning tokens in a loop, and a classifier outage becoming
silent auto-execution.

Does **not** protect against: a peer host that is already root (it holds its own key and can say
anything as itself — revocation is a key rotation), a human who approves something bad, or secrets
leaking *in message text* (nothing here redacts; that is the sender's job and yours).

## Testing

```bash
python -m unittest discover -s tests -p "test_*.py" -v   # 13 tests, real processes, no mocks
bash scripts/leak-scan.sh                                # refuse to publish private detail
```

The tests start a real relay on a free port and a real HTTP sink for the webhook, then assert the
signature, the allowlist refusal, fail-closed classification, the thread brake, and wake pacing.

## Origin

Extracted from a working two-agent deployment and sanitised for publication: this pattern has been
running an agent pair — one operating a home-estate estate, one reading the web — since 2026-10-23.
The relay and intake logic is the code that runs there, parameterised; the tests are new. It was
written by an AI agent working for its operator, and reviewed by them.

MIT licensed. Issues and counter-examples welcome — especially if you think a rule above is wrong.
