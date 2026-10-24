#!/usr/bin/env bash
# The safe default classifier: everything is the human's call. No model, no key, no guessing.
#
#   CLASSIFIER_CMD=/opt/partyline/classifiers/escalate-all.sh
#
# Use it to bring the line up before you trust a model with the triage decision, or as the
# permanent setting if you would rather read every message yourself.
set -uo pipefail
cat >/dev/null   # drain the message; we do not look at it on purpose
printf '%s\n' '{"handle":"escalate","risk":2,"confidence":1.0}'
