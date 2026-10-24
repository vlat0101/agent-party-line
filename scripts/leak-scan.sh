#!/usr/bin/env bash
# Refuse to publish anything that carries a private detail from wherever this code came from.
# Run in CI on every push, and locally before the first push to a public remote.
#
# Add your own markers to the PATTERNS list — the point is that this file is edited by you,
# not that the defaults are complete.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

PATTERNS=(
  '100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'   # CGNAT / typical tailnet range
  '192\.168\.[0-9]+\.[0-9]+'                          # RFC1918
  '\b10\.[0-9]+\.[0-9]+\.[0-9]+'                      # RFC1918
  '\.ts\.net'                                         # tailnet MagicDNS suffix
  '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'    # any email address
  '/root/\.hermes'                                    # one specific home layout
  '/workspace/'                                       # one specific deployment path
  '\b[0-9a-f]{64}\b'                                  # raw fingerprints / keys
  '\b[0-9]{17,19}\b'                                  # chat platform ids (Discord/Slack snowflakes)
  'BEGIN [A-Z ]*PRIVATE KEY'                          # private keys
  'AKIA[0-9A-Z]{16}'                                  # AWS access key id
  'ghp_[A-Za-z0-9]{20,}'                              # GitHub token
  'xox[baprs]-'                                       # Slack token
)

# Names of the people and boxes this was extracted from. Edit to match your own estate.
NAMES='(vlat|Vlat|infra-grokbot|rex-chuckwalla)'

# Strings that are public ON PURPOSE and must not fail the scan: this file, documented
# placeholders, and the GitHub handle the project is published under.
ALLOW=('leak-scan.sh' 'NAMES=' 'PATTERNS=' 'example.com' 'vlat0101/' 'REPLACE-' 'one specific deployment path')

allowed() {  # allowed <line>; true when the line is a known-public literal
  local line="$1" a
  for a in "${ALLOW[@]}"; do
    case "$line" in *"$a"*) return 0 ;; esac
  done
  return 1
}

hits=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.png|*.jpg|*.gif|*.pdf|./.git/*) continue ;;
  esac
  for p in "${PATTERNS[@]}"; do
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      allowed "$hit" && continue
      echo "LEAK  $file: $hit   (pattern: $p)"
      hits=$((hits + 1))
    done < <(grep -nEI -- "$p" "$file" 2>/dev/null)
  done
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    allowed "$hit" && continue
    echo "NAME  $file: $hit   (pattern: $NAMES)"
    hits=$((hits + 1))
  done < <(grep -nE -- "$NAMES" "$file" 2>/dev/null)
done < <(find . -type f -not -path './.git/*' -print0)

if [ "$hits" -gt 0 ]; then
  echo
  echo "refusing: $hits hit(s). Fix them, or narrow a pattern if the hit is genuinely generic."
  exit 1
fi

echo "leak scan clean"
