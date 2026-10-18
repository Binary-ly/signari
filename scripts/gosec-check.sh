#!/usr/bin/env bash
# Run gosec and compare its findings with engine/gosec-baseline.txt.
#
# Fails when any (rule, file) pair has more findings than the baseline allows,
# or appears with no baseline line at all. A count that has gone DOWN is
# reported so the baseline can be lowered in the same change.
#
# Usage: scripts/gosec-check.sh            (from the repository root)
# Needs: gosec on PATH (or GOSEC=/path/to/gosec), jq.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
gosec="${GOSEC:-gosec}"
baseline="$root/engine/gosec-baseline.txt"
report="$(mktemp)"
trap 'rm -f "$report"' EXIT

cd "$root/engine"
# gosec exits non-zero whenever it finds anything; the comparison below is the
# verdict, so its exit status is not.
"$gosec" -exclude=G101 -fmt=json -out="$report" -quiet ./... || true
if ! jq -e '.Issues' "$report" >/dev/null 2>&1; then
    echo "gosec produced no report: it did not run, which is not the same as passing" >&2
    exit 2
fi

current="$(jq -r '.Issues[] | "\(.rule_id) \(.file | sub(".*/engine/"; ""))"' "$report" | sort | uniq -c | awk '{print $2, $3, $1}')"
allowed="$(grep -vE '^\s*(#|$)' "$baseline" | awk '{print $1, $2, $3}')"

status=0
while read -r rule file count; do
    [ -z "$rule" ] && continue
    limit="$(awk -v r="$rule" -v f="$file" '$1==r && $2==f {print $3}' <<<"$allowed")"
    if [ -z "$limit" ]; then
        echo "NEW  $rule $file: $count finding(s) with no baseline line -- review it (docs/security-scanning.md)" >&2
        status=1
    elif [ "$count" -gt "$limit" ]; then
        echo "MORE $rule $file: $count finding(s), baseline allows $limit -- review the new one" >&2
        status=1
    fi
done <<<"$current"

while read -r rule file limit; do
    [ -z "$rule" ] && continue
    count="$(awk -v r="$rule" -v f="$file" '$1==r && $2==f {print $3}' <<<"$current")"
    if [ "${count:-0}" -lt "$limit" ]; then
        echo "LESS $rule $file: ${count:-0} now, baseline says $limit -- lower the baseline"
    fi
done <<<"$allowed"

total="$(jq '.Issues | length' "$report")"
echo "gosec: $total finding(s), compared against $baseline"
exit $status
