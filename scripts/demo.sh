#!/usr/bin/env bash
# Local two-passport free/busy exchange. No network, no calendar API.
set -euo pipefail
cd "$(dirname "$0")/.."
RUN="demo-run"
rm -rf "$RUN"
mkdir -p "$RUN/shared"
CLI=(node src/cli.js)

"${CLI[@]}" init momo --dir "$RUN/momo" >/dev/null
"${CLI[@]}" init claude --dir "$RUN/claude" >/dev/null
MOMO_ID=$("${CLI[@]}" id --dir "$RUN/momo")
CLAUDE_ID=$("${CLI[@]}" id --dir "$RUN/claude")
"${CLI[@]}" add-contact --dir "$RUN/momo" --name claude --id "$CLAUDE_ID" >/dev/null
"${CLI[@]}" add-contact --dir "$RUN/claude" --name momo --id "$MOMO_ID" >/dev/null
echo "init ok"

"${CLI[@]}" seed-calendar --dir "$RUN/claude" >/dev/null
grep -q 'secret dentist' "$RUN/claude/calendar.json"
CAL_SUM=$(sha256sum "$RUN/claude/calendar.json" | awk '{print $1}')
echo "seed ok"

"${CLI[@]}" ask-freebusy --dir "$RUN/momo" --to claude \
  --from 2026-10-05T13:00:00.000Z \
  --to-time 2026-10-05T17:00:00.000Z \
  --outbox "$RUN/shared" >/dev/null
"${CLI[@]}" poll --dir "$RUN/claude" --inbox "$RUN/shared"

node - "$RUN/shared" << 'JS'
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
let replies = 0;
for (const f of files) {
  const msg = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const data = JSON.stringify(msg.d);
  if (/secret/i.test(data) || /dentist/i.test(data)) {
    console.error('FAIL leak in ' + f);
    process.exit(1);
  }
  const raw = JSON.stringify(msg);
  if (/"title"/.test(raw) || /"attendees"/.test(raw) || /"location"/.test(raw) || /"body"/.test(raw)) {
    console.error('FAIL private field in ' + f);
    process.exit(1);
  }
  if (msg.t === 'fb.res') {
    replies += 1;
    if (msg.d.decline) {
      console.error('FAIL unexpected decline');
      process.exit(1);
    }
    const got = (msg.d.open || []).map((s) => [s.start, s.end]);
    const want = [
      ['2026-10-05T13:00:00.000Z', '2026-10-05T14:00:00.000Z'],
      ['2026-10-05T15:30:00.000Z', '2026-10-05T17:00:00.000Z'],
    ];
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      console.error('FAIL open slots ' + JSON.stringify(got));
      process.exit(1);
    }
  }
}
if (replies !== 1) {
  console.error('FAIL reply count ' + replies);
  process.exit(1);
}
JS

REPLY=$(node - "$RUN/shared" << 'JS'
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
for (const f of fs.readdirSync(dir)) {
  const p = path.join(dir, f);
  const m = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (m.t === 'fb.res') process.stdout.write(p);
}
JS
)
SUM1=$(sha256sum "$REPLY" | awk '{print $1}')
"${CLI[@]}" show --dir "$RUN/momo" --message "$REPLY" >/dev/null
SUM2=$(sha256sum "$REPLY" | awk '{print $1}')
test "$SUM1" = "$SUM2"
echo "no leak ok"

BEFORE=$(find "$RUN/shared" -name '*.json' | wc -l)
"${CLI[@]}" request-field --dir "$RUN/momo" --to claude --field eventTitle --outbox "$RUN/shared" >/dev/null
"${CLI[@]}" poll --dir "$RUN/claude" --inbox "$RUN/shared"
AFTER=$(find "$RUN/shared" -name '*.json' | wc -l)
# The request file was already written; poll must not grant or answer it.
test "$BEFORE" -eq "$((AFTER - 1))"
PEND=$("${CLI[@]}" pending --dir "$RUN/claude")
echo "$PEND" | grep -q 'field=eventTitle'
REQ=$(printf '%s\n' "$PEND" | awk 'NR==1 {print $1}')
test -n "$REQ"
echo "field pending ok"

"${CLI[@]}" decide --dir "$RUN/claude" --request "$REQ" --deny >/dev/null
LOG=$("${CLI[@]}" log --dir "$RUN/claude")
printf '%s\n' "$LOG" | grep -q '"field":"eventTitle"'
printf '%s\n' "$LOG" | grep -q '"decision":"deny"'
printf '%s\n' "$LOG" | grep -q '"decision":"request"'
if "${CLI[@]}" pending --dir "$RUN/claude" | grep -q "$REQ"; then
  echo "FAIL still pending" >&2
  exit 1
fi
if "${CLI[@]}" decide --dir "$RUN/claude" --request "$REQ" --allow once >/dev/null; then
  echo "FAIL denial was not final" >&2
  exit 1
fi
echo "deny logged ok"

CAL_AFTER=$(sha256sum "$RUN/claude/calendar.json" | awk '{print $1}')
test "$CAL_SUM" = "$CAL_AFTER"

# Decision on the wire is the decision only: no title, no English sentence.
node - "$RUN/shared" << 'JS'
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
let n = 0;
for (const f of fs.readdirSync(dir)) {
  const msg = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const data = JSON.stringify(msg.d);
  if (/secret|dentist/i.test(data)) {
    console.error('FAIL leak after decide');
    process.exit(1);
  }
  if (msg.t === 'field.dec') {
    n += 1;
    const keys = Object.keys(msg.d).sort();
    if (JSON.stringify(keys) !== JSON.stringify(['decision', 'field', 'req'])) {
      console.error('FAIL decision payload ' + JSON.stringify(msg.d));
      process.exit(1);
    }
    if (msg.d.decision !== 'deny' || msg.d.field !== 'eventTitle') {
      console.error('FAIL decision value');
      process.exit(1);
    }
  }
}
if (n !== 1) {
  console.error('FAIL decision count ' + n);
  process.exit(1);
}
JS

echo PASS
