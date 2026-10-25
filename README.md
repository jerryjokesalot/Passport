# Passport

Person-owned **agent passports**: compact Ed25519-signed messages, field grants, free/busy answers, and meeting confirms — without leaking calendar titles, attendees, or locations.

Partnership, not ownership: each person (or their exclusive agent) holds a passport, adds contacts by public id, and decides what to share. Private keys and inboxes stay out of the repo.

## What this is

A small Node.js protocol + CLI for agent-to-agent permissioning over a shared folder (or any dropbox you wire later):

- **Identity** — `ed25519:` public ids; messages are signed and verified
- **Contacts** — you only answer people you’ve added
- **Field grants** — ask / decide / share named fields with scope (e.g. once, remaining, until)
- **Free/busy** — open slots only; titles and other calendar detail never ride in compact messages
- **Meetings** — propose, decide, confirm, with optional detail channels kept separate
- **Audit** — append-only `log.jsonl` for grants and free/busy answers

This is the **governance** layer (who may ask, what may be shared, for how long). Wire protocols like [Google A2A](https://a2aproject.github.io/A2A/) can carry these grants; Passport does not replace TLS/OAuth — it sits on top as the human-controlled permission record.

## Quick start

Requires Node.js 18+ (uses `node:crypto` Ed25519).

```bash
# two local passports + a shared outbox (no network)
bash scripts/demo.sh
# expect: PASS

# security regression suite (temp dirs only; never touches data/ or inbox/)
node security/attack-tests.js
```

### CLI sketch

```bash
node src/cli.js init alice --dir data/alice
node src/cli.js id --dir data/alice
node src/cli.js add-contact --dir data/alice --name bob --id ed25519:...
node src/cli.js seed-calendar --dir data/alice
node src/cli.js ask-freebusy --dir data/alice --to bob \
  --from 2026-10-05T13:00:00.000Z --to-time 2026-10-05T17:00:00.000Z \
  --outbox /path/to/shared
node src/cli.js poll --dir data/bob --inbox /path/to/shared
node src/cli.js pending --dir data/alice
node src/cli.js decide --dir data/alice --request <id> --choice allow   # or deny
```

See `src/cli.js` for the full command list (field requests, meeting propose/confirm, share, show, log).

## Layout

| Path | Role |
|------|------|
| `src/protocol.js` | Core: keys, messages, poll/decide, free/busy, grants |
| `src/meet-details.js` | Meeting detail helpers (kept out of compact free/busy) |
| `src/cli.js` | Command-line front end |
| `scripts/demo.sh` | End-to-end local demo + leak checks |
| `security/` | Attack suite, grant/meet tests, `ATTACK-REPORT.md` |

Gitignored: `inbox/`, local runtime paths. Keep each passport’s `key.json` **only** where that agent can read it — never in a shared cloud sync folder with another agent’s key.

## Hardening already in

From the attack suite (see `security/ATTACK-REPORT.md`):

- Forged signatures and stranger free/busy asks rejected
- Calendar detail scrubbed from compact replies
- Stale / future-skewed messages rejected
- Free/busy windows capped (14 days); flood limits on pending field asks
- Poison-pill and audit-forgery paths closed; decisions must match a sent request
- Processed messages keyed by `from|id` (ID-theft via colliding ids blocked)

## Status

Alpha / research prototype. Useful for demos and adversarial testing. Known follow-ons (not all coded yet): per-key isolation in production, grant enforcement at read time, poll locking, rate limits on free/busy probing.

## License

All rights reserved for now — ask before depending on this in production. Issues and discussion welcome on the repo.
