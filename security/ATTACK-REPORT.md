# passport-alpha: attack test and patch report

- **Date:** 2026-10-02
- **Tester:** Claude (the `claude` passport)
- **For:** Jerry and Momo

## Summary

I ran 14 attacks against `src/protocol.js`. Three were already blocked: forged signatures, strangers asking for free/busy, and calendar details leaking into replies. The other 11 got through, four of them rated high. All 11 are now blocked by the patched `src/protocol.js`, and `scripts/demo.sh` still prints PASS.

To re-run the tests:

    node security/attack-tests.js

The suite builds throwaway passports in a temp folder, so it never touches `data/` or `inbox/`. The pre-patch file is saved as `security/protocol.original.js`.

## Findings and fixes

| # | Sev | Attack | What happened before | Fix |
|---|-----|--------|----------------------|-----|
| 1 | High | **Poison pill (bad decision).** A contact sends a `field.dec` with `decision: "maybe"`. | `poll` threw before saving, so the message was never marked processed. Every later poll crashed on it, and everything queued behind it went unanswered. | Each message is handled in its own try/catch. A bad message is rejected, marked processed and logged as `reject`. The passport is saved in a `finally` block. |
| 2 | High | **Poison pill (bad field).** A `field.req` whose `field` is not a string. | Same permanent jam. | Same as #1, plus field names are checked against `FIELD_RE`. |
| 3 | High | **Forged decision in the audit log.** A contact sends `field.dec allow permanent bankAccount` for a request that was never made. | Written straight into `log.jsonl` as a real grant, which poisons the audit trail. | Outgoing requests are now recorded in `passport.sent`. A decision only counts if it answers a `field.req` that we sent to that same sender for that same field, and only once. Scope values are validated. |
| 4 | High | **ID theft.** A stranger signs a message with their own key but reuses the `id` of a pending message from a real contact, using a filename that sorts first. | The stranger's message was marked processed by bare id, so the real message was silently skipped. | The processed list is keyed `from|id`. Older bare-id entries are still honored. |
| 5 | Med | **Calendar sweep.** One `fb.req` for 2000–2100. | Answered with every busy gap across 100 years. | Windows are capped at 14 days (`MAX_WINDOW_MS`) and declined as `window_too_large`. Times must be strict ISO-8601 UTC. |
| 6 | Med | **Hidden fields.** Add `d.sig` (any nested key named `sig`) after signing. | `canonical()` stripped `sig` at every depth, so the message still verified. | Only the top-level `sig` is excluded. Existing messages had no nested `sig`, so old signatures still verify. |
| 7 | Med | **Stale replay.** A validly signed message dated 2020. | Answered. Anyone who lost `processed` state would re-answer everything. | Messages older than 7 days are rejected (`stale`), and so are messages more than 5 minutes in the future. |
| 8 | Med | **Fail-open calendar.** A busy entry with an unreadable date. | Silently skipped, so the slot was reported as free. | Fails closed with a `calendar_error` decline. |
| 9 | Med | **Audit gap.** Free/busy replies wrote nothing to the log. (This is why `log.jsonl` was empty.) | Calendar shape was shared with no record. | Every free/busy answer is logged: `field: "freebusy"`, `decision: "auto-share"` or `"decline"`, with the window as scope. |
| 10 | Low | **Flood.** 200 `field.req` messages. | All 200 queued for the human. | At most 10 pending requests per contact (`too_many_pending`). |
| 11 | Low | **Unsolicited reply.** An `fb.res` for a request never sent. | Accepted. | Must match a `sent` entry. Asks made before tracking existed are allowed through once (see Compatibility). |

## Compatibility notes (Momo, please read)

- **New passport fields.** `sent` and `sentTrackingSince` are added automatically the first time a passport loads, and nothing else is migrated. `fb.res` replies older than `sentTrackingSince` are accepted, so replies to asks made with the old code still work.
- **Your next poll.** I tested this on a copy of the live data. `claude` polls as `idle`, and `momo` gets `reply fgUeJU5kxm-K6vVD` and `reply zTWvxADvMwEPeqYb`. A fresh ask, reply and log round-trip works end to end.
- **If you run your own copy of `protocol.js`,** update it. A patched passport and an unpatched one still talk fine, but the unpatched one keeps the holes.
- **New poll output.** `reject <reason> <id>` is a new action line. Possible reasons: `stale`, `from_future`, `unsolicited`, `already_answered`, `field_mismatch`, `bad_decision`, `bad_field`, `bad_scope`, `bad_id`, `bad_ts`, `too_many_pending`.
- **New log field.** Log lines may carry an optional `note` field.

## Not fixed (needs a decision, not a code change)

1. **Both private keys sit in one shared, cloud-synced folder.** `data/claude/key.json` and `data/momo/key.json` are both in this OneDrive folder. Anyone who can read the folder, including either agent, can sign as either passport. I could have forged Momo, and Momo could have forged me. On Windows and OneDrive, the 0600 file permissions do nothing, and the keys sync to the cloud. **This is the most important item in this report.** Each agent should keep only its own `key.json`, somewhere the other agent can't read. Only `inbox/` and the public parts need to be shared.
2. **`lastInbox` is an absolute path.** It's stored as a path from whichever machine last polled (right now a `/sessions/...` Linux path). Running `decide` from Windows would fail to deliver the decision message.
3. **Free/busy probing is inherent.** A contact can still map your busy times with many small asks inside the 14-day cap. The usual next step is a per-contact rate limit or a human-approved allowlist of windows.
4. **Grants are recorded but not enforced.** `remaining` and `until` are never checked or decremented, because nothing reads grants yet.
5. **Concurrent polls.** Two `poll` processes running at once could both answer the same request. A lock file would fix this.
6. **`scripts/run-once.js` has a broken check.** It looks for `msg.payload.type`, which doesn't exist, so it always reports `reply null`. Its leak check still works.
