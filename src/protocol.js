'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  randomBytes,
} = require('node:crypto');
const details = require('./meet-details');

// Calendar facts that must never ride in a compact message.
const LEAK_KEYS = new Set([
  'title',
  'attendees',
  'location',
  'summary',
  'description',
  'notes',
  'organizer',
  'body',
]);

// Limits that keep a contact from sweeping, flooding or replaying.
const MAX_WINDOW_MS = 14 * 24 * 3600 * 1000; // one free/busy ask covers at most 14 days
const MAX_AGE_MS = 7 * 24 * 3600 * 1000; // messages older than 7 days are stale
const MAX_SKEW_MS = 5 * 60 * 1000; // tolerate 5 minutes of clock drift into the future
const MAX_PENDING_PER_CONTACT = 10; // field requests waiting on a human, per contact
const ID_RE = /^[A-Za-z0-9_-]{16}$/;
const FIELD_RE = /^[A-Za-z][A-Za-z0-9]{0,40}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

// Only the top-level "sig" is excluded; every nested field is covered by the signature.
function canonical(value, top = true) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => canonical(v, false)).join(',') + ']';
  const keys = Object.keys(value).filter((k) => !(top && k === 'sig')).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k], false)).join(',') + '}';
}

function jwkFromPublicId(id) {
  if (typeof id !== 'string' || !id.startsWith('ed25519:') || id.length < 20) {
    throw new Error('bad public id');
  }
  return { kty: 'OKP', crv: 'Ed25519', x: id.slice('ed25519:'.length) };
}

function assertPublicId(id) {
  createPublicKey({ key: jwkFromPublicId(id), format: 'jwk' });
  return id;
}

function loadPassport(dir) {
  const passport = JSON.parse(fs.readFileSync(path.join(dir, 'passport.json'), 'utf8'));
  const key = JSON.parse(fs.readFileSync(path.join(dir, 'key.json'), 'utf8'));
  for (const k of ['contacts', 'pending', 'decided', 'processed', 'grants', 'sent', 'meetings']) {
    if (!Array.isArray(passport[k])) passport[k] = [];
  }
  // Passports created before outgoing requests were tracked: replies to older asks are honored.
  if (!passport.sentTrackingSince) passport.sentTrackingSince = new Date().toISOString();
  return {
    dir,
    passport,
    privateKey: createPrivateKey({ key, format: 'jwk' }),
  };
}

function savePassport(p) {
  const file = path.join(p.dir, 'passport.json');
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(p.passport, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

function appendLog(dir, entry) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    who: entry.who,
    field: entry.field,
    scope: entry.scope ?? null,
    decision: entry.decision,
    request: entry.request,
    ...(entry.note ? { note: entry.note } : {}),
  });
  fs.appendFileSync(path.join(dir, 'log.jsonl'), line + '\n');
}

function signMessage(privateKey, msg) {
  const payload = canonical(msg);
  const sig = sign(null, Buffer.from(payload), privateKey);
  return Object.assign({}, msg, { sig: sig.toString('base64url') });
}

function verifyMessage(msg) {
  if (!msg || typeof msg !== 'object' || typeof msg.sig !== 'string' || typeof msg.from !== 'string') {
    return false;
  }
  let key;
  try {
    key = createPublicKey({ key: jwkFromPublicId(msg.from), format: 'jwk' });
  } catch {
    return false;
  }
  let sig;
  try {
    sig = Buffer.from(msg.sig, 'base64url');
  } catch {
    return false;
  }
  return verify(null, Buffer.from(canonical(msg)), key, sig);
}

function assertSendable(msg) {
  const walk = (v) => {
    if (Array.isArray(v)) {
      v.forEach(walk);
      return;
    }
    if (v && typeof v === 'object') {
      for (const k of Object.keys(v)) {
        if (LEAK_KEYS.has(k)) throw new Error('blocked private calendar field: ' + k);
        walk(v[k]);
      }
    }
  };
  walk(msg.d);
  // A granted field.share may carry the human-approved value (an event title is prose).
  // Every other byte on the wire still refuses English prose.
  const scanned = JSON.parse(JSON.stringify(msg));
  if (scanned && scanned.t === 'field.share' && scanned.d && typeof scanned.d.value === 'string') {
    delete scanned.d.value;
  }
  if (scanned && scanned.t === 'meet.confirm' && scanned.d && Array.isArray(scanned.d.fields)) {
    for (const entry of scanned.d.fields) {
      if (entry && typeof entry.value === 'string') delete entry.value;
    }
  }
  const raw = JSON.stringify(scanned);
  if (/[A-Za-z]{3,}\s+[A-Za-z]{3,}/.test(raw)) {
    throw new Error('refusing English prose on the wire');
  }
}

function writeMessage(dir, msg) {
  assertSendable(msg);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, msg.id + '.json');
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(msg) + '\n');
  fs.renameSync(tmp, file);
  return file;
}

function newId() {
  return randomBytes(12).toString('base64url');
}

function buildMessage(p, to, t, d) {
  return signMessage(p.privateKey, {
    v: 1,
    t,
    id: newId(),
    from: p.passport.publicId,
    to,
    ts: new Date().toISOString(),
    d,
  });
}

function contactByName(p, name) {
  const c = p.passport.contacts.find((x) => x.name === name);
  if (!c) throw new Error('unknown contact: ' + name);
  return c;
}

function init(name, dir) {
  if (!/^[a-z][a-z0-9-]{0,40}$/.test(name)) throw new Error('bad passport name');
  if (fs.existsSync(path.join(dir, 'passport.json'))) throw new Error('passport already exists: ' + dir);
  fs.mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  if (pub.x !== priv.x) throw new Error('keypair mismatch');
  fs.writeFileSync(path.join(dir, 'key.json'), JSON.stringify(priv) + '\n', { mode: 0o600 });
  fs.chmodSync(path.join(dir, 'key.json'), 0o600);
  const passport = {
    v: 1,
    name,
    publicId: 'ed25519:' + pub.x,
    contacts: [],
    pending: [],
    decided: [],
    processed: [],
    grants: [],
    sent: [],
    meetings: [],
    sentTrackingSince: new Date().toISOString(),
    lastInbox: null,
  };
  fs.writeFileSync(path.join(dir, 'passport.json'), JSON.stringify(passport, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'log.jsonl'), '');
  return passport.publicId;
}

function addContact(dir, name, id) {
  if (!/^[a-z][a-z0-9-]{0,40}$/.test(name)) throw new Error('bad contact name');
  assertPublicId(id);
  const p = loadPassport(dir);
  if (id === p.passport.publicId) throw new Error('cannot add self');
  if (p.passport.contacts.some((c) => c.name === name || c.id === id)) {
    throw new Error('contact already exists');
  }
  p.passport.contacts.push({ name, id });
  savePassport(p);
}

// Local fixture only. Titles stay in this file; replies read start/end.
function seedCalendar(dir) {
  loadPassport(dir);
  const calendar = {
    busy: [
      {
        start: '2026-10-05T14:00:00.000Z',
        end: '2026-10-05T15:30:00.000Z',
        title: 'secret dentist',
        attendees: ['ada@clinic.example'],
        location: 'Suite 4',
        body: 'secret notes about the visit',
      },
    ],
  };
  const file = path.join(dir, 'calendar.json');
  fs.writeFileSync(file, JSON.stringify(calendar, null, 2) + '\n');
  return file;
}

function parseIso(v) {
  if (typeof v !== 'string' || !ISO_RE.test(v)) return NaN;
  return Date.parse(v);
}

function checkWindow(startIso, endIso) {
  const start = parseIso(startIso);
  const end = parseIso(endIso);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 'bad_window';
  if (end - start > MAX_WINDOW_MS) return 'window_too_large';
  return null;
}

function slotError(slot) {
  if (!slot || typeof slot !== 'object' || Array.isArray(slot)) return 'bad_slot';
  const keys = Object.keys(slot).sort();
  if (keys.length !== 2 || keys[0] !== 'end' || keys[1] !== 'start') return 'bad_slot';
  return checkWindow(slot.start, slot.end);
}

function openSlots(startIso, endIso, busy) {
  if (checkWindow(startIso, endIso)) return null;
  const start = parseIso(startIso);
  const end = parseIso(endIso);
  const clipped = [];
  for (const b of busy) {
    const s = Date.parse(b.start);
    const e = Date.parse(b.end);
    // Fail closed: a busy entry we cannot read must never show up as free time.
    if (!Number.isFinite(s) || !Number.isFinite(e) || e < s) throw new Error('calendar_error');
    const from = Math.max(start, s);
    const to = Math.min(end, e);
    if (to > from) clipped.push({ from, to });
  }
  clipped.sort((a, b) => a.from - b.from);
  const merged = [];
  for (const b of clipped) {
    const last = merged[merged.length - 1];
    if (!last || b.from > last.to) merged.push({ from: b.from, to: b.to });
    else last.to = Math.max(last.to, b.to);
  }
  const open = [];
  let cursor = start;
  for (const b of merged) {
    if (b.from > cursor) {
      open.push({ start: new Date(cursor).toISOString(), end: new Date(b.from).toISOString() });
    }
    cursor = Math.max(cursor, b.to);
  }
  if (cursor < end) {
    open.push({ start: new Date(cursor).toISOString(), end: new Date(end).toISOString() });
  }
  return open;
}

function instantsOnly(dir) {
  const file = path.join(dir, 'calendar.json');
  if (!fs.existsSync(file)) return null;
  const cal = JSON.parse(fs.readFileSync(file, 'utf8'));
  return (cal.busy || []).map((b) => ({ start: b.start, end: b.end }));
}

function askFreeBusy(dir, toName, start, end, outbox) {
  const p = loadPassport(dir);
  const c = contactByName(p, toName);
  const bad = checkWindow(start, end);
  if (bad) throw new Error(bad === 'window_too_large' ? 'window longer than 14 days' : 'bad window');
  const msg = buildMessage(p, c.id, 'fb.req', { start, end });
  const file = writeMessage(outbox, msg);
  p.passport.sent.push({ request: msg.id, t: 'fb.req', to: c.id, ts: msg.ts, answered: false });
  savePassport(p);
  return file;
}

function requestField(dir, toName, field, outbox) {
  if (!FIELD_RE.test(field || '')) throw new Error('bad field name');
  if (field === 'freebusy') throw new Error('freebusy is already the default field');
  const p = loadPassport(dir);
  const c = contactByName(p, toName);
  const msg = buildMessage(p, c.id, 'field.req', { field });
  const file = writeMessage(outbox, msg);
  p.passport.sent.push({ request: msg.id, t: 'field.req', to: c.id, field, ts: msg.ts, answered: false });
  savePassport(p);
  appendLog(dir, { who: c.id, field, scope: null, decision: 'request', request: msg.id });
  return file;
}

// Slot only. A note, title, attendees, location, or body is not part of this message.
function proposeMeet(dir, toName, start, end, outbox) {
  const p = loadPassport(dir);
  const c = contactByName(p, toName);
  const bad = slotError({ start, end });
  if (bad) throw new Error(bad === 'window_too_large' ? 'window longer than 14 days' : 'bad window');
  const slot = { start, end };
  const msg = buildMessage(p, c.id, 'meet.prop', { slot });
  const file = writeMessage(outbox, msg);
  p.passport.sent.push({
    request: msg.id,
    t: 'meet.prop',
    to: c.id,
    ts: msg.ts,
    answered: false,
    slot,
  });
  appendLog(dir, {
    who: c.id,
    field: 'meet',
    scope: start + '/' + end,
    decision: 'propose',
    request: msg.id,
  });
  savePassport(p);
  return file;
}

function replyFreeBusy(p, msg, inbox) {
  let busy = null;
  try {
    busy = instantsOnly(p.dir);
  } catch {
    busy = 'error';
  }
  let d;
  const bad = checkWindow(msg.d.start, msg.d.end);
  if (bad) d = { req: msg.id, decline: bad };
  else if (!busy) d = { req: msg.id, decline: 'no_calendar' };
  else if (busy === 'error') d = { req: msg.id, decline: 'calendar_error' };
  else {
    try {
      d = { req: msg.id, open: openSlots(msg.d.start, msg.d.end, busy) };
    } catch {
      d = { req: msg.id, decline: 'calendar_error' };
    }
  }
  const file = writeMessage(inbox, buildMessage(p, msg.from, 'fb.res', d));
  // Every answer that reveals calendar shape goes in the audit log.
  appendLog(p.dir, {
    who: msg.from,
    field: 'freebusy',
    scope: d.open ? msg.d.start + '/' + msg.d.end : null,
    decision: d.open ? 'auto-share' : 'decline',
    request: msg.id,
    ...(d.decline ? { note: d.decline } : {}),
  });
  return file;
}

function queueField(p, msg) {
  const field = msg.d.field;
  if (typeof field !== 'string' || !FIELD_RE.test(field)) throw new Error('bad_field');
  if (p.passport.decided.some((d) => d.request === msg.id)) return 'already-decided';
  if (p.passport.pending.some((d) => d.request === msg.id)) return 'already-pending';
  if (p.passport.pending.filter((d) => d.who === msg.from).length >= MAX_PENDING_PER_CONTACT) {
    throw new Error('too_many_pending');
  }
  p.passport.pending.push({
    request: msg.id,
    field,
    who: msg.from,
    ts: new Date().toISOString(),
  });
  appendLog(p.dir, {
    who: msg.from,
    field,
    scope: null,
    decision: 'request',
    request: msg.id,
  });
  return 'queued';
}

function queueMeet(p, msg) {
  const d = msg.d;
  const keys = Object.keys(d).sort();
  if (keys.length !== 1 || keys[0] !== 'slot') throw new Error('bad_meet');
  const bad = slotError(d.slot);
  if (bad) throw new Error(bad);
  if (p.passport.pending.some((x) => x.request === msg.id)) return 'already-pending';
  if (!Array.isArray(p.passport.meetings)) p.passport.meetings = [];
  if (p.passport.meetings.some((x) => x.request === msg.id && x.role === 'in')) return 'already-decided';
  if (p.passport.pending.filter((x) => x.who === msg.from).length >= MAX_PENDING_PER_CONTACT) {
    throw new Error('too_many_pending');
  }
  const slot = { start: d.slot.start, end: d.slot.end };
  p.passport.pending.push({
    request: msg.id,
    field: 'meet',
    kind: 'meet',
    who: msg.from,
    slot,
    ts: new Date().toISOString(),
  });
  appendLog(p.dir, {
    who: msg.from,
    field: 'meet',
    scope: slot.start + '/' + slot.end,
    decision: 'request',
    request: msg.id,
  });
  return 'queued';
}

function learnMeet(p, msg) {
  const d = msg.d;
  const decision = d.decision;
  if (decision !== 'yes' && decision !== 'no' && decision !== 'counter') throw new Error('bad_decision');
  const keys = Object.keys(d).sort();
  let counterSlot = null;
  if (decision === 'counter') {
    if (keys.length !== 3 || keys[0] !== 'decision' || keys[1] !== 'req' || keys[2] !== 'slot') {
      throw new Error('bad_counter');
    }
    const bad = slotError(d.slot);
    if (bad) throw new Error(bad);
    counterSlot = { start: d.slot.start, end: d.slot.end };
  } else if (keys.length !== 2 || keys[0] !== 'decision' || keys[1] !== 'req') {
    throw new Error('bad_decision');
  }
  const s = matchSent(p, msg, 'meet.prop');
  s.answered = true;
  s.decision = decision;
  if (counterSlot) s.counter = counterSlot;
  if (!Array.isArray(p.passport.meetings)) p.passport.meetings = [];
  const slot = counterSlot || (s.slot ? { start: s.slot.start, end: s.slot.end } : null);
  p.passport.meetings.push({
    request: d.req,
    who: msg.from,
    slot,
    decision,
    role: 'out',
    ts: new Date().toISOString(),
  });
  appendLog(p.dir, {
    who: msg.from,
    field: 'meet',
    scope: slot ? slot.start + '/' + slot.end : null,
    decision,
    request: d.req,
  });
  return 'learned ' + decision + ' ' + d.req;
}

function checkEnvelope(msg) {
  if (msg.v !== 1) throw new Error('bad_version');
  if (typeof msg.id !== 'string' || !ID_RE.test(msg.id)) throw new Error('bad_id');
  if (typeof msg.t !== 'string') throw new Error('bad_type');
  if (!msg.d || typeof msg.d !== 'object' || Array.isArray(msg.d)) throw new Error('bad_body');
  const ts = parseIso(msg.ts);
  if (!Number.isFinite(ts)) throw new Error('bad_ts');
  const now = Date.now();
  if (now - ts > MAX_AGE_MS) throw new Error('stale');
  if (ts - now > MAX_SKEW_MS) throw new Error('from_future');
}

// A reply or decision only counts if it answers something we actually sent to that sender.
function matchSent(p, msg, type, field) {
  const req = msg.d.req;
  if (typeof req !== 'string') throw new Error('bad_req');
  const s = p.passport.sent.find((x) => x.request === req && x.t === type && x.to === msg.from);
  if (!s) {
    // Grace for asks made before this passport tracked outgoing requests (free/busy only).
    if (type === 'fb.req' && Date.parse(msg.ts) < Date.parse(p.passport.sentTrackingSince)) return null;
    throw new Error('unsolicited');
  }
  if (s.answered) throw new Error('already_answered');
  if (field !== undefined && s.field !== field) throw new Error('field_mismatch');
  return s;
}

function learnConfirm(p, msg) {
  const reason = details.validateConfirmBody(msg.d);
  if (reason) throw new Error(reason);
  const req = msg.d.req;
  const sent = p.passport.sent.find((x) => x.request === req && x.t === 'meet.prop' && x.to === msg.from);
  if (!sent) throw new Error('unsolicited');
  if (!Array.isArray(p.passport.meetings)) p.passport.meetings = [];
  const meeting = [...p.passport.meetings].reverse().find((m) => m.request === req && m.who === msg.from && m.role === 'out' && m.decision === 'yes');
  if (!meeting) throw new Error('no yes');
  const copied = details.copiedMeetUrl(msg.d);
  if (copied !== null) meeting.meetUrl = copied;
  appendLog(p.dir, {
    who: msg.from,
    field: 'meet',
    scope: meeting.slot ? meeting.slot.start + '/' + meeting.slot.end : null,
    decision: 'copy',
    request: req,
  });
  return copied !== null ? 'copied meetUrl ' + req : 'confirm ' + req;
}

function handle(p, msg, inbox) {
  checkEnvelope(msg);
  if (msg.t === 'fb.req') {
    const file = replyFreeBusy(p, msg, inbox);
    return 'replied ' + msg.id + ' ' + path.basename(file);
  }
  if (msg.t === 'field.req') {
    return 'field ' + queueField(p, msg) + ' ' + msg.id;
  }
  if (msg.t === 'field.dec') {
    const { decision, field, scope } = msg.d;
    if (decision !== 'allow' && decision !== 'deny') throw new Error('bad_decision');
    if (typeof field !== 'string' || !FIELD_RE.test(field)) throw new Error('bad_field');
    const okScope = decision === 'deny' ? scope === undefined : ['once', 'timed', 'permanent'].includes(scope);
    if (!okScope) throw new Error('bad_scope');
    const s = matchSent(p, msg, 'field.req', field);
    s.answered = true;
    appendLog(p.dir, { who: msg.from, field, scope: scope ?? null, decision, request: msg.d.req });
    return 'learned ' + decision + ' ' + msg.d.req;
  }
  if (msg.t === 'fb.res') {
    const s = matchSent(p, msg, 'fb.req');
    if (s) s.answered = true;
    return 'reply ' + msg.id;
  }
  if (msg.t === 'meet.prop') {
    return 'meet ' + queueMeet(p, msg) + ' ' + msg.id;
  }
  if (msg.t === 'meet.res') {
    return learnMeet(p, msg);
  }
  if (msg.t === 'meet.confirm') {
    return learnConfirm(p, msg);
  }
  return 'ignore ' + msg.t;
}

function poll(dir, inbox) {
  const p = loadPassport(dir);
  p.passport.lastInbox = path.resolve(inbox);
  const names = fs.existsSync(inbox)
    ? fs.readdirSync(inbox).filter((f) => f.endsWith('.json')).sort()
    : [];
  const actions = [];
  try {
    for (const name of names) {
      let msg;
      try {
        msg = JSON.parse(fs.readFileSync(path.join(inbox, name), 'utf8'));
      } catch {
        actions.push('skip unreadable ' + name);
        continue;
      }
      if (!msg || typeof msg !== 'object' || msg.to !== p.passport.publicId) continue;
      if (!verifyMessage(msg)) {
        actions.push('skip bad-sig ' + (typeof msg.id === 'string' ? msg.id : name));
        continue;
      }
      // Processed is keyed by sender + id, so a stranger cannot "use up" someone else's id.
      const key = msg.from + '|' + msg.id;
      if (p.passport.processed.includes(key) || p.passport.processed.includes(msg.id)) continue;
      p.passport.processed.push(key);
      if (!p.passport.contacts.some((c) => c.id === msg.from)) {
        actions.push('skip unknown ' + msg.id);
        continue;
      }
      // One bad message is rejected and recorded; it can never jam the rest of the inbox.
      try {
        actions.push(handle(p, msg, inbox));
      } catch (err) {
        const reason = String(err.message || err).slice(0, 40);
        actions.push('reject ' + reason + ' ' + msg.id);
        appendLog(p.dir, {
          who: msg.from,
          field: typeof msg.t === 'string' ? msg.t.slice(0, 20) : null,
          scope: null,
          decision: 'reject',
          request: msg.id,
          note: reason,
        });
      }
    }
  } finally {
    savePassport(p);
  }
  return actions;
}

function pending(dir) {
  const p = loadPassport(dir);
  return p.passport.pending.map((item) => {
    const c = p.passport.contacts.find((x) => x.id === item.who);
    const name = c ? c.name : '?';
    if (item.kind === 'meet' && item.slot) {
      return item.request + ' field=meet start=' + item.slot.start + ' end=' + item.slot.end + ' who=' + item.who + ' name=' + name;
    }
    return item.request + ' field=' + item.field + ' who=' + item.who + ' name=' + name;
  });
}

function decide(dir, request, choice) {
  const p = loadPassport(dir);
  const prior = p.passport.decided.find((d) => d.request === request);
  if (prior && prior.decision === 'deny') throw new Error('denial is final for ' + request);
  if (prior) throw new Error('already decided ' + request);
  const item = p.passport.pending.find((d) => d.request === request);
  if (!item) throw new Error('no pending request ' + request);
  if (item.kind === 'meet') throw new Error('use decide-meet for ' + request);
  const allow = choice.allow;
  const deny = choice.deny;
  if (Boolean(allow) === Boolean(deny)) throw new Error('pass exactly one of --allow or --deny');
  let decision;
  let scope = null;
  let until = null;
  if (deny) {
    decision = 'deny';
  } else {
    if (!['once', 'timed', 'permanent'].includes(allow)) {
      throw new Error('scope must be once|timed|permanent');
    }
    decision = 'allow';
    scope = allow;
    if (scope === 'timed') {
      const n = Number(choice.hours);
      if (!Number.isFinite(n) || n <= 0) throw new Error('timed scope needs --hours');
      until = new Date(Date.now() + n * 3600 * 1000).toISOString();
    }
  }
  p.passport.decided.push({
    request,
    field: item.field,
    who: item.who,
    decision,
    scope,
    until,
    ts: new Date().toISOString(),
  });
  p.passport.pending = p.passport.pending.filter((d) => d.request !== request);
  if (decision === 'allow') {
    p.passport.grants.push({
      request,
      field: item.field,
      who: item.who,
      scope,
      until,
      remaining: scope === 'once' ? 1 : null,
    });
  }
  appendLog(p.dir, { who: item.who, field: item.field, scope, decision, request });
  savePassport(p);
  if (!p.passport.lastInbox) throw new Error('decision logged; no inbox to notify');
  const d = { req: request, field: item.field, decision };
  if (decision === 'allow') {
    d.scope = scope;
    if (until) d.until = until;
  }
  return writeMessage(p.passport.lastInbox, buildMessage(p, item.who, 'field.dec', d));
}

function decideMeet(dir, request, choice, outbox) {
  const yes = Boolean(choice.yes);
  const no = Boolean(choice.no);
  const counter = Boolean(choice.counter);
  if (Number(yes) + Number(no) + Number(counter) !== 1) {
    throw new Error('pass exactly one of --yes, --no, or --counter');
  }
  const p = loadPassport(dir);
  const item = p.passport.pending.find((d) => d.request === request);
  if (!item) throw new Error('no pending request ' + request);
  if (item.kind !== 'meet') throw new Error('not a meeting proposal ' + request);
  let decision = 'no';
  let slot = null;
  if (yes) decision = 'yes';
  else if (counter) {
    decision = 'counter';
    const bad = slotError({ start: choice.from, end: choice.toTime });
    if (bad) throw new Error(bad === 'window_too_large' ? 'window longer than 14 days' : 'bad window');
    slot = { start: choice.from, end: choice.toTime };
  }
  const kept = { start: item.slot.start, end: item.slot.end };
  const body = { req: request, decision };
  if (decision === 'counter') body.slot = slot;
  const file = writeMessage(outbox, buildMessage(p, item.who, 'meet.res', body));
  if (!Array.isArray(p.passport.meetings)) p.passport.meetings = [];
  p.passport.meetings.push({
    request,
    who: item.who,
    slot: slot || kept,
    decision,
    role: 'in',
    ts: new Date().toISOString(),
  });
  p.passport.pending = p.passport.pending.filter((d) => d.request !== request);
  appendLog(p.dir, {
    who: item.who,
    field: 'meet',
    scope: (slot || kept).start + '/' + (slot || kept).end,
    decision,
    request,
  });
  savePassport(p);
  return file;
}

// Local record only. A yes on the wire is not an event, and a title is never invented.
// google:true does not call a calendar API. After a local confirm it writes google-outbox.json
// as one object {start, end, summary:"Hold", timeZone} for a later create by the parent.
// summary stays Hold unless a live eventTitle grant supplied a title. description and
// meetUrl are included only when granted. Those three fields also leave on a new signed
// meet.confirm; a dead grant is deny with no value. Only role in may set them.
function confirmMeet(dir, request, opts) {
  const google = Boolean(opts && opts.google === true);
  const p = loadPassport(dir);
  if (!Array.isArray(p.passport.meetings)) p.passport.meetings = [];
  const yes = [...p.passport.meetings].reverse().find((m) => m.request === request && m.decision === 'yes' && m.slot);
  if (!yes) throw new Error('no yes to confirm ' + request);
  const inputs = details.detailInputs(opts);
  if (inputs.length && yes.role !== 'in') throw new Error('only the confirming side sets meet fields');
  const file = path.join(dir, 'proposals.json');
  let doc = { proposals: [] };
  if (fs.existsSync(file)) {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.proposals)) throw new Error('bad proposals file');
  }
  if (google) {
    const record = doc.proposals.find((r) => r.request === request);
    if (!record || record.status !== 'confirmed') throw new Error('not confirmed locally ' + request);
    // A stored googleEvent of "pending" is not a create and does not authorize one.
    const eventId = record.eventId || record.googleEventId;
    const markedEvent = typeof record.googleEvent === 'string' && record.googleEvent && record.googleEvent !== 'pending';
    if (record.googleReady === true || record.googleCreated === true || eventId || markedEvent) {
      throw new Error('google create already prepared ' + request);
    }
    if (!record.slot || record.slot.start !== yes.slot.start || record.slot.end !== yes.slot.end) {
      throw new Error('not confirmed locally ' + request);
    }
    const payload = {
      start: record.slot.start,
      end: record.slot.end,
      summary: 'Hold',
      timeZone: 'America/New_York',
    };
    const now = Date.now();
    const stored = record.shared && typeof record.shared === 'object' ? Object.assign({}, record.shared) : {};
    if (inputs.length) {
      const parts = details.releaseDetails((field) => liveGrant(p, yes.who, field, now), request, opts, stored);
      for (const part of parts) {
        if (part.denied) delete stored[part.field];
        else stored[part.field] = part.value;
      }
      details.spendGrants(parts, request);
      const kept = {};
      for (const field of details.DETAIL_FIELDS) {
        if (typeof stored[field] === 'string') kept[field] = stored[field];
      }
      if (Object.keys(kept).length) record.shared = kept;
      else delete record.shared;
    }
    const gated = {};
    for (const field of details.DETAIL_FIELDS) {
      if (typeof stored[field] !== 'string') continue;
      const value = details.allowedStored(liveGrant(p, yes.who, field, now), request, stored[field]);
      if (typeof value === 'string') gated[field] = value;
    }
    details.applyPayload(payload, gated);
    const outFile = path.join(dir, 'google-outbox.json');
    const outTmp = outFile + '.tmp';
    fs.writeFileSync(outTmp, JSON.stringify(payload) + '\n');
    fs.renameSync(outTmp, outFile);
    record.googleReady = true;
    record.googleCreated = false;
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n');
    fs.renameSync(tmp, file);
    appendLog(dir, {
      who: yes.who,
      field: 'meet',
      scope: record.slot.start + '/' + record.slot.end,
      decision: 'google-ready',
      request,
      note: 'no event id',
    });
    savePassport(p);
    return payload;
  }
  const record = {
    request,
    who: yes.who,
    slot: { start: yes.slot.start, end: yes.slot.end },
    status: 'confirmed',
  };
  if (doc.proposals.some((r) => r.request === request)) throw new Error('already confirmed ' + request);
  if (inputs.length) {
    if (!opts.outbox || opts.outbox === true) throw new Error('missing outbox');
    const now = Date.now();
    const parts = details.releaseDetails((field) => liveGrant(p, yes.who, field, now), request, opts, null);
    writeMessage(opts.outbox, buildMessage(p, yes.who, 'meet.confirm', { req: request, fields: details.wireFields(parts) }));
    details.spendGrants(parts, request);
    for (const part of parts) {
      if (!part.denied && part.replay) continue;
      appendLog(dir, {
        who: yes.who,
        field: part.field,
        scope: part.verdict.scope,
        decision: part.verdict.decision,
        request: part.verdict.request || request,
      });
    }
    const shared = details.sharedValues(parts);
    if (Object.keys(shared).length) record.shared = shared;
  }
  doc.proposals.push(record);
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n');
  fs.renameSync(tmp, file);
  appendLog(dir, {
    who: yes.who,
    field: 'meet',
    scope: record.slot.start + '/' + record.slot.end,
    decision: 'confirm',
    request,
  });
  savePassport(p);
  return file;
}

// Records an event id after the outbox payload was prepared. Does not call a calendar API.
function markCreated(dir, request, eventId) {
  if (typeof request !== 'string' || !request) throw new Error('bad request');
  if (typeof eventId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(eventId)) throw new Error('bad event id');
  if (!fs.existsSync(path.join(dir, 'passport.json'))) throw new Error('not a passport');
  const file = path.join(dir, 'proposals.json');
  if (!fs.existsSync(file)) throw new Error('google not ready ' + request);
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.proposals)) throw new Error('bad proposals file');
  const record = doc.proposals.find((r) => r.request === request);
  if (!record || record.googleReady !== true) throw new Error('google not ready ' + request);
  if (record.googleCreated === true || record.eventId || record.googleEventId) {
    throw new Error('event already recorded ' + request);
  }
  record.googleCreated = true;
  record.eventId = eventId;
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n');
  fs.renameSync(tmp, file);
  appendLog(dir, {
    who: record.who,
    field: 'meet',
    scope: record.slot ? record.slot.start + '/' + record.slot.end : null,
    decision: 'google-created',
    request,
    note: 'event id recorded',
  });
  return eventId;
}

// Latest human decision for this contact and field. A deny stays in force until a
// newer human allow; an agent cannot insert or lift either one.
function controllingDecision(p, who, field) {
  let latest = null;
  for (const d of p.passport.decided) {
    if (d.who !== who || d.field !== field) continue;
    if (!latest || Date.parse(d.ts) >= Date.parse(latest.ts)) latest = d;
  }
  return latest;
}

function classifyGrant(grant, now) {
  const scope = grant.scope || null;
  const request = grant.request || null;
  if (grant.scope === 'permanent') {
    return { live: true, decision: 'share', scope, request, grant };
  }
  if (grant.scope === 'once') {
    if (Number(grant.remaining) > 0) return { live: true, decision: 'spend', scope, request, grant };
    return { live: false, decision: 'spent', scope, request, grant };
  }
  if (grant.scope === 'timed') {
    const until = Date.parse(grant.until);
    if (Number.isFinite(until) && now < until) return { live: true, decision: 'share', scope, request, grant };
    return { live: false, decision: 'expired', scope, request, grant };
  }
  return { live: false, decision: 'blocked', scope, request, grant: null };
}

// Send-time check. Recording a grant is not enough: once/timed/deny are applied here.
function liveGrant(p, who, field, now) {
  const latest = controllingDecision(p, who, field);
  if (latest && latest.decision === 'deny') {
    return { live: false, decision: 'deny', scope: null, request: latest.request, grant: null };
  }
  let grant = null;
  if (latest && latest.decision === 'allow') {
    grant = p.passport.grants.find((g) => g.request === latest.request) || null;
  }
  if (!grant) {
    const matches = p.passport.grants.filter((g) => g.who === who && g.field === field);
    grant = matches.length ? matches[matches.length - 1] : null;
  }
  if (!grant) return { live: false, decision: 'blocked', scope: null, request: latest ? latest.request : null, grant: null };
  return classifyGrant(grant, now);
}

function fieldValue(p, field, explicit) {
  if (explicit !== undefined && explicit !== null) {
    if (typeof explicit !== 'string' || explicit.length < 1 || explicit.length > 500) throw new Error('bad value');
    return explicit;
  }
  if (field === 'eventTitle') {
    const file = path.join(p.dir, 'calendar.json');
    if (!fs.existsSync(file)) throw new Error('no value');
    const cal = JSON.parse(fs.readFileSync(file, 'utf8'));
    const titles = [];
    for (const b of cal.busy || []) {
      if (b && typeof b.title === 'string' && b.title) titles.push(b.title);
    }
    if (!titles.length) throw new Error('no value');
    return titles.join('\n');
  }
  throw new Error('no value');
}

// Share one non-freebusy field. The wire carries the value or a bare deny.
// Spend, expiry and the deny reason stay in the local log.
function shareField(dir, toName, field, outbox, explicit) {
  if (!FIELD_RE.test(field || '')) throw new Error('bad field name');
  if (field === 'freebusy') throw new Error('freebusy is already the default field');
  const p = loadPassport(dir);
  const c = contactByName(p, toName);
  const verdict = liveGrant(p, c.id, field, Date.now());
  let d;
  if (!verdict.live) d = { field, decision: 'deny' };
  else d = { field, value: fieldValue(p, field, explicit) };
  const msg = buildMessage(p, c.id, 'field.share', d);
  const file = writeMessage(outbox, msg);
  if (verdict.live && verdict.grant && verdict.grant.scope === 'once') verdict.grant.remaining -= 1;
  appendLog(p.dir, {
    who: c.id,
    field,
    scope: verdict.scope,
    decision: verdict.decision,
    request: verdict.request,
  });
  savePassport(p);
  return file;
}

function readLog(dir) {
  const file = path.join(dir, 'log.jsonl');
  if (!fs.existsSync(file)) return '';
  return fs.readFileSync(file, 'utf8').replace(/\n$/, '');
}

function render(msg) {
  if (!verifyMessage(msg)) return 'Unsigned or invalid compact message.';
  const lines = [];
  if (msg.t === 'fb.req') {
    lines.push('Free/busy request ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('To ' + msg.to);
    lines.push('Window ' + msg.d.start + ' to ' + msg.d.end);
  } else if (msg.t === 'fb.res') {
    lines.push('Free/busy reply ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('About request ' + msg.d.req);
    if (msg.d.decline) lines.push('Declined (' + msg.d.decline + ').');
    else if (!msg.d.open.length) lines.push('No open time in that window.');
    else {
      lines.push('Open slots:');
      for (const s of msg.d.open) lines.push('  ' + s.start + ' to ' + s.end);
    }
  } else if (msg.t === 'field.req') {
    lines.push('Field request ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('Asks to add field ' + msg.d.field + '.');
    lines.push('Pending until a person decides. An agent cannot grant this.');
  } else if (msg.t === 'field.dec') {
    lines.push('Field decision ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('Request ' + msg.d.req + ' for ' + msg.d.field + '.');
    if (msg.d.decision === 'deny') lines.push('Denied. This request is closed.');
    else lines.push('Allowed, scope ' + msg.d.scope + (msg.d.until ? ', until ' + msg.d.until : '') + '.');
  } else if (msg.t === 'field.share') {
    lines.push('Field share ' + msg.id);
    lines.push('From ' + msg.from);
    if (msg.d.decision === 'deny') lines.push('Field ' + msg.d.field + ' denied.');
    else lines.push('Field ' + msg.d.field + ': ' + msg.d.value);
  } else if (msg.t === 'meet.prop') {
    lines.push('Meeting proposal ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('To ' + msg.to);
    lines.push('Slot ' + msg.d.slot.start + ' to ' + msg.d.slot.end);
  } else if (msg.t === 'meet.res') {
    lines.push('Meeting response ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('About request ' + msg.d.req);
    lines.push('Decision ' + msg.d.decision);
    if (msg.d.decision === 'counter' && msg.d.slot) {
      lines.push('Counter slot ' + msg.d.slot.start + ' to ' + msg.d.slot.end);
    }
  } else if (msg.t === 'meet.confirm') {
    lines.push('Meeting confirm ' + msg.id);
    lines.push('From ' + msg.from);
    lines.push('About request ' + msg.d.req);
    const fields = Array.isArray(msg.d.fields) ? msg.d.fields : [];
    for (const entry of fields) {
      if (entry.decision === 'deny') lines.push('Field ' + entry.field + ' denied.');
      else lines.push('Field ' + entry.field + ': ' + entry.value);
    }
  } else {
    lines.push('Compact message type ' + msg.t + '.');
  }
  return lines.join('\n');
}

function show(dir, file) {
  loadPassport(dir);
  const before = fs.readFileSync(file);
  const text = render(JSON.parse(before.toString('utf8')));
  const after = fs.readFileSync(file);
  if (!before.equals(after)) throw new Error('show mutated the message');
  return text;
}

module.exports = {
  init,
  addContact,
  seedCalendar,
  askFreeBusy,
  requestField,
  poll,
  pending,
  decide,
  readLog,
  show,
  shareField,
  proposeMeet,
  decideMeet,
  confirmMeet,
  markCreated,
  loadPassport,
};
