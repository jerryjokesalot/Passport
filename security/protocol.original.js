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

// Calendar facts that must never ride in a compact message.
const LEAK_KEYS = new Set([
  'title',
  'attendees',
  'location',
  'summary',
  'description',
  'notes',
  'organizer',
]);

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).filter((k) => k !== 'sig').sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
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
  const raw = JSON.stringify(msg);
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

function openSlots(startIso, endIso, busy) {
  const start = Date.parse(startIso);
  const end = Date.parse(endIso);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null;
  const clipped = [];
  for (const b of busy) {
    const s = Date.parse(b.start);
    const e = Date.parse(b.end);
    if (!Number.isFinite(s) || !Number.isFinite(e)) continue;
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
  if (openSlots(start, end, []) === null) throw new Error('bad window');
  const msg = buildMessage(p, c.id, 'fb.req', { start, end });
  return writeMessage(outbox, msg);
}

function requestField(dir, toName, field, outbox) {
  if (!/^[A-Za-z][A-Za-z0-9]{0,40}$/.test(field || '')) throw new Error('bad field name');
  if (field === 'freebusy') throw new Error('freebusy is already the default field');
  const p = loadPassport(dir);
  const c = contactByName(p, toName);
  const msg = buildMessage(p, c.id, 'field.req', { field });
  appendLog(dir, { who: c.id, field, scope: null, decision: 'request', request: msg.id });
  return writeMessage(outbox, msg);
}

function replyFreeBusy(p, msg, inbox) {
  const busy = instantsOnly(p.dir);
  let d;
  if (!busy) d = { req: msg.id, decline: 'no_calendar' };
  else {
    const open = openSlots(msg.d && msg.d.start, msg.d && msg.d.end, busy);
    if (!open) d = { req: msg.id, decline: 'bad_window' };
    else d = { req: msg.id, open };
  }
  return writeMessage(inbox, buildMessage(p, msg.from, 'fb.res', d));
}

function queueField(p, msg) {
  const field = msg.d && msg.d.field;
  if (typeof field !== 'string') throw new Error('bad field request');
  if (p.passport.decided.some((d) => d.request === msg.id)) return 'already-decided';
  if (p.passport.pending.some((d) => d.request === msg.id)) return 'already-pending';
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

function poll(dir, inbox) {
  const p = loadPassport(dir);
  p.passport.lastInbox = path.resolve(inbox);
  const names = fs.existsSync(inbox)
    ? fs.readdirSync(inbox).filter((f) => f.endsWith('.json')).sort()
    : [];
  const actions = [];
  for (const name of names) {
    let msg;
    try {
      msg = JSON.parse(fs.readFileSync(path.join(inbox, name), 'utf8'));
    } catch {
      actions.push('skip unreadable ' + name);
      continue;
    }
    if (!msg || msg.to !== p.passport.publicId) continue;
    if (p.passport.processed.includes(msg.id)) continue;
    if (!verifyMessage(msg)) {
      actions.push('skip bad-sig ' + (msg.id || name));
      continue;
    }
    if (!p.passport.contacts.some((c) => c.id === msg.from)) {
      p.passport.processed.push(msg.id);
      actions.push('skip unknown ' + msg.id);
      continue;
    }
    if (msg.t === 'fb.req') {
      const file = replyFreeBusy(p, msg, inbox);
      actions.push('replied ' + msg.id + ' ' + path.basename(file));
    } else if (msg.t === 'field.req') {
      const status = queueField(p, msg);
      actions.push('field ' + status + ' ' + msg.id);
    } else if (msg.t === 'field.dec') {
      const decision = msg.d && msg.d.decision;
      if (decision !== 'allow' && decision !== 'deny') throw new Error('bad decision');
      appendLog(p.dir, {
        who: msg.from,
        field: msg.d.field,
        scope: msg.d.scope ?? null,
        decision,
        request: msg.d.req,
      });
      actions.push('learned ' + decision + ' ' + msg.d.req);
    } else if (msg.t === 'fb.res') {
      actions.push('reply ' + msg.id);
    } else {
      actions.push('ignore ' + msg.t);
    }
    p.passport.processed.push(msg.id);
  }
  savePassport(p);
  return actions;
}

function pending(dir) {
  const p = loadPassport(dir);
  return p.passport.pending.map((item) => {
    const c = p.passport.contacts.find((x) => x.id === item.who);
    return item.request + ' field=' + item.field + ' who=' + item.who + ' name=' + (c ? c.name : '?');
  });
}

function decide(dir, request, choice) {
  const p = loadPassport(dir);
  const prior = p.passport.decided.find((d) => d.request === request);
  if (prior && prior.decision === 'deny') throw new Error('denial is final for ' + request);
  if (prior) throw new Error('already decided ' + request);
  const item = p.passport.pending.find((d) => d.request === request);
  if (!item) throw new Error('no pending request ' + request);
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
  loadPassport,
};
