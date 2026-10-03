'use strict';
// Attack suite for passport-alpha. Builds throwaway passports in a temp folder,
// runs each attack against src/protocol.js, and reports BLOCKED or VULNERABLE.
// Usage: node security/attack-tests.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPrivateKey, sign, randomBytes } = require('node:crypto');
const proto = require(path.resolve(__dirname, '..', 'src', 'protocol.js'));

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-attack-'));
let n = 0;
function fresh() {
  const base = path.join(root, 'r' + n++);
  const dirs = { claude: path.join(base, 'claude'), momo: path.join(base, 'momo'), eve: path.join(base, 'eve'), inbox: path.join(base, 'inbox') };
  fs.mkdirSync(dirs.inbox, { recursive: true });
  for (const who of ['claude', 'momo', 'eve']) proto.init(who, dirs[who]);
  const id = (w) => proto.loadPassport(dirs[w]).passport.publicId;
  proto.addContact(dirs.claude, 'momo', id('momo'));
  proto.addContact(dirs.momo, 'claude', id('claude'));
  proto.seedCalendar(dirs.claude);
  return { ...dirs, id };
}
// Top-level-only canonical form (identical to the original for messages with no nested "sig").
function canon(v, top = true) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => canon(x, false)).join(',') + ']';
  const keys = Object.keys(v).filter((k) => !(top && k === 'sig')).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(v[k], false)).join(',') + '}';
}
function forge(env, who, fields) {
  const key = createPrivateKey({ key: JSON.parse(fs.readFileSync(path.join(env[who], 'key.json'), 'utf8')), format: 'jwk' });
  const msg = Object.assign({ v: 1, id: randomBytes(12).toString('base64url'), from: env.id(who), to: env.id('claude'), ts: new Date().toISOString() }, fields);
  delete msg.sig;
  return Object.assign(msg, { sig: sign(null, Buffer.from(canon(msg)), key).toString('base64url') });
}
function drop(env, msg, name) {
  fs.writeFileSync(path.join(env.inbox, (name || msg.id) + '.json'), JSON.stringify(msg) + '\n');
}
function poll(env) {
  try { return { out: proto.poll(env.claude, env.inbox) }; } catch (e) { return { err: e.message }; }
}
const log = (env) => proto.readLog(env.claude);
const replies = (env) => fs.readdirSync(env.inbox).map((f) => JSON.parse(fs.readFileSync(path.join(env.inbox, f), 'utf8'))).filter((m) => m.t === 'fb.res' && m.from === env.id('claude'));

const results = [];
function attack(sev, name, fn) {
  let vulnerable, detail;
  try { [vulnerable, detail] = fn(); } catch (e) { vulnerable = true; detail = 'crashed: ' + e.message; }
  results.push({ sev, name, vulnerable, detail });
}

attack('high', 'Poison pill: malformed decision jams the inbox forever', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'field.dec', d: { req: 'x', field: 'eventTitle', decision: 'maybe' } }), '0-poison');
  const good = forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  drop(env, good, '1-good');
  const a = poll(env), b = poll(env);
  const jammed = Boolean(a.err && b.err) || replies(env).length === 0;
  return [jammed, jammed ? 'poll crashed twice; the legit request behind it never got answered' : 'bad message rejected, legit request answered'];
});

attack('high', 'Poison pill: malformed field request jams the inbox forever', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'field.req', d: { field: { evil: true } } }), '0-poison');
  drop(env, forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }), '1-good');
  const a = poll(env), b = poll(env);
  const jammed = Boolean(a.err && b.err) || replies(env).length === 0;
  return [jammed, jammed ? 'poll crashed twice' : 'bad message rejected, legit request answered'];
});

attack('high', 'Forged decision written into the audit log', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'field.dec', d: { req: 'never-asked', field: 'bankAccount', decision: 'allow', scope: 'permanent' } }));
  poll(env);
  const hit = log(env).includes('bankAccount');
  return [hit, hit ? 'log now says Claude was granted bankAccount for a request it never made' : 'unsolicited decision rejected, log untouched'];
});

attack('high', 'Stranger blocks a legit message by stealing its id', () => {
  const env = fresh();
  const legit = forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  const evil = forge(env, 'eve', { t: 'fb.req', id: legit.id, d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  drop(env, evil, '0-evil'); drop(env, legit, '1-legit');
  poll(env);
  const blocked = replies(env).length === 0;
  return [blocked, blocked ? "Momo's real request was silently skipped" : "Momo's request still answered"];
});

attack('medium', 'Calendar sweep: one request for a 100-year window', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'fb.req', d: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' } }));
  poll(env);
  const r = replies(env)[0];
  const swept = Boolean(r && r.d.open);
  return [swept, swept ? 'answered with every busy gap across 100 years' : 'declined: ' + (r ? r.d.decline : 'no reply')];
});

attack('medium', 'Tampering: extra "sig" fields hide inside a signed message', () => {
  const env = fresh();
  const m = forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  m.d.sig = 'injected-after-signing';
  drop(env, m);
  const out = poll(env).out || [];
  const accepted = out.some((l) => l.startsWith('replied'));
  return [accepted, accepted ? 'message altered after signing still passed verification' : 'altered message rejected'];
});

attack('medium', 'Stale replay: a message from 2020 is still honored', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'fb.req', ts: '2020-01-01T00:00:00.000Z', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }));
  poll(env);
  const ok = replies(env).length > 0 && !replies(env)[0].d.decline;
  return [ok, ok ? 'six-year-old message answered' : 'stale message rejected'];
});

attack('medium', 'Fail-open calendar: a garbled busy entry shows as free', () => {
  const env = fresh();
  fs.writeFileSync(path.join(env.claude, 'calendar.json'), JSON.stringify({ busy: [{ start: 'next tuesday', end: 'later', title: 'board meeting' }] }));
  drop(env, forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }));
  poll(env);
  const r = replies(env)[0];
  const open = Boolean(r && r.d.open && r.d.open.length);
  return [open, open ? 'reported the whole window as open' : 'declined: ' + (r ? r.d.decline : 'none')];
});

attack('medium', 'Audit gap: calendar answers leave no trace in the log', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }));
  poll(env);
  const empty = !log(env).includes('freebusy');
  return [empty, empty ? 'reply sent, log empty' : 'disclosure logged'];
});

attack('low', 'Flood: 200 field requests pile up for the human', () => {
  const env = fresh();
  for (let i = 0; i < 200; i++) drop(env, forge(env, 'momo', { t: 'field.req', d: { field: 'f' + i } }));
  poll(env);
  const q = proto.pending(env.claude).length;
  return [q > 25, q + ' requests queued'];
});

attack('low', 'Unsolicited reply accepted', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'fb.res', d: { req: 'never-asked', open: [] } }));
  const out = poll(env).out || [];
  const took = out.some((l) => l.startsWith('reply '));
  return [took, took ? 'reply to a request never sent was accepted' : 'rejected'];
});

// Controls: these should already be blocked.
attack('control', 'Forged signature (edited window)', () => {
  const env = fresh();
  const m = forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  m.d.end = '2026-10-09T17:00:00.000Z';
  drop(env, m); poll(env);
  return [replies(env).length > 0, 'edited message ' + (replies(env).length ? 'accepted' : 'rejected')];
});
attack('control', 'Stranger asks for free/busy', () => {
  const env = fresh();
  drop(env, forge(env, 'eve', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }));
  poll(env);
  return [replies(env).length > 0, 'stranger ' + (replies(env).length ? 'answered' : 'ignored')];
});
attack('control', 'Private calendar details leak into a reply', () => {
  const env = fresh();
  drop(env, forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } }));
  poll(env);
  const raw = JSON.stringify(replies(env));
  const leak = /dentist|secret|clinic|Suite/i.test(raw);
  return [leak, leak ? 'LEAKED' : 'only start/end times left the building'];
});

fs.rmSync(root, { recursive: true, force: true });
let vuln = 0;
for (const r of results) {
  if (r.vulnerable) vuln++;
  console.log((r.vulnerable ? 'VULNERABLE' : 'BLOCKED   ') + ' [' + r.sev + '] ' + r.name + ' -- ' + r.detail);
}
console.log('\n' + (results.length - vuln) + '/' + results.length + ' blocked');
process.exit(vuln ? 1 : 0);
