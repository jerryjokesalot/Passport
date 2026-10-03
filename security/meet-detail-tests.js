'use strict';
// Signed calendar details on meet.confirm. Throwaway passports only.
// Usage: node security/meet-detail-tests.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createPrivateKey, createPublicKey, sign, verify, randomBytes } = require('node:crypto');
const proto = require(path.resolve(__dirname, '..', 'src', 'protocol.js'));

const cliPath = path.resolve(__dirname, '..', 'src', 'cli.js');
const START = '2026-10-08T15:00:00.000Z';
const END = '2026-10-08T16:00:00.000Z';
const START2 = '2026-10-09T15:00:00.000Z';
const END2 = '2026-10-09T16:00:00.000Z';
const URL = 'https://meet.google.com/abc-defg-hij';
const URL2 = 'https://meet.google.com/zzz-zzzz-zzz';
const TITLE = 'Plan review';
const DESC = 'Bring the notes';
const HIDDEN = 'Hidden dentist notes';

let failed = 0;
function check(name, ok, detail) {
  if (!ok) failed++;
  console.log((ok ? 'PASS' : 'FAIL') + ' ' + name + (detail ? ' -- ' + detail : ''));
}
function cli(args) {
  return execFileSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' }).replace(/\r/g, '').trim();
}
function cliFail(args) {
  try { cli(args); return ''; } catch (e) { return String(e.stderr || e.message || '').replace(/\r/g, ''); }
}
function canon(v, top) {
  if (top === undefined) top = true;
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => canon(x, false)).join(',') + ']';
  const keys = Object.keys(v).filter((k) => !(top && k === 'sig')).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(v[k], false)).join(',') + '}';
}
function sigOk(msg) {
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: msg.from.slice('ed25519:'.length) }, format: 'jwk' });
    return verify(null, Buffer.from(canon(msg)), key, Buffer.from(msg.sig, 'base64url'));
  } catch (e) { return false; }
}
function forge(env, who, fields) {
  const key = createPrivateKey({ key: JSON.parse(fs.readFileSync(path.join(env[who], 'key.json'), 'utf8')), format: 'jwk' });
  const msg = Object.assign({ v: 1, id: randomBytes(12).toString('base64url'), from: env.id(who), to: env.id('momo'), ts: new Date().toISOString() }, fields);
  delete msg.sig;
  msg.sig = sign(null, Buffer.from(canon(msg)), key).toString('base64url');
  return msg;
}
function readMsgs(dir) {
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
}
function setup() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-detail-'));
  const env = { base, claude: path.join(base, 'claude'), momo: path.join(base, 'momo'), momoOut: path.join(base, 'momo-out'), claudeOut: path.join(base, 'claude-out'), detailOut: path.join(base, 'detail-out'), inbox: path.join(base, 'inbox') };
  fs.mkdirSync(env.momoOut, { recursive: true });
  fs.mkdirSync(env.claudeOut, { recursive: true });
  fs.mkdirSync(env.detailOut, { recursive: true });
  fs.mkdirSync(env.inbox, { recursive: true });
  proto.init('claude', env.claude);
  proto.init('momo', env.momo);
  env.id = (w) => proto.loadPassport(env[w]).passport.publicId;
  proto.addContact(env.claude, 'momo', env.id('momo'));
  proto.addContact(env.momo, 'claude', env.id('claude'));
  proto.seedCalendar(env.claude);
  return env;
}
function cleanup(env) { fs.rmSync(env.base, { recursive: true, force: true }); }
function run(label, fn) {
  const env = setup();
  try { fn(env); } catch (e) { check(label + ' crashed', false, String(e && e.stack || e).slice(0, 400)); } finally { cleanup(env); }
}

function grant(env, field, how) {
  cli(['request-field', '--dir', env.momo, '--to', 'claude', '--field', field, '--outbox', env.inbox]);
  cli(['poll', '--dir', env.claude, '--inbox', env.inbox]);
  const line = cli(['pending', '--dir', env.claude]).split('\n').filter(Boolean).reverse().find((l) => l.indexOf('field=' + field + ' ') >= 0);
  if (!line) throw new Error('no pending ' + field);
  const id = line.split(' ')[0];
  if (how === 'deny') cli(['decide', '--dir', env.claude, '--request', id, '--deny']);
  else if (how === 'timed') cli(['decide', '--dir', env.claude, '--request', id, '--allow', 'timed', '--hours', '2']);
  else if (how === 'once') cli(['decide', '--dir', env.claude, '--request', id, '--allow', 'once']);
  else cli(['decide', '--dir', env.claude, '--request', id, '--allow', 'permanent']);
}
function yesMeet(env, start, end) {
  const propFile = cli(['propose-meet', '--dir', env.momo, '--to', 'claude', '--from', start, '--to-time', end, '--outbox', env.momoOut]);
  const prop = JSON.parse(fs.readFileSync(propFile, 'utf8'));
  cli(['poll', '--dir', env.claude, '--inbox', env.momoOut]);
  cli(['decide-meet', '--dir', env.claude, '--request', prop.id, '--yes', '--outbox', env.claudeOut]);
  cli(['poll', '--dir', env.momo, '--inbox', env.claudeOut]);
  return prop;
}
function confirms(dir) {
  return readMsgs(dir).filter((m) => m.t === 'meet.confirm');
}
function fieldOf(msg, name) {
  return msg.d.fields.filter((f) => f.field === name);
}
function wireKeys(msg) {
  const acc = [];
  const walk = (v) => {
    if (!v || typeof v !== 'object') return;
    for (const k of Object.keys(v)) { acc.push(k); walk(v[k]); }
  };
  walk(msg);
  return acc;
}

run('granted details', (env) => {
  grant(env, 'eventTitle');
  grant(env, 'eventDescription');
  grant(env, 'meetUrl');
  const prop = yesMeet(env, START, END);
  const other = cliFail(['confirm-meet', '--dir', env.momo, '--request', prop.id, '--meet-url', URL2, '--outbox', env.momoOut]);
  check('proposer cannot set the meet url', other.indexOf('only the confirming side') >= 0 && confirms(env.momoOut).length === 0, other.trim());
  const recFile = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--title', TITLE, '--description', DESC, '--meet-url', URL, '--outbox', env.detailOut]);
  const signed = confirms(env.detailOut);
  const msg = signed[0];
  const banned = ['title', 'summary', 'description', 'notes', 'note', 'location', 'attendees', 'organizer', 'body'];
  const leaked = wireKeys(msg).filter((k) => banned.indexOf(k) >= 0);
  const titleF = fieldOf(msg, 'eventTitle')[0];
  const descF = fieldOf(msg, 'eventDescription')[0];
  const urlF = fieldOf(msg, 'meetUrl')[0];
  const bodyKeys = Object.keys(msg.d).sort().join();
  check('signed confirm carries the three granted values', signed.length === 1 && msg.t === 'meet.confirm' && msg.from === env.id('claude') && msg.to === env.id('momo') && sigOk(msg) && bodyKeys === 'fields,req' && msg.d.req === prop.id && titleF.value === TITLE && descF.value === DESC && urlF.value === URL && leaked.length === 0, bodyKeys + ' leaked=' + leaked.join(','));
  check('local log does not copy the title or description', proto.readLog(env.claude).indexOf(TITLE) < 0 && proto.readLog(env.claude).indexOf(DESC) < 0);
  const learned = cli(['poll', '--dir', env.momo, '--inbox', env.detailOut]);
  const meeting = proto.loadPassport(env.momo).passport.meetings.filter((m) => m.request === prop.id && m.role === 'out')[0];
  check('other side copies the exact url', learned.indexOf('copied meetUrl ' + prop.id) >= 0 && meeting && meeting.meetUrl === URL && meeting.meetUrl.length === URL.length, learned + ' copied=' + (meeting && meeting.meetUrl));
  const printed = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google']);
  const payload = JSON.parse(printed);
  const expected = { start: START, end: END, summary: TITLE, timeZone: 'America/New_York', description: DESC, meetUrl: URL };
  check('google outbox includes granted fields', printed === JSON.stringify(expected) && payload.summary === TITLE && payload.description === DESC && payload.meetUrl === URL, printed);
  const rec = JSON.parse(fs.readFileSync(recFile, 'utf8')).proposals[0];
  check('local record keeps the granted values for the outbox', rec.status === 'confirmed' && rec.shared.eventTitle === TITLE && rec.shared.meetUrl === URL && !('title' in rec));
});

run('missing grant omits the value', (env) => {
  grant(env, 'eventTitle');
  grant(env, 'meetUrl');
  const prop = yesMeet(env, START, END);
  cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--title', TITLE, '--description', HIDDEN, '--meet-url', URL, '--outbox', env.detailOut]);
  const msg = confirms(env.detailOut)[0];
  const descF = fieldOf(msg, 'eventDescription')[0];
  const raw = JSON.stringify(msg);
  check('dead description is a deny with no value', sigOk(msg) && descF && descF.decision === 'deny' && !('value' in descF) && raw.indexOf(HIDDEN) < 0 && fieldOf(msg, 'eventTitle')[0].value === TITLE && fieldOf(msg, 'meetUrl')[0].value === URL, JSON.stringify(msg.d.fields));
  const printed = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google', '--description', HIDDEN]);
  const payload = JSON.parse(printed);
  const expected = { start: START, end: END, summary: TITLE, timeZone: 'America/New_York', meetUrl: URL };
  check('outbox omits the ungranted description', printed === JSON.stringify(expected) && !('description' in payload) && printed.indexOf(HIDDEN) < 0 && payload.summary === TITLE && payload.meetUrl === URL, printed);
});

run('later deny wins', (env) => {
  grant(env, 'eventTitle');
  grant(env, 'eventTitle', 'deny');
  grant(env, 'eventDescription');
  const prop = yesMeet(env, START, END);
  cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--title', HIDDEN, '--description', DESC, '--meet-url', URL, '--outbox', env.detailOut]);
  const msg = confirms(env.detailOut)[0];
  const titleF = fieldOf(msg, 'eventTitle')[0];
  const raw = JSON.stringify(msg);
  check('later deny keeps the title off the signed confirm', titleF.decision === 'deny' && !('value' in titleF) && raw.indexOf(HIDDEN) < 0 && fieldOf(msg, 'meetUrl')[0].decision === 'deny' && fieldOf(msg, 'eventDescription')[0].value === DESC, JSON.stringify(msg.d.fields));
  const printed = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google']);
  const payload = JSON.parse(printed);
  const expected = { start: START, end: END, summary: 'Hold', timeZone: 'America/New_York', description: DESC };
  check('later deny leaves summary Hold and omits the url', printed === JSON.stringify(expected) && payload.summary === 'Hold' && !('meetUrl' in payload) && printed.indexOf(HIDDEN) < 0 && printed.indexOf(URL) < 0, printed);
});

run('once title is spent', (env) => {
  grant(env, 'eventTitle', 'once');
  const first = yesMeet(env, START, END);
  cli(['confirm-meet', '--dir', env.claude, '--request', first.id, '--title', TITLE, '--outbox', env.detailOut]);
  const grantRow = proto.loadPassport(env.claude).passport.grants.filter((g) => g.field === 'eventTitle')[0];
  const msg = confirms(env.detailOut)[0];
  check('once grant puts the title on the first confirm', fieldOf(msg, 'eventTitle')[0].value === TITLE && grantRow.remaining === 0 && grantRow.consumedRequest === first.id);
  const second = yesMeet(env, START2, END2);
  const again = path.join(env.base, 'again');
  fs.mkdirSync(again);
  cli(['confirm-meet', '--dir', env.claude, '--request', second.id, '--title', HIDDEN, '--outbox', again]);
  const msg2 = confirms(again)[0];
  const titleF = fieldOf(msg2, 'eventTitle')[0];
  check('spent once grant omits the next title', titleF.decision === 'deny' && !('value' in titleF) && JSON.stringify(msg2).indexOf(HIDDEN) < 0, JSON.stringify(titleF));
  const printed = cli(['confirm-meet', '--dir', env.claude, '--request', second.id, '--google', '--title', HIDDEN]);
  check('spent once grant keeps summary Hold', JSON.parse(printed).summary === 'Hold' && printed.indexOf(HIDDEN) < 0, printed);
});

run('forged or note-bearing confirm is rejected', (env) => {
  grant(env, 'eventTitle');
  grant(env, 'eventDescription');
  grant(env, 'meetUrl');
  const prop = yesMeet(env, START, END);
  cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--title', TITLE, '--description', DESC, '--meet-url', URL, '--outbox', env.detailOut]);
  cli(['poll', '--dir', env.momo, '--inbox', env.detailOut]);
  const tamperedDir = path.join(env.base, 'tamper');
  fs.mkdirSync(tamperedDir);
  const tampered = JSON.parse(JSON.stringify(confirms(env.detailOut)[0]));
  tampered.d.fields.filter((f) => f.field === 'meetUrl')[0].value = URL2;
  fs.writeFileSync(path.join(tamperedDir, tampered.id + '.json'), JSON.stringify(tampered) + '\n');
  const notedDir = path.join(env.base, 'noted');
  fs.mkdirSync(notedDir);
  const noted = forge(env, 'claude', { t: 'meet.confirm', d: { req: prop.id, fields: [{ field: 'meetUrl', value: URL2 }], note: 'hello there' } });
  fs.writeFileSync(path.join(notedDir, noted.id + '.json'), JSON.stringify(noted) + '\n');
  const extra = forge(env, 'claude', { t: 'meet.confirm', d: { req: prop.id, fields: [{ field: 'meetUrl', value: URL2, note: 'x' }] } });
  fs.writeFileSync(path.join(notedDir, extra.id + '.json'), JSON.stringify(extra) + '\n');
  const good = forge(env, 'claude', { t: 'fb.req', to: env.id('momo'), d: { start: '2026-10-08T13:00:00.000Z', end: '2026-10-08T17:00:00.000Z' } });
  fs.writeFileSync(path.join(notedDir, good.id + '.json'), JSON.stringify(good) + '\n');
  const badSig = cli(['poll', '--dir', env.momo, '--inbox', tamperedDir]);
  const rejected = cli(['poll', '--dir', env.momo, '--inbox', notedDir]);
  const meeting = proto.loadPassport(env.momo).passport.meetings.filter((m) => m.request === prop.id && m.role === 'out')[0];
  const replies = readMsgs(notedDir).filter((m) => m.t === 'fb.res');
  check('tampered url is rejected and the copy stays', badSig.indexOf('skip bad-sig') >= 0 && meeting.meetUrl === URL, badSig + ' url=' + meeting.meetUrl);
  check('note-bearing confirm is rejected and does not jam the inbox', rejected.indexOf('reject bad_confirm') >= 0 && replies.length === 1 && meeting.meetUrl === URL, rejected);
});

console.log(failed ? failed + ' failed' : 'all detail checks passed');
process.exit(failed ? 1 : 0);
