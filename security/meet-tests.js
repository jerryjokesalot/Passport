'use strict';
// Meeting round-trip checks. Throwaway passports only; never touches live keys.
// Usage: node security/meet-tests.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createPrivateKey, createPublicKey, sign, verify, randomBytes } = require('node:crypto');
const proto = require(path.resolve(__dirname, '..', 'src', 'protocol.js'));

const cliPath = path.resolve(__dirname, '..', 'src', 'cli.js');
const START = '2026-10-06T15:00:00.000Z';
const END = '2026-10-06T16:00:00.000Z';
const CSTART = '2026-10-07T15:00:00.000Z';
const CEND = '2026-10-07T16:00:00.000Z';
const BANNED = ['title', 'attendees', 'location', 'summary', 'description', 'notes', 'note', 'organizer', 'body'];

let failed = 0;
function check(name, ok, detail) {
  if (!ok) failed++;
  console.log((ok ? 'PASS' : 'FAIL') + ' ' + name + (detail ? ' -- ' + detail : ''));
}

function cli(args) {
  return execFileSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' }).replace(/\r/g, '').trim();
}
function cliFail(args) {
  try {
    cli(args);
    return '';
  } catch (e) {
    return String(e.stderr || e.message || '').replace(/\r/g, '');
  }
}

function canon(v, top = true) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => canon(x, false)).join(',') + ']';
  const keys = Object.keys(v).filter((k) => !(top && k === 'sig')).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(v[k], false)).join(',') + '}';
}
function sigOk(msg) {
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: msg.from.slice('ed25519:'.length) }, format: 'jwk' });
    return verify(null, Buffer.from(canon(msg)), key, Buffer.from(msg.sig, 'base64url'));
  } catch {
    return false;
  }
}
function keysOf(v, acc) {
  if (!v || typeof v !== 'object') return acc;
  for (const k of Object.keys(v)) {
    acc.push(k);
    keysOf(v[k], acc);
  }
  return acc;
}
function forge(env, who, fields) {
  const key = createPrivateKey({ key: JSON.parse(fs.readFileSync(path.join(env[who], 'key.json'), 'utf8')), format: 'jwk' });
  const msg = Object.assign({
    v: 1,
    id: randomBytes(12).toString('base64url'),
    from: env.id(who),
    to: env.id('claude'),
    ts: new Date().toISOString(),
  }, fields);
  delete msg.sig;
  msg.sig = sign(null, Buffer.from(canon(msg)), key).toString('base64url');
  return msg;
}
function drop(dir, msg) {
  fs.writeFileSync(path.join(dir, msg.id + '.json'), JSON.stringify(msg) + '\n');
}
function readMsgs(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
}
function decisions(dir) {
  return proto.readLog(dir).split('\n').filter(Boolean).map((l) => JSON.parse(l).decision);
}
function names(dir) {
  return fs.readdirSync(dir).filter((f) => !f.endsWith('.tmp')).sort();
}

function setup() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-meet-'));
  const env = {
    base,
    claude: path.join(base, 'claude'),
    momo: path.join(base, 'momo'),
    eve: path.join(base, 'eve'),
    momoOut: path.join(base, 'momo-out'),
    claudeOut: path.join(base, 'claude-out'),
    inbox: path.join(base, 'inbox'),
  };
  fs.mkdirSync(env.momoOut, { recursive: true });
  fs.mkdirSync(env.claudeOut, { recursive: true });
  fs.mkdirSync(env.inbox, { recursive: true });
  for (const who of ['claude', 'momo', 'eve']) proto.init(who, env[who]);
  env.id = (w) => proto.loadPassport(env[w]).passport.publicId;
  proto.addContact(env.claude, 'momo', env.id('momo'));
  proto.addContact(env.momo, 'claude', env.id('claude'));
  proto.seedCalendar(env.claude);
  env.calendar = fs.readFileSync(path.join(env.claude, 'calendar.json'));
  return env;
}
function cleanup(env) {
  fs.rmSync(env.base, { recursive: true, force: true });
}
function run(label, fn) {
  const env = setup();
  try {
    fn(env);
  } catch (e) {
    check(label + ' crashed', false, String(e.message || e).slice(0, 180));
  } finally {
    cleanup(env);
  }
}

run('proposal and confirm', (env) => {
  const unknown = cliFail(['propose-meet', '--dir', env.momo, '--to', 'nope', '--from', START, '--to-time', END, '--outbox', env.momoOut]);
  check('proposal requires a known contact', unknown.includes('unknown contact'), unknown.trim());
  const tooWide = cliFail(['propose-meet', '--dir', env.momo, '--to', 'claude', '--from', '2026-10-01T00:00:00.000Z', '--to-time', '2026-10-20T00:00:00.000Z', '--outbox', env.momoOut]);
  check('proposal window stays inside 14 days', tooWide.includes('14 days') && readMsgs(env.momoOut).length === 0, tooWide.trim());

  const propFile = cli(['propose-meet', '--dir', env.momo, '--to', 'claude', '--from', START, '--to-time', END, '--outbox', env.momoOut]);
  const prop = JSON.parse(fs.readFileSync(propFile, 'utf8'));
  const bodyKeys = Object.keys(prop.d).sort();
  const slotKeys = Object.keys(prop.d.slot || {}).sort();
  const leaked = keysOf(prop, []).filter((k) => BANNED.includes(k));
  check('proposal contains only the slot', bodyKeys.length === 1 && bodyKeys[0] === 'slot' && slotKeys.join() === 'end,start' && prop.d.slot.start === START && prop.d.slot.end === END && leaked.length === 0, 'body=' + bodyKeys.join(',') + ' slot=' + slotKeys.join(',') + ' leaked=' + leaked.join(','));
  check('proposal is signed to the contact', prop.t === 'meet.prop' && prop.to === env.id('claude') && prop.from === env.id('momo') && sigOk(prop) && !/[A-Za-z]{3,}\s+[A-Za-z]{3,}/.test(JSON.stringify(prop)));
  check('proposal is logged locally', decisions(env.momo).includes('propose'));

  const polled = cli(['poll', '--dir', env.claude, '--inbox', env.momoOut]);
  check('poll queues the proposal and does not auto-accept', polled.includes('meet queued ' + prop.id) && readMsgs(env.momoOut).every((m) => m.t !== 'meet.res'), polled);
  const pending = cli(['pending', '--dir', env.claude]);
  check('pending lists the proposal', pending.includes(prop.id) && pending.includes('field=meet') && pending.includes(START) && pending.includes(END), pending);
  const refused = cliFail(['decide', '--dir', env.claude, '--request', prop.id, '--allow', 'permanent']);
  check('field decide cannot accept a meeting', refused.includes('use decide-meet') && cli(['pending', '--dir', env.claude]).includes(prop.id), refused.trim());

  const beforeYes = names(env.claude);
  const yesFile = cli(['decide-meet', '--dir', env.claude, '--request', prop.id, '--yes', '--outbox', env.claudeOut]);
  const yes = JSON.parse(fs.readFileSync(yesFile, 'utf8'));
  const yesKeys = Object.keys(yes.d).sort();
  check('yes is only the decision', yes.t === 'meet.res' && yesKeys.join() === 'decision,req' && yes.d.decision === 'yes' && yes.d.req === prop.id && sigOk(yes) && keysOf(yes, []).filter((k) => BANNED.includes(k)).length === 0, yesKeys.join(','));
  check('yes does not create an event', !fs.existsSync(path.join(env.claude, 'proposals.json')) && !fs.existsSync(path.join(env.momo, 'proposals.json')) && names(env.claude).join() === beforeYes.join() && fs.readFileSync(path.join(env.claude, 'calendar.json')).equals(env.calendar), names(env.claude).join(','));
  check('yes is logged on the responder only as a decision', decisions(env.claude).includes('yes') && !decisions(env.claude).includes('confirm'));

  const learned = cli(['poll', '--dir', env.momo, '--inbox', env.claudeOut]);
  check('proposer learns the decision only', learned.includes('learned yes ' + prop.id) && !fs.existsSync(path.join(env.momo, 'proposals.json')) && !decisions(env.momo).includes('confirm'), learned);

  cli(['request-field', '--dir', env.momo, '--to', 'claude', '--field', 'eventTitle', '--outbox', env.inbox]);
  cli(['poll', '--dir', env.claude, '--inbox', env.inbox]);
  const fieldLine = cli(['pending', '--dir', env.claude]).split('\n').find((l) => l.includes('field=eventTitle'));
  cli(['decide', '--dir', env.claude, '--request', fieldLine.split(' ')[0], '--allow', 'permanent']);
  const grant = proto.loadPassport(env.claude).passport.grants.find((g) => g.field === 'eventTitle');
  let earlyGoogle = '';
  try {
    proto.confirmMeet(env.claude, prop.id, { google: true });
  } catch (e) {
    earlyGoogle = String(e.message || e);
  }
  check('google create refuses until the proposal is confirmed locally', earlyGoogle.includes('not confirmed locally') && !fs.existsSync(path.join(env.claude, 'proposals.json')), earlyGoogle.trim());

  const outBefore = names(env.claudeOut);
  const recFile = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id]);
  const doc = JSON.parse(fs.readFileSync(recFile, 'utf8'));
  const record = doc.proposals[0];
  const recKeys = Object.keys(record).sort();
  const secret = JSON.parse(env.calendar.toString('utf8')).busy[0].title;
  check('confirm writes a local record with no title', grant && grant.scope === 'permanent' && doc.proposals.length === 1 && recKeys.join() === 'request,slot,status,who' && record.status === 'confirmed' && record.request === prop.id && record.slot.start === START && record.slot.end === END && !('title' in record) && !JSON.stringify(doc).includes(secret) && names(env.claudeOut).join() === outBefore.join(), recKeys.join(','));
  check('confirm does not write a calendar event', fs.readFileSync(path.join(env.claude, 'calendar.json')).equals(env.calendar) && names(env.claude).join() === 'calendar.json,key.json,log.jsonl,passport.json,proposals.json' && !fs.existsSync(path.join(env.momo, 'proposals.json')));
  check('confirm is logged locally and not sent', decisions(env.claude).includes('confirm') && !decisions(env.momo).includes('confirm') && readMsgs(env.claudeOut).every((m) => m.t !== 'meet.confirm'));
  check('default confirm has no googleReady', !('googleReady' in record) && !('googleCreated' in record) && !('title' in record) && !('googleEvent' in record));
  const notReady = cliFail(['mark-created', '--dir', env.claude, '--request', prop.id, '--event', 'evt_test_1']);
  check('mark-created refuses before google is ready', notReady.includes('google not ready') && !fs.existsSync(path.join(env.claude, 'google-outbox.json')), notReady.trim());
  const planted = JSON.parse(fs.readFileSync(recFile, 'utf8'));
  planted.proposals[0].googleEvent = 'pending';
  fs.writeFileSync(recFile, JSON.stringify(planted, null, 2) + '\n');
  const expected = { start: START, end: END, summary: 'Hold', timeZone: 'America/New_York' };
  const printed = cli(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google']);
  const payload = JSON.parse(printed);
  const payloadKeys = Object.keys(payload).sort();
  const outPath = path.join(env.claude, 'google-outbox.json');
  const outRaw = fs.readFileSync(outPath, 'utf8');
  const outDoc = JSON.parse(outRaw);
  check('confirm-meet --google prints the hold payload', printed === JSON.stringify(expected) && payloadKeys.join() === 'end,start,summary,timeZone' && payload.start === START && payload.end === END && payload.summary === 'Hold' && payload.timeZone === 'America/New_York' && !('title' in payload) && !('attendees' in payload) && !('location' in payload) && !('description' in payload) && !printed.includes(secret), printed);
  check('google outbox is that one object', outRaw === printed + '\n' && !Array.isArray(outDoc) && Object.keys(outDoc).sort().join() === 'end,start,summary,timeZone' && outDoc.summary === 'Hold' && outDoc.timeZone === 'America/New_York' && outDoc.start === START && outDoc.end === END && !JSON.stringify(outDoc).includes(secret), outRaw.trim());
  const marked = JSON.parse(fs.readFileSync(recFile, 'utf8')).proposals[0];
  check('google flag sets ready without an event id', marked.status === 'confirmed' && marked.googleReady === true && marked.googleCreated === false && !('title' in marked) && !marked.eventId && !marked.googleEventId && marked.googleEvent === 'pending' && fs.readFileSync(path.join(env.claude, 'calendar.json')).equals(env.calendar));
  const outBeforeSecond = fs.readFileSync(outPath);
  const second = cliFail(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google']);
  const afterSecond = JSON.parse(fs.readFileSync(recFile, 'utf8')).proposals[0];
  check('second google create is refused', second.includes('already prepared') && afterSecond.googleCreated === false && !afterSecond.eventId && fs.readFileSync(outPath).equals(outBeforeSecond), second.trim());
  const markedOk = cli(['mark-created', '--dir', env.claude, '--request', prop.id, '--event', 'evt_test_1']);
  const created = JSON.parse(fs.readFileSync(recFile, 'utf8')).proposals[0];
  check('mark-created stores the event id', markedOk === 'ok' && created.googleReady === true && created.googleCreated === true && created.eventId === 'evt_test_1' && !('title' in created) && fs.readFileSync(path.join(env.claude, 'calendar.json')).equals(env.calendar) && fs.readFileSync(outPath).equals(outBeforeSecond), markedOk);
  const third = cliFail(['confirm-meet', '--dir', env.claude, '--request', prop.id, '--google']);
  const afterThird = JSON.parse(fs.readFileSync(recFile, 'utf8')).proposals[0];
  check('google create stays refused after the event id is recorded', third.includes('already prepared') && afterThird.googleCreated === true && afterThird.eventId === 'evt_test_1', third.trim());
});

run('counter', (env) => {
  const propFile = cli(['propose-meet', '--dir', env.momo, '--to', 'claude', '--from', START, '--to-time', END, '--outbox', env.momoOut]);
  const prop = JSON.parse(fs.readFileSync(propFile, 'utf8'));
  cli(['poll', '--dir', env.claude, '--inbox', env.momoOut]);
  const before = names(env.claude);
  const resFile = cli(['decide-meet', '--dir', env.claude, '--request', prop.id, '--counter', '--from', CSTART, '--to-time', CEND, '--outbox', env.claudeOut]);
  const res = JSON.parse(fs.readFileSync(resFile, 'utf8'));
  const keys = Object.keys(res.d).sort();
  const slotKeys = Object.keys(res.d.slot || {}).sort();
  check('counter carries a new slot and nothing else', res.t === 'meet.res' && res.d.decision === 'counter' && res.d.req === prop.id && keys.join() === 'decision,req,slot' && slotKeys.join() === 'end,start' && res.d.slot.start === CSTART && res.d.slot.end === CEND && keysOf(res, []).filter((k) => BANNED.includes(k)).length === 0 && sigOk(res), keys.join(','));
  const learned = cli(['poll', '--dir', env.momo, '--inbox', env.claudeOut]);
  const sent = proto.loadPassport(env.momo).passport.sent.find((s) => s.request === prop.id);
  check('counter is accepted for the proposal we sent', learned.includes('learned counter ' + prop.id) && sent && sent.answered === true && sent.decision === 'counter' && sent.counter.start === CSTART, learned);
  check('counter does not create an event', !fs.existsSync(path.join(env.claude, 'proposals.json')) && !fs.existsSync(path.join(env.momo, 'proposals.json')) && names(env.claude).join() === before.join() && fs.readFileSync(path.join(env.claude, 'calendar.json')).equals(env.calendar));
  const noYes = cliFail(['confirm-meet', '--dir', env.claude, '--request', prop.id]);
  check('counter cannot be confirmed into an event', noYes.includes('no yes') && !fs.existsSync(path.join(env.claude, 'proposals.json')), noYes.trim());
});

run('rejects', (env) => {
  drop(env.inbox, forge(env, 'momo', { t: 'meet.res', d: { req: 'never-asked', decision: 'yes' } }));
  const unsol = cli(['poll', '--dir', env.claude, '--inbox', env.inbox]);
  check('unsolicited yes is rejected', unsol.includes('reject unsolicited') && !fs.existsSync(path.join(env.claude, 'proposals.json')) && decisions(env.claude).includes('reject') && !decisions(env.claude).includes('yes'), unsol);

  const staleDir = path.join(env.base, 'stale');
  fs.mkdirSync(staleDir);
  drop(staleDir, forge(env, 'momo', { t: 'meet.res', ts: '2020-01-01T00:00:00.000Z', d: { req: 'old', decision: 'yes' } }));
  const stale = cli(['poll', '--dir', env.claude, '--inbox', staleDir]);
  check('stale response is rejected', stale.includes('reject stale') && !fs.existsSync(path.join(env.claude, 'proposals.json')), stale);

  const forgedDir = path.join(env.base, 'forged');
  fs.mkdirSync(forgedDir);
  const forged = forge(env, 'momo', { t: 'meet.res', d: { req: 'never-asked', decision: 'yes' } });
  forged.d.decision = 'no';
  drop(forgedDir, forged);
  const forgedOut = cli(['poll', '--dir', env.claude, '--inbox', forgedDir]);
  check('forged response is rejected', forgedOut.includes('skip bad-sig') && !cli(['pending', '--dir', env.claude]) && !fs.existsSync(path.join(env.claude, 'proposals.json')), forgedOut);

  const wrongDir = path.join(env.base, 'wrong');
  fs.mkdirSync(wrongDir);
  drop(wrongDir, forge(env, 'momo', { t: 'meet.res', to: env.id('eve'), d: { req: 'never-asked', decision: 'yes' } }));
  const wrong = cli(['poll', '--dir', env.claude, '--inbox', wrongDir]);
  check('wrong-passport response is ignored', wrong === 'idle' && !fs.existsSync(path.join(env.claude, 'proposals.json')), wrong);

  const strangerDir = path.join(env.base, 'stranger');
  fs.mkdirSync(strangerDir);
  drop(strangerDir, forge(env, 'eve', { t: 'meet.prop', d: { slot: { start: START, end: END } } }));
  const stranger = cli(['poll', '--dir', env.claude, '--inbox', strangerDir]);
  check('unknown contact proposal is not queued', stranger.includes('skip unknown') && !cli(['pending', '--dir', env.claude]), stranger);

  const noteDir = path.join(env.base, 'note');
  fs.mkdirSync(noteDir);
  drop(noteDir, forge(env, 'momo', { t: 'meet.prop', d: { slot: { start: START, end: END }, note: 'x' } }));
  const good = forge(env, 'momo', { t: 'fb.req', d: { start: '2026-10-05T13:00:00.000Z', end: '2026-10-05T17:00:00.000Z' } });
  drop(noteDir, good);
  const noted = cli(['poll', '--dir', env.claude, '--inbox', noteDir]);
  const replies = readMsgs(noteDir).filter((m) => m.t === 'fb.res');
  check('note on a proposal is rejected and does not jam the inbox', noted.includes('reject bad_meet') && replies.length === 1 && !cli(['pending', '--dir', env.claude]).includes('field=meet'), noted);
});

console.log(failed ? failed + ' failed' : 'all meet checks passed');
process.exit(failed ? 1 : 0);