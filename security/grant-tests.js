'use strict';
// Grant enforcement checks. Throwaway passports only; never touches live keys.
// Usage: node security/grant-tests.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const proto = require(path.resolve(__dirname, '..', 'src', 'protocol.js'));

let failed = 0;
function check(name, ok, detail) {
  if (!ok) failed++;
  console.log((ok ? 'PASS' : 'FAIL') + ' ' + name + (detail ? ' -- ' + detail : ''));
}

function setup() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-grant-'));
  const env = {
    base,
    claude: path.join(base, 'claude'),
    momo: path.join(base, 'momo'),
    inbox: path.join(base, 'inbox'),
  };
  fs.mkdirSync(env.inbox, { recursive: true });
  proto.init('claude', env.claude);
  proto.init('momo', env.momo);
  env.id = (w) => proto.loadPassport(env[w]).passport.publicId;
  proto.addContact(env.claude, 'momo', env.id('momo'));
  proto.addContact(env.momo, 'claude', env.id('claude'));
  proto.seedCalendar(env.claude);
  return env;
}

function ask(env, field) {
  proto.requestField(env.momo, 'claude', field || 'eventTitle', env.inbox);
  proto.poll(env.claude, env.inbox);
  const lines = proto.pending(env.claude);
  if (!lines.length) throw new Error('nothing pending');
  return lines[lines.length - 1].split(' ')[0];
}

function shares(env) {
  return fs.readdirSync(env.inbox)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(env.inbox, f), 'utf8')))
    .filter((m) => m.t === 'field.share' && m.from === env.id('claude'))
    .sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : a.id < b.id ? -1 : 1));
}

function decisions(env) {
  return proto.readLog(env.claude).split('\n').filter(Boolean).map((l) => JSON.parse(l).decision);
}

function cleanup(env) {
  fs.rmSync(env.base, { recursive: true, force: true });
}

{
  const env = setup();
  const req = ask(env);
  proto.decide(env.claude, req, { allow: 'once', deny: false });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'OnceTitle');
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'OnceTitle');
  const s = shares(env);
  const valued = s.filter((m) => m.d.value === 'OnceTitle');
  const blocked = s.filter((m) => m.d.decision === 'deny' && !('value' in m.d));
  const grant = proto.loadPassport(env.claude).passport.grants[0];
  const logged = decisions(env);
  check('once spent: first share carries the value', valued.length === 1, 'valued=' + valued.length);
  check('once spent: further share blocked', blocked.length === 1 && s.length === 2, JSON.stringify(s.map((m) => m.d)));
  check('once spent: remaining is 0', grant && grant.remaining === 0, String(grant && grant.remaining));
  check('once spent: log records spend then spent', logged.includes('spend') && logged.includes('spent'), logged.join(','));
  check('once spent: wire does not say spent', !JSON.stringify(s).includes('spent') && !JSON.stringify(s).includes('remaining'));
  const req2 = ask(env);
  proto.decide(env.claude, req2, { allow: 'once', deny: false });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'OnceAgain');
  check('once spent: new human approval shares once more', shares(env).some((m) => m.d.value === 'OnceAgain'));
  cleanup(env);
}

{
  const env = setup();
  const req = ask(env);
  proto.decide(env.claude, req, { allow: 'timed', deny: false, hours: 2 });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'TimedLive');
  const pass = JSON.parse(fs.readFileSync(path.join(env.claude, 'passport.json'), 'utf8'));
  pass.grants[0].until = '2020-01-01T00:00:00.000Z';
  fs.writeFileSync(path.join(env.claude, 'passport.json'), JSON.stringify(pass, null, 2) + '\n');
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'TimedDead');
  const s = shares(env);
  const raw = JSON.stringify(s);
  check('timed: live grant shares', s.some((m) => m.d.value === 'TimedLive'));
  check('timed expired: value stays off the wire', s.some((m) => m.d.decision === 'deny' && !('value' in m.d)) && !raw.includes('TimedDead'));
  check('timed expired: expiry logged locally only', decisions(env).includes('expired') && !raw.includes('expired'), decisions(env).join(','));
  cleanup(env);
}

{
  const env = setup();
  const req = ask(env);
  proto.decide(env.claude, req, { deny: true, allow: null });
  let flipped = false;
  try {
    proto.decide(env.claude, req, { allow: 'permanent', deny: false });
    flipped = true;
  } catch {
    flipped = false;
  }
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'secret dentist');
  const s = shares(env);
  check('deny still blocks: denial is final', flipped === false);
  check('deny still blocks: field not shared', s.length === 1 && s[0].d.decision === 'deny' && !('value' in s[0].d) && !JSON.stringify(s[0]).includes('dentist'), JSON.stringify(s[0] && s[0].d));
  check('deny still blocks: log records deny', decisions(env).filter((d) => d === 'deny').length >= 1, decisions(env).join(','));
  const req2 = ask(env);
  proto.decide(env.claude, req2, { allow: 'permanent', deny: false });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'AfterLaterAllow');
  const req3 = ask(env);
  proto.decide(env.claude, req3, { deny: true, allow: null });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'AfterLaterDeny');
  const later = shares(env);
  check('deny still blocks: a later deny beats an older grant', later.some((m) => m.d.value === 'AfterLaterAllow') && later[later.length - 1].d.decision === 'deny' && !JSON.stringify(later[later.length - 1]).includes('AfterLaterDeny'));
  cleanup(env);
}

{
  const env = setup();
  const req = ask(env);
  proto.decide(env.claude, req, { allow: 'permanent', deny: false });
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox);
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox);
  const s = shares(env);
  const grant = proto.loadPassport(env.claude).passport.grants[0];
  check('permanent still allows: title shared twice', s.length === 2 && s.every((m) => m.d.value === 'secret dentist'), JSON.stringify(s.map((m) => m.d)));
  check('permanent still allows: grant is not spent', grant && grant.scope === 'permanent' && grant.remaining === null);
  check('permanent still allows: log does not copy the title', !proto.readLog(env.claude).includes('dentist'));
  proto.askFreeBusy(env.momo, 'claude', '2026-10-05T13:00:00.000Z', '2026-10-05T17:00:00.000Z', env.inbox);
  proto.poll(env.claude, env.inbox);
  const replies = fs.readdirSync(env.inbox)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(env.inbox, f), 'utf8')))
    .filter((m) => m.t === 'fb.res');
  const replyRaw = JSON.stringify(replies);
  check('freebusy stays title-free under a live eventTitle grant', replies.length === 1 && replies[0].d.open && !/dentist|secret|eventTitle|"title"/.test(replyRaw), replyRaw);
  cleanup(env);
}

{
  const env = setup();
  proto.requestField(env.momo, 'claude', 'eventTitle', env.inbox);
  proto.poll(env.claude, env.inbox);
  const before = proto.loadPassport(env.claude).passport.grants.length;
  proto.shareField(env.claude, 'momo', 'eventTitle', env.inbox, 'secret dentist');
  const s = shares(env);
  check('request does not grant', before === 0);
  check('ungranted field stays off the wire', s.length === 1 && s[0].d.decision === 'deny' && !JSON.stringify(s[0]).includes('dentist'), JSON.stringify(s[0] && s[0].d));
  cleanup(env);
}

console.log(failed ? failed + ' failed' : 'all grant checks passed');
process.exit(failed ? 1 : 0);
