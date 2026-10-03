'use strict';
const fs = require('node:fs');
const path = require('node:path');
const proto = require('../src/protocol');
const momo = 'C:\\Users\\heyje\\AppData\\Local\\passport-alpha\\momo';
const claude = 'C:\\Users\\heyje\\AppData\\Local\\passport-alpha\\claude';
const inbox = 'C:\\Users\\heyje\\OneDrive\\Desktop\\passport-alpha\\inbox';

const req = proto.requestField(momo, 'claude', 'eventTitle', inbox);
console.log('requested', path.basename(req));
const actions = proto.poll(claude, inbox);
console.log('poll', actions.join(' | ') || 'idle');
const pending = proto.pending(claude);
console.log('pending', pending.join(' | ') || 'none');
const idLine = pending[pending.length - 1] || '';
const id = idLine.split(/\s+/)[0];
if (!id) { console.log('FAIL no pending'); process.exit(1); }
console.log('decide', proto.decide(claude, id, { allow: 'once', deny: false }));
const first = proto.shareField(claude, 'momo', 'eventTitle', inbox);
const second = proto.shareField(claude, 'momo', 'eventTitle', inbox);
function body(file) {
  const msg = JSON.parse(fs.readFileSync(file, 'utf8'));
  return JSON.stringify(msg.d);
}
console.log('first', path.basename(first), body(first));
console.log('second', path.basename(second), body(second));
const a = JSON.parse(fs.readFileSync(first, 'utf8')).d;
const b = JSON.parse(fs.readFileSync(second, 'utf8')).d;
if (!a.value || a.value.indexOf('secret') === -1) { console.log('FAIL first share missing granted title'); process.exit(1); }
if (b.value || b.decision !== 'deny') { console.log('FAIL second share was not a bare deny'); process.exit(1); }
console.log('PASS once spent');
