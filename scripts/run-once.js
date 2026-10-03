'use strict';
const fs = require('node:fs');
const path = require('node:path');
const proto = require('../src/protocol');

const root = path.resolve(__dirname, '..');
const momo = path.join(root, 'data', 'momo');
const claude = path.join(root, 'data', 'claude');
const inbox = path.join(root, 'inbox');
fs.mkdirSync(inbox, { recursive: true });

console.log(proto.init('momo', momo));
console.log(proto.init('claude', claude));
const momoId = proto.loadPassport(momo).passport.publicId;
const claudeId = proto.loadPassport(claude).passport.publicId;
proto.addContact(momo, 'claude', claudeId);
proto.addContact(claude, 'momo', momoId);
console.log('seed', proto.seedCalendar(claude));
const req = proto.askFreeBusy(momo, 'claude', '2026-10-05T13:00:00.000Z', '2026-10-05T17:00:00.000Z', inbox);
console.log('asked', path.basename(req));
console.log(proto.poll(claude, inbox).join('\n'));
const files = fs.readdirSync(inbox).filter(f => f.endsWith('.json'));
let leaked = false;
let reply = null;
for (const f of files) {
  const raw = fs.readFileSync(path.join(inbox, f), 'utf8');
  if (raw.toLowerCase().includes('secret')) leaked = true;
  const msg = JSON.parse(raw);
  if (msg.payload && msg.payload.type === 'fb.res') reply = msg.payload;
}
if (leaked) {
  console.log('FAIL leak');
  process.exit(1);
}
console.log('reply', JSON.stringify(reply));
console.log('PASS no title leak');
