'use strict';

const path = require('node:path');
const proto = require('./protocol');

function parseArgs(argv) {
  const positional = [];
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) opts[key] = true;
      else {
        opts[key] = next;
        i++;
      }
    } else positional.push(a);
  }
  return { positional, opts };
}

function need(opts, key) {
  if (opts[key] === undefined || opts[key] === true) throw new Error('missing --' + key);
  return opts[key];
}

function main() {
  const { positional, opts } = parseArgs(process.argv.slice(2));
  const cmd = positional[0];
  if (!cmd) throw new Error('usage: node src/cli.js <command>');

  if (cmd === 'init') {
    const name = positional[1];
    if (!name) throw new Error('init <name> [--dir <passportDir>]');
    const dir = opts.dir || path.join('data', name);
    process.stdout.write(proto.init(name, dir) + '\n');
    return;
  }

  const dir = need(opts, 'dir');
  if (cmd === 'id') {
    process.stdout.write(proto.loadPassport(dir).passport.publicId + '\n');
    return;
  }
  if (cmd === 'add-contact') {
    proto.addContact(dir, need(opts, 'name'), need(opts, 'id'));
    process.stdout.write('ok\n');
    return;
  }
  if (cmd === 'seed-calendar') {
    process.stdout.write(proto.seedCalendar(dir) + '\n');
    return;
  }
  if (cmd === 'ask-freebusy') {
    const file = proto.askFreeBusy(
      dir,
      need(opts, 'to'),
      need(opts, 'from'),
      need(opts, 'to-time'),
      need(opts, 'outbox')
    );
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'request-field') {
    const file = proto.requestField(dir, need(opts, 'to'), need(opts, 'field'), need(opts, 'outbox'));
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'poll') {
    const actions = proto.poll(dir, need(opts, 'inbox'));
    process.stdout.write((actions.length ? actions.join('\n') : 'idle') + '\n');
    return;
  }
  if (cmd === 'pending') {
    const lines = proto.pending(dir);
    process.stdout.write(lines.join('\n') + (lines.length ? '\n' : ''));
    return;
  }
  if (cmd === 'decide') {
    const file = proto.decide(dir, need(opts, 'request'), {
      allow: opts.allow === true ? '' : opts.allow || null,
      deny: Boolean(opts.deny),
      hours: opts.hours,
    });
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'share-field') {
    const explicit = Object.prototype.hasOwnProperty.call(opts, 'value') ? opts.value : undefined;
    const file = proto.shareField(dir, need(opts, 'to'), need(opts, 'field'), need(opts, 'outbox'), explicit);
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'propose-meet') {
    const file = proto.proposeMeet(
      dir,
      need(opts, 'to'),
      need(opts, 'from'),
      need(opts, 'to-time'),
      need(opts, 'outbox')
    );
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'decide-meet') {
    const file = proto.decideMeet(dir, need(opts, 'request'), {
      yes: Boolean(opts.yes),
      no: Boolean(opts.no),
      counter: Boolean(opts.counter),
      from: opts.from === true ? undefined : opts.from,
      toTime: opts['to-time'] === true ? undefined : opts['to-time'],
    }, need(opts, 'outbox'));
    process.stdout.write(file + '\n');
    return;
  }
  if (cmd === 'confirm-meet') {
    const request = need(opts, 'request');
    const details = {};
    if (Object.prototype.hasOwnProperty.call(opts, 'title')) details.title = opts.title;
    if (Object.prototype.hasOwnProperty.call(opts, 'description')) details.description = opts.description;
    if (Object.prototype.hasOwnProperty.call(opts, 'meet-url')) details.meetUrl = opts['meet-url'];
    if (Object.prototype.hasOwnProperty.call(opts, 'outbox') && opts.outbox !== true) details.outbox = opts.outbox;
    if (opts.google === true) {
      const payload = proto.confirmMeet(dir, request, Object.assign({ google: true }, details));
      process.stdout.write(JSON.stringify(payload) + '\n');
      return;
    }
    process.stdout.write(proto.confirmMeet(dir, request, details) + '\n');
    return;
  }
  if (cmd === 'mark-created') {
    proto.markCreated(dir, need(opts, 'request'), need(opts, 'event'));
    process.stdout.write('ok\n');
    return;
  }
  if (cmd === 'log') {
    const text = proto.readLog(dir);
    process.stdout.write(text + (text ? '\n' : ''));
    return;
  }
  if (cmd === 'show') {
    process.stdout.write(proto.show(dir, need(opts, 'message')) + '\n');
    return;
  }
  throw new Error('unknown command ' + cmd);
}

try {
  main();
} catch (err) {
  process.stderr.write(String(err.message || err) + '\n');
  process.exit(1);
}
