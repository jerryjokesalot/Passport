'use strict';

const DETAIL_FIELDS = ['eventTitle', 'eventDescription', 'meetUrl'];
const DETAIL_SET = new Set(DETAIL_FIELDS);

function isMeetUrl(value) {
  const prefix = 'https://meet.google.com/';
  if (typeof value !== 'string' || !value.startsWith(prefix)) return false;
  const parts = value.slice(prefix.length).split('-');
  if (parts.length !== 3) return false;
  const lens = [3, 4, 3];
  for (let i = 0; i < 3; i++) {
    if (parts[i].length !== lens[i]) return false;
    for (const ch of parts[i]) {
      if (ch < 'a' || ch > 'z') return false;
    }
  }
  return true;
}

function detailInputs(opts) {
  if (!opts) return [];
  const out = [];
  if (Object.prototype.hasOwnProperty.call(opts, 'title')) {
    out.push({ field: 'eventTitle', raw: opts.title, outKey: 'summary' });
  }
  if (Object.prototype.hasOwnProperty.call(opts, 'description')) {
    out.push({ field: 'eventDescription', raw: opts.description, outKey: 'description' });
  }
  if (Object.prototype.hasOwnProperty.call(opts, 'meetUrl')) {
    out.push({ field: 'meetUrl', raw: opts.meetUrl, outKey: 'meetUrl' });
  }
  return out;
}

function cleanDetail(field, raw) {
  if (typeof raw !== 'string' || raw.length < 1 || raw.length > 500) throw new Error('bad value');
  if (field === 'meetUrl' && !isMeetUrl(raw)) throw new Error('bad meet url');
  return raw;
}

function grantAllows(verdict, request) {
  if (verdict && verdict.live) return { ok: true, replay: false };
  if (verdict && verdict.decision === 'spent' && verdict.grant && verdict.grant.consumedRequest === request) {
    return { ok: true, replay: true };
  }
  return { ok: false, replay: false };
}

function releaseDetails(verdictFor, request, opts, stored) {
  const inputs = detailInputs(opts);
  const parts = [];
  for (const item of inputs) {
    const verdict = verdictFor(item.field);
    const gate = grantAllows(verdict, request);
    if (!gate.ok) {
      parts.push({ field: item.field, denied: true, verdict: verdict });
      continue;
    }
    if (gate.replay) {
      const prev = stored && typeof stored[item.field] === 'string' ? stored[item.field] : null;
      if (prev === null) {
        parts.push({ field: item.field, denied: true, verdict: verdict });
        continue;
      }
      parts.push({ field: item.field, value: prev, outKey: item.outKey, denied: false, verdict: verdict, replay: true });
      continue;
    }
    const value = cleanDetail(item.field, item.raw);
    parts.push({ field: item.field, value: value, outKey: item.outKey, denied: false, verdict: verdict, replay: false });
  }
  return parts;
}

function wireFields(parts) {
  const fields = [];
  for (const part of parts) {
    if (part.denied) fields.push({ field: part.field, decision: 'deny' });
    else fields.push({ field: part.field, value: part.value });
  }
  return fields;
}

function sharedValues(parts) {
  const shared = {};
  for (const part of parts) {
    if (!part.denied) shared[part.field] = part.value;
  }
  return shared;
}

function applyPayload(payload, values) {
  if (typeof values.eventTitle === 'string') payload.summary = values.eventTitle;
  if (typeof values.eventDescription === 'string') payload.description = values.eventDescription;
  if (typeof values.meetUrl === 'string') payload.meetUrl = values.meetUrl;
  return payload;
}

function spendGrants(parts, request) {
  for (const part of parts) {
    if (part.denied || part.replay) continue;
    const grant = part.verdict && part.verdict.grant;
    if (grant && grant.scope === 'once' && grant.consumedRequest !== request) {
      grant.remaining -= 1;
      grant.consumedRequest = request;
    }
  }
}

function allowedStored(verdict, request, storedValue) {
  if (typeof storedValue !== 'string') return undefined;
  const gate = grantAllows(verdict, request);
  if (!gate.ok) return undefined;
  return storedValue;
}

function isId(value) {
  if (typeof value !== 'string' || value.length !== 16) return false;
  for (const ch of value) {
    const ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch === '_' || ch === '-';
    if (!ok) return false;
  }
  return true;
}

function validateConfirmBody(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return 'bad_confirm';
  const keys = Object.keys(d).sort();
  if (keys.length !== 2 || keys[0] !== 'fields' || keys[1] !== 'req') return 'bad_confirm';
  if (!isId(d.req)) return 'bad_confirm';
  if (!Array.isArray(d.fields) || d.fields.length < 1 || d.fields.length > 3) return 'bad_confirm';
  const seen = new Set();
  for (const f of d.fields) {
    if (!f || typeof f !== 'object' || Array.isArray(f)) return 'bad_confirm';
    if (typeof f.field !== 'string' || !DETAIL_SET.has(f.field) || seen.has(f.field)) return 'bad_confirm';
    seen.add(f.field);
    const fk = Object.keys(f).sort();
    const deny = fk.length === 2 && fk[0] === 'decision' && fk[1] === 'field' && f.decision === 'deny' && !Object.prototype.hasOwnProperty.call(f, 'value');
    if (deny) continue;
    const share = fk.length === 2 && fk[0] === 'field' && fk[1] === 'value' && typeof f.value === 'string' && f.value.length >= 1 && f.value.length <= 500;
    if (!share) return 'bad_confirm';
    if (f.field === 'meetUrl' && !isMeetUrl(f.value)) return 'bad_confirm';
  }
  return '';
}

function copiedMeetUrl(d) {
  for (const f of d.fields) {
    if (f && f.field === 'meetUrl' && typeof f.value === 'string') return f.value;
  }
  return null;
}

module.exports = {
  DETAIL_FIELDS,
  detailInputs,
  releaseDetails,
  wireFields,
  sharedValues,
  applyPayload,
  spendGrants,
  allowedStored,
  validateConfirmBody,
  copiedMeetUrl,
};
