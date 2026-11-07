'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { UrlhausClient } = require('../desktop-app/threat-intel/urlhaus-client.js');
const { ThreatIntelService } = require('../desktop-app/threat-intel/service.js');

const URL_FIXTURE = 'https://example.invalid/sample?private=synthetic';
const KEY = 'synthetic-test-key';
const hit = { query_status: 'ok', id: '123', url: URL_FIXTURE,
  url_status: 'offline', threat: 'malware_download', date_added: '2026-10-25 12:00:00 UTC' };
const response = (payload, status = 200) => new Response(
  typeof payload === 'string' ? payload : JSON.stringify(payload), { status });
const client = (fetchImpl, options = {}) => new UrlhausClient({
  authKeyProvider: async () => KEY, fetchImpl, ...options,
});
const lookup = (c, url = URL_FIXTURE) => c.lookupUrl(url, { consent: true });

test('read-only request, source attribution and allowlisted matched metadata', async () => {
  let calls = 0;
  const c = client(async (url, options) => {
    calls++;
    assert.equal(url, 'https://urlhaus-api.abuse.ch/v1/url/');
    assert.equal(options.method, 'POST');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers['Auth-Key'], KEY);
    assert.equal(new URLSearchParams(options.body).get('url'), URL_FIXTURE);
    return response({ ...hit, unexpectedSecret: KEY, urlhaus_reference: 'https://untrusted.invalid' });
  });
  const actual = await lookup(c);
  assert.deepEqual(actual, { provider: 'urlhaus', source: 'https://urlhaus.abuse.ch/',
    status: 'matched', reference: 'https://urlhaus.abuse.ch/url/123/', urlStatus: 'offline',
    threat: 'malware_download', upstreamTimestamp: hit.date_added });
  assert.equal(calls, 1);
  assert(!JSON.stringify(actual).includes(KEY));
  assert(!JSON.stringify(actual).includes(URL_FIXTURE));
});

test('only explicit no_results becomes no_match, never safe or clean', async () => {
  const actual = await lookup(client(async () => response({ query_status: 'no_results' })));
  assert.equal(actual.status, 'no_match');
  assert.equal(actual.safe, undefined);
  assert.equal(actual.verdict, undefined);
});

test('consent defaults off and is checked before reading credentials or fetching', async () => {
  const forbidden = () => { throw new Error('must not be called'); };
  const c = client(forbidden, { authKeyProvider: forbidden });
  for (const consent of [undefined, false, 'true', 1]) {
    assert.equal((await c.lookupUrl(URL_FIXTURE, { consent })).status, 'not_checked');
  }
});

test('invalid, oversized and credential-bearing indicators never leave the client', async () => {
  const c = client(() => { throw new Error('must not fetch'); });
  for (const input of [null, {}, 'file:///tmp/test', 'javascript:alert(1)',
    'https://user:password@example.invalid/', ' https://example.invalid/',
    'https://example.invalid/\n', 'https://example.invalid/' + 'x'.repeat(8192)]) {
    assert.equal((await lookup(c, input)).reason, 'invalid_url');
  }
});

test('missing or inaccessible credentials never fetch', async () => {
  let calls = 0;
  for (const authKeyProvider of [async () => null, async () => '', async () => { throw Error(KEY); }]) {
    const actual = await lookup(client(async () => { calls++; }, { authKeyProvider }));
    assert.equal(actual.status, 'unavailable');
    assert(!JSON.stringify(actual).includes(KEY));
  }
  assert.equal(calls, 0);
});

for (const status of [301, 401, 403, 429, 500, 503]) {
  test('HTTP ' + status + ' remains unavailable', async () => {
    const actual = await lookup(client(async () => response({ query_status: 'no_results' }, status)));
    assert.equal(actual.status, 'unavailable');
    assert.equal(actual.reason, 'http_' + status);
  });
}

test('network exceptions are sanitized', async () => {
  const actual = await lookup(client(async () => { throw Error(KEY + URL_FIXTURE); }));
  assert.equal(actual.reason, 'network_error');
  assert(!JSON.stringify(actual).includes(KEY));
  assert(!JSON.stringify(actual).includes(URL_FIXTURE));
});

test('request deadline works even when fetch ignores AbortSignal', async () => {
  const actual = await lookup(client(() => new Promise(() => {}), { timeoutMs: 10 }));
  assert.equal(actual.reason, 'timeout');
});

test('deadline includes stalled credentials and does not start a late request', async () => {
  let resolveKey;
  let calls = 0;
  const c = client(async () => { calls++; }, { timeoutMs: 10,
    authKeyProvider: () => new Promise(resolve => { resolveKey = resolve; }) });
  assert.equal((await lookup(c)).reason, 'timeout');
  resolveKey(KEY);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 0);
});

test('deadline includes a response body that never completes', async () => {
  const body = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array([123])); } });
  const actual = await lookup(client(async () => new Response(body), { timeoutMs: 10 }));
  assert.equal(actual.reason, 'timeout');
});

test('stream byte limit cancels oversized bodies before buffering everything', async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(33)); },
    cancel() { cancelled = true; },
  });
  const actual = await lookup(client(async () => new Response(body), { maxResponseBytes: 32 }));
  assert.equal(actual.status, 'invalid_response');
  assert.equal(actual.reason, 'response_too_large');
  assert.equal(cancelled, true);
});

test('malformed JSON, unexpected schemas, mismatched URL and unknown states fail closed', async () => {
  for (const payload of ['{bad', null, [], {}, { query_status: 'unknown' },
    { query_status: 'ok' }, { ...hit, url: 'https://other.invalid/' },
    { ...hit, url_status: 'safe' }, { ...hit, threat: 'safe' }, { ...hit, id: '../bad' }]) {
    assert.equal((await lookup(client(async () => response(payload)))).status, 'invalid_response');
  }
});

test('authentication errors never become no_match', async () => {
  assert.equal((await lookup(client(async () => response({ query_status: 'no_api_key' })))).status,
    'unavailable');
});

test('missing timestamps stay explicitly absent', async () => {
  assert.equal((await lookup(client(async () => response({ ...hit, date_added: undefined }))))
    .upstreamTimestamp, null);
});

test('body read errors, missing bodies and invalid UTF-8 cannot produce a negative result', async () => {
  const broken = new ReadableStream({ start(controller) { controller.error(Error(KEY)); } });
  for (const body of [broken, null, new Uint8Array([0xff, 0xfe])]) {
    const actual = await lookup(client(async () => new Response(body)));
    assert.equal(actual.status, 'invalid_response');
    assert(!JSON.stringify(actual).includes(KEY));
  }
});

test('body limit counts UTF-8 bytes rather than characters', async () => {
  const actual = await lookup(client(async () => response('é'.repeat(20)), { maxResponseBytes: 32 }));
  assert.equal(actual.reason, 'response_too_large');
});

test('body exactly at the byte limit is accepted', async () => {
  const payload = JSON.stringify({ query_status: 'no_results' });
  const actual = await lookup(client(async () => response(payload),
    { maxResponseBytes: Buffer.byteLength(payload) }));
  assert.equal(actual.status, 'no_match');
});

test('service exposes separate opt-in URL lookup without hash lookups or cache writes', async () => {
  let calls = 0;
  const service = new ThreatIntelService({ credentials: { getAuthKey: async () => KEY },
    client: { lookupSha256() { throw Error('unexpected hash lookup'); } },
    cache: {}, fetchImpl: async () => { calls++; return response(hit); } });
  assert.equal((await service.lookupUrl(URL_FIXTURE)).status, 'not_checked');
  assert.equal(calls, 0);
  assert.equal((await service.lookupUrl(URL_FIXTURE, { consent: true })).status, 'matched');
  assert.equal(calls, 1);
});


test('URLhaus ID validation does not coerce arrays, objects or unsafe numbers', async () => {
  for (const id of [['123'], ['123', '456'], {}, null, true, false, 0, -1,
    1.2, 1e30, '12e3', '../bad', '', []]) {
    const actual = await lookup(client(async () => response({ ...hit, id })));
    assert.equal(actual.status, 'invalid_response', 'unexpected accepted id: ' + JSON.stringify(id));
    assert.equal(actual.reference, undefined);
  }
});

test('positive integer URLhaus ID retains previous numeric compatibility', async () => {
  const actual = await lookup(client(async () => response({ ...hit, id: 123 })));
  assert.equal(actual.status, 'matched');
  assert.equal(actual.reference, 'https://urlhaus.abuse.ch/url/123/');
});

test('calendar-invalid URLhaus timestamps are not returned as evidence', async () => {
  for (const date_added of ['2026-99-99 99:99:99 UTC', '2026-02-29 12:00:00 UTC',
    '2025-02-29 12:00:00 UTC', '2026-04-31 12:00:00 UTC',
    '2026-10-25 24:00:00 UTC', '2026-10-25 23:60:00 UTC',
    '2026-10-25 23:59:60 UTC', '0000-01-01 00:00:00 UTC',
    '2026-01-01T01:01:01Z', null, {}, 123]) {
    const actual = await lookup(client(async () => response({ ...hit, date_added })));
    assert.equal(actual.status, 'matched');
    assert.equal(actual.upstreamTimestamp, null);
  }
});

test('valid leap-day, boundary and early-year timestamps remain supported', async () => {
  for (const date_added of ['2024-02-29 00:00:00 UTC',
    '2026-12-31 23:59:59 UTC', '0001-01-01 00:00:00',
    '0099-01-01 00:00:00 UTC']) {
    const actual = await lookup(client(async () => response({ ...hit, date_added })));
    assert.equal(actual.status, 'matched');
    assert.equal(actual.upstreamTimestamp, date_added);
  }
});

test('no_results with record fields is contradictory, not a negative verdict', async () => {
  for (const field of ['id', 'url', 'url_status', 'threat', 'date_added']) {
    const actual = await lookup(client(async () => response({
      query_status: 'no_results', [field]: hit[field],
    })));
    assert.equal(actual.status, 'invalid_response');
    assert.equal(actual.reason, 'unexpected_shape');
    assert.equal(actual.verdict, undefined);
  }
});

test('ordinary no_results response stays no_match', async () => {
  const actual = await lookup(client(async () => response({ query_status: 'no_results' })));
  assert.equal(actual.status, 'no_match');
  assert.equal(actual.safe, undefined);
});
