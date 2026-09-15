'use strict';

const assert = require('assert');
const { AbuseChCredentialStore } = require('../desktop-app/threat-intel/credential-store.js');

(async () => {
  const secret = 'unit-test-secret-1234567890';
  const store = new AbuseChCredentialStore({ env: { MALGUARD_ABUSECH_AUTH_KEY: secret }, platform: 'linux' });
  assert.equal(await store.getAuthKey(), secret);
  const status = await store.status();
  assert.deepEqual(status, { configured: true, source: 'environment' });
  assert(!JSON.stringify(status).includes(secret), 'status endpoint must never expose credential');

  const none = new AbuseChCredentialStore({ env: {}, platform: 'linux' });
  assert.equal(await none.getAuthKey(), null);
  await assert.rejects(() => none.setAuthKey(secret), error => error && error.code === 'DPAPI_UNAVAILABLE');

  console.log('✓ abuse.ch credential provider avoids secret disclosure and requires DPAPI for persistent storage PASS');
})().catch(error => { console.error(error); process.exit(1); });
