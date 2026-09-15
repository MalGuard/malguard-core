'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { EntitlementGate } = require('../desktop-app/entitlement/entitlement-gate.js');

function makeToken(privateKey, claims) {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64url');
  return `${payload}.${signature}`;
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const now = 1_900_000_000_000;

const proToken = makeToken(privateKey, { schemaVersion: '1.0.0', subject: 'synthetic-test', plan: 'pro', expiresAt: now + 60_000 });
const plusToken = makeToken(privateKey, { schemaVersion: '1.0.0', subject: 'synthetic-test', plan: 'plus', expiresAt: now + 60_000 });

const defaultGate = new EntitlementGate({ now: () => now });
assert.equal(defaultGate.status().plan, 'standard');
assert.equal(defaultGate.requireModel('standard').plan, 'standard');
assert.throws(() => defaultGate.requireModel('plus'), err => err && err.code === 'ENTITLEMENT_REQUIRED');
assert.throws(() => defaultGate.requireModel('pro'), err => err && err.code === 'ENTITLEMENT_REQUIRED');

const plusGate = new EntitlementGate({ publicKeyPem, token: plusToken, now: () => now });
assert.equal(plusGate.requireModel('standard').plan, 'plus');
assert.equal(plusGate.requireModel('plus').plan, 'plus');
assert.throws(() => plusGate.requireModel('pro'), err => err && err.code === 'ENTITLEMENT_REQUIRED');

const proGate = new EntitlementGate({ publicKeyPem, token: proToken, now: () => now });
assert.equal(proGate.requireModel('pro').plan, 'pro');

const expired = makeToken(privateKey, { schemaVersion: '1.0.0', plan: 'pro', expiresAt: now - 1 });
assert.equal(new EntitlementGate({ publicKeyPem, token: expired, now: () => now }).status().valid, false);

const tamperedParts = proToken.split('.');
const tamperedClaims = { schemaVersion: '1.0.0', subject: 'synthetic-test', plan: 'pro', expiresAt: now + 120_000 };
tamperedParts[0] = Buffer.from(JSON.stringify(tamperedClaims)).toString('base64url');
const tampered = tamperedParts.join('.');
assert.throws(() => new EntitlementGate({ publicKeyPem, token: tampered, now: () => now }).requireModel('pro'), err => err && err.code === 'ENTITLEMENT_INVALID');

console.log('✓ Entitlement gate: signed Standard/Plus/Pro boundary, expiry and tamper rejection PASS');
