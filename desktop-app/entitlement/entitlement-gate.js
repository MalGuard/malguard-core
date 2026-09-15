'use strict';

const crypto = require('crypto');

const PLAN_LEVEL = Object.freeze({ standard: 0, plus: 1, pro: 2 });

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function decodeToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) throw Object.assign(new Error('entitlement token missing'), { code: 'ENTITLEMENT_REQUIRED' });
  const [payloadB64, signatureB64, extra] = token.split('.');
  if (!payloadB64 || !signatureB64 || extra !== undefined) throw Object.assign(new Error('invalid entitlement token'), { code: 'ENTITLEMENT_INVALID' });
  let claims;
  try { claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')); }
  catch (_) { throw Object.assign(new Error('invalid entitlement payload'), { code: 'ENTITLEMENT_INVALID' }); }
  return { payloadB64, signatureB64, claims };
}

class EntitlementGate {
  constructor(options = {}) {
    this.publicKeyPem = options.publicKeyPem || process.env.MALGUARD_ENTITLEMENT_PUBLIC_KEY_PEM || null;
    this.token = options.token || process.env.MALGUARD_ENTITLEMENT_TOKEN || null;
    this.now = options.now || (() => Date.now());
  }

  verify() {
    if (!this.token || !this.publicKeyPem) return { valid: true, plan: 'standard', source: 'default-standard' };
    const { payloadB64, signatureB64, claims } = decodeToken(this.token);
    if (!claims || claims.schemaVersion !== '1.0.0' || !Object.hasOwn(PLAN_LEVEL, claims.plan)) {
      throw Object.assign(new Error('unsupported entitlement claims'), { code: 'ENTITLEMENT_INVALID' });
    }
    if (!Number.isInteger(claims.expiresAt) || claims.expiresAt <= this.now()) {
      throw Object.assign(new Error('entitlement expired'), { code: 'ENTITLEMENT_EXPIRED' });
    }
    const key = crypto.createPublicKey(this.publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') throw Object.assign(new Error('entitlement key must be Ed25519'), { code: 'ENTITLEMENT_INVALID' });
    const ok = crypto.verify(null, Buffer.from(payloadB64, 'utf8'), key, Buffer.from(signatureB64, 'base64url'));
    if (!ok) throw Object.assign(new Error('entitlement signature verification failed'), { code: 'ENTITLEMENT_INVALID' });
    return { valid: true, plan: claims.plan, subject: claims.subject || null, expiresAt: claims.expiresAt, source: 'signed-token' };
  }

  requirePlan(plan) {
    if (!Object.hasOwn(PLAN_LEVEL, plan)) throw Object.assign(new Error('invalid entitlement plan'), { code: 'INVALID_MODEL' });
    const entitlement = this.verify();
    if (PLAN_LEVEL[entitlement.plan] < PLAN_LEVEL[plan]) {
      throw Object.assign(new Error(`${plan} requires a higher entitlement`), { code: 'ENTITLEMENT_REQUIRED', requiredPlan: plan, currentPlan: entitlement.plan });
    }
    return entitlement;
  }

  requireModel(model) {
    return this.requirePlan(model);
  }

  status() {
    try { return this.verify(); }
    catch (error) { return { valid: false, plan: 'standard', code: error.code || 'ENTITLEMENT_INVALID', source: 'fail-closed' }; }
  }
}

module.exports = { EntitlementGate, PLAN_LEVEL, canonicalize, decodeToken };
