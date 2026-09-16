'use strict';

const path = require('path');
const { verifyRuntimePackageIntegrity } = require('./runtime-integrity.js');

const root = path.resolve(__dirname, '..', '..');
const result = verifyRuntimePackageIntegrity(root, {
  requireSealed: process.env.MALGUARD_REQUIRE_SEALED_RUNTIME === '1',
});

if (!result.ok) {
  const code = typeof result.code === 'string' ? result.code : 'RUNTIME_INTEGRITY_FAILED';
  process.stderr.write(`MalGuard runtime integrity check failed: ${code}\n`);
  process.exit(78);
}

Object.defineProperty(globalThis, '__MALGUARD_RUNTIME_INTEGRITY__', {
  value: Object.freeze({ ...result }),
  enumerable: false,
  configurable: false,
  writable: false,
});
