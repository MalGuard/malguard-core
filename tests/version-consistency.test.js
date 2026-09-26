'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const desktop = fs.readFileSync(path.join(ROOT, 'DESKTOP-VERSION'), 'utf8').trim();
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

assert.match(desktop, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
assert.equal(pkg.version, desktop, 'package.json version must exactly match DESKTOP-VERSION');

console.log('✓ Version consistency gate PASS: ' + desktop);
