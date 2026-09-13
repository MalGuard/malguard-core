'use strict';

const path = require('path');

function normalizeAbsolute(input) {
  if (typeof input !== 'string' || !input.trim()) throw new TypeError('path required');
  return path.resolve(input);
}

function isWithin(child, parent) {
  const c = normalizeAbsolute(child);
  const p = normalizeAbsolute(parent);
  const rel = path.relative(p, c);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

function assertWithinAny(target, roots) {
  if (!Array.isArray(roots) || roots.length === 0) {
    const error = new Error('at least one allowed root is required');
    error.code = 'NO_ALLOWED_ROOTS';
    throw error;
  }
  const resolved = normalizeAbsolute(target);
  if (!roots.some(root => isWithin(resolved, root))) {
    const error = new Error('path is outside configured game roots');
    error.code = 'PATH_OUTSIDE_ALLOWED_ROOTS';
    throw error;
  }
  return resolved;
}

module.exports = { normalizeAbsolute, isWithin, assertWithinAny };
