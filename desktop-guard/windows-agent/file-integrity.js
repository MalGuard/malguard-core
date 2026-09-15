'use strict';

const fs = require('fs');
const crypto = require('crypto');

async function hashFile(filePath) {
  const stat = await fs.promises.lstat(filePath);
  if (!stat.isFile()) {
    const error = new Error('regular file required');
    error.code = stat.isSymbolicLink() ? 'SYMLINK_NOT_ALLOWED' : 'NOT_A_REGULAR_FILE';
    throw error;
  }

  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', resolve);
  });

  return Object.freeze({
    sha256: hash.digest('hex'),
    size: stat.size,
    mtimeMs: stat.mtimeMs,
  });
}

function sameIdentity(a, b) {
  return !!a && !!b && a.sha256 === b.sha256 && a.size === b.size;
}

module.exports = { hashFile, sameIdentity };
