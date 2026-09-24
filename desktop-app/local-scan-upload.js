'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_SCAN_UPLOAD_BYTES = 64 * 1024 * 1024;

function uploadError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function validFileName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 128
    && name !== '.' && name !== '..' && !/[<>:"/\\|?*\x00-\x1f]/.test(name)
    && !/[. ]$/.test(name) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name);
}

function uploadRoot() {
  const base = process.env.LOCALAPPDATA || os.tmpdir();
  return path.join(base, 'MalGuard', 'scan-uploads');
}

async function discardScanUpload(upload) {
  if (upload && upload.directory) await fs.promises.rm(upload.directory, { recursive: true, force: true });
}

async function stageScanUpload(request, name, { maxBytes = MAX_SCAN_UPLOAD_BYTES, root = uploadRoot() } = {}) {
  if (!validFileName(name)) throw uploadError('UPLOAD_NAME_INVALID');
  const declaredLength = Number(request.headers && request.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw uploadError('UPLOAD_TOO_LARGE');
  await fs.promises.mkdir(root, { recursive: true, mode: 0o700 });
  const directory = await fs.promises.mkdtemp(path.join(root, 'scan-'));
  const filePath = path.join(directory, name);
  let file;
  let bytes = 0;
  try {
    file = await fs.promises.open(filePath, 'wx', 0o600);
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > maxBytes) throw uploadError('UPLOAD_TOO_LARGE');
      await file.writeFile(chunk);
    }
    if (bytes === 0) throw uploadError('UPLOAD_EMPTY');
    await file.close();
    return { path: filePath, directory, bytes };
  } catch (error) {
    if (file) await file.close().catch(() => {});
    await discardScanUpload({ directory });
    throw error;
  }
}

module.exports = { MAX_SCAN_UPLOAD_BYTES, validFileName, stageScanUpload, discardScanUpload };
