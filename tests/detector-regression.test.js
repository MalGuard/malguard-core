'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '..');

class FileLike {
  constructor(name, bytes) { this.name = name; this._b = Buffer.from(bytes || ''); this.size = this._b.length; }
  async arrayBuffer() { return this._b.buffer.slice(this._b.byteOffset, this._b.byteOffset + this._b.byteLength); }
  slice(s, e) { return new FileLike(this.name, this._b.subarray(s || 0, e == null ? this._b.length : e)); }
}
const c = { console, TextDecoder, window: null }; c.window = c; vm.createContext(c);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'gta-mod-detector.js'), 'utf8'), c, { filename: 'gta-mod-detector.js' });

(async () => {
  const cases = [
    ['mod.asi', Buffer.from('MZ'), 'ENGINE', 'plugin', false],
    ['mod.dll', Buffer.from('MZ'), 'INCONCLUSIVE', 'plugin', false],
    ['mod.zip', Buffer.from([0x50,0x4b,0x03,0x04]), 'ARCHIVE_INSPECTION', 'archive', false],
    ['mod.lua', Buffer.from('print("GTA V")'), 'INCONCLUSIVE', 'script', false],
    ['mod.cs', Buffer.from('using GTA;'), 'INCONCLUSIVE', 'script', false],
    ['mod.exe', Buffer.from('MZ'), 'INCONCLUSIVE', 'executable', false],
    ['texture.ytd', Buffer.from('RSC7'), 'INCONCLUSIVE', 'asset', false],
    ['config.meta', Buffer.from('<Item/>'), 'INCONCLUSIVE', 'metadata', false],
    ['readme.txt', Buffer.from('hello'), 'REJECT', 'unknown', false],
    ['payload.dll.txt', Buffer.from('MZ'), 'REJECT', 'unknown', true],
    ['archive.zip.exe', Buffer.from([0x50,0x4b,0x03,0x04]), 'INCONCLUSIVE', 'executable', true],
    ['plugin.asi.txt', Buffer.from('MZ'), 'REJECT', 'unknown', true],
    ['x.a.b.c.d.e.f.g.h.i.j.k.asi.txt', Buffer.from('MZ'), 'REJECT', 'unknown', true],
  ];
  for (const [name, bytes, route, type, suspicious] of cases) {
    const r = await c.GtaModDetector.analyze(new FileLike(name, bytes));
    assert.equal(r.route, route, `${name}: route`);
    assert.equal(r.modType, type, `${name}: type`);
    assert.equal(r.suspiciousPackaging, suspicious, `${name}: packaging`);
  }
  console.log(`✓ Detector regression: ${cases.length}/${cases.length} routing/packaging cases passed`);
})().catch(e => { console.error(e.stack || e); process.exit(1); });
