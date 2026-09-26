'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const ENGINE_VERSION = '2.0.0';
const DEFAULT_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 2 * 1024 * 1024;
const ENGINE_ROOT = path.join(__dirname, '..', 'engines');
function bundled(relative, fallback) {
  const candidate = path.join(ENGINE_ROOT, ...relative.split('/'));
  return fs.existsSync(candidate) ? candidate : fallback;
}

function bounded(text) {
  const s = String(text || '');
  return s.length > MAX_OUTPUT ? s.slice(0, MAX_OUTPUT) : s;
}

function runProcess(command, args, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise(resolve => {
    let stdout = '', stderr = '', settled = false;
    let child;
    try {
      child = spawn(command, args, { windowsHide: true, shell: false, stdio: ['ignore','pipe','pipe'] });
    } catch (error) {
      resolve({ ok:false, available:false, code:'spawn_failed', error:error.code || error.message });
      return;
    }
    const timer = setTimeout(() => {
      if (settled) return;
      try { child.kill(); } catch (_) {}
      settled = true;
      resolve({ ok:false, available:true, code:'timeout', stdout:bounded(stdout), stderr:bounded(stderr) });
    }, timeoutMs);
    child.stdout.on('data', d => { if (stdout.length < MAX_OUTPUT) stdout += d; });
    child.stderr.on('data', d => { if (stderr.length < MAX_OUTPUT) stderr += d; });
    child.on('error', error => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      resolve({ ok:false, available:false, code:'process_error', error:error.code || error.message });
    });
    child.on('close', code => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      resolve({ ok:code===0, available:true, exitCode:code, stdout:bounded(stdout), stderr:bounded(stderr) });
    });
  });
}

function verdictFromClam(result) {
  if (!result.available) return 'unavailable';
  if (result.exitCode === 1) return 'malicious';
  if (result.exitCode === 0) return 'clean';
  return 'error';
}

function verdictFromYara(result) {
  if (!result.available) return 'unavailable';
  if (result.exitCode !== 0) return 'error';
  return String(result.stdout || '').trim() ? 'matched' : 'no_match';
}

function parseJson(result) {
  if (!result || !result.ok) return null;
  try { return JSON.parse(result.stdout); } catch (_) { return null; }
}

async function runExternalEngines(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  const st = await fs.promises.stat(resolved);
  if (!st.isFile()) throw Object.assign(new Error('scan target must be a file'), { code:'NOT_FILE' });

  const yaraRules = options.yaraRules || process.env.MALGUARD_YARAX_RULES || path.join(__dirname,'rules','malguard.yar');
  const tasks = [];

  tasks.push((async()=>{
    if (!yaraRules) return { name:'yara_x', status:'unavailable', reason:'rules_not_configured' };
    const r=await runProcess(process.env.MALGUARD_YARAX_BIN || bundled('yara-x/yr.exe','yr'), ['scan','--output-format','ndjson',yaraRules,resolved]);
    return { name:'yara_x', status:verdictFromYara(r), available:r.available, exitCode:r.exitCode, evidence:r.stdout ? bounded(r.stdout) : null, stderr:r.stderr ? bounded(r.stderr) : null };
  })());

  tasks.push((async()=>{
    const r=await runProcess(process.env.MALGUARD_CAPA_BIN || bundled('capa/capa.exe','capa'), ['-j',resolved], {timeoutMs:90_000});
    const json=parseJson(r);
    return { name:'capa', status:!r.available?'unavailable':r.ok?'complete':'error', available:r.available, capabilities:json && json.rules ? Object.keys(json.rules).slice(0,256) : [], evidenceCount:json && json.rules ? Object.keys(json.rules).length : 0 };
  })());

  tasks.push((async()=>{
    const r=await runProcess(process.env.MALGUARD_FLOSS_BIN || bundled('floss/floss.exe','floss'), ['--json',resolved], {timeoutMs:90_000});
    const json=parseJson(r);
    const strings=json && json.strings ? json.strings : null;
    const count=strings && typeof strings==='object' ? Object.values(strings).reduce((n,v)=>n+(Array.isArray(v)?v.length:0),0) : 0;
    return { name:'floss', status:!r.available?'unavailable':r.ok?'complete':'error', available:r.available, decodedStringCount:count };
  })());

  tasks.push((async()=>{
    const r=await runProcess(process.env.MALGUARD_CLAM_BIN || bundled('clamav/clamscan.exe','clamscan'), ['--no-summary','--infected',resolved], {timeoutMs:90_000});
    return { name:'clamav', status:verdictFromClam(r), available:r.available, exitCode:r.exitCode };
  })());

  if (process.platform === 'win32') {
    tasks.push((async()=>{
      const defender=process.env.MALGUARD_DEFENDER_BIN || 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe';
      const r=await runProcess(defender, ['-Scan','-ScanType','3','-File',resolved,'-DisableRemediation'], {timeoutMs:120_000});
      return { name:'microsoft_defender', status:!r.available?'unavailable':r.exitCode===0?'clean':'detected_or_error', available:r.available, exitCode:r.exitCode };
    })());
  } else {
    tasks.push(Promise.resolve({ name:'microsoft_defender', status:'unavailable', reason:'not_windows' }));
  }

  const engines=await Promise.all(tasks);
  return {
    schemaVersion:'2.0',
    engineVersion:ENGINE_VERSION,
    fileSize:st.size,
    engines,
    completed:engines.filter(x=>['complete','clean','matched','malicious','no_match','detected_or_error'].includes(x.status)).length,
    unavailable:engines.filter(x=>x.status==='unavailable').map(x=>x.name),
  };
}

module.exports={ ENGINE_VERSION, runExternalEngines, runProcess };
