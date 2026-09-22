'use strict';

const ALLOWED_KEYS = new Set([
  'schemaVersion','event','version','os','arch','cpuCoresBucket',
  'ramBucket','gpuVendor','display','language'
]);
const CPU = new Set(['1-4','5-8','9-12','13-16','17-24','25+','unknown']);
const RAM = new Set(['<4 GB','4-8 GB','8-16 GB','16-32 GB','32-64 GB','64+ GB','unknown']);
const GPU = new Set(['NVIDIA','AMD','Intel','Microsoft','Other','unknown']);
const ARCH = new Set(['x64','arm64']);
const rate = [];

function cleanAscii(value, max) {
  const text = String(value || '').replace(/[^\x20-\x7E]/g, '').trim();
  return text && text.length <= max ? text : null;
}

function parseBody(req) {
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('invalid-body');
  if (Object.keys(body).some(k => !ALLOWED_KEYS.has(k))) throw new Error('unsupported-field');
  if (body.schemaVersion !== '1.0' || body.event !== 'first_successful_launch') throw new Error('invalid-schema');

  const version = cleanAscii(body.version, 64);
  const osName = body.os && cleanAscii(body.os.name, 80);
  const build = body.os && cleanAscii(body.os.build, 16);
  const language = cleanAscii(body.language, 24);
  const display = cleanAscii(body.display, 24);

  if (!version || !/^[0-9A-Za-z._-]+$/.test(version)) throw new Error('invalid-version');
  if (!osName || !/^Windows/i.test(osName)) throw new Error('invalid-os');
  if (!build || !/^(?:\d{3,10}|unknown)$/.test(build)) throw new Error('invalid-build');
  if (!ARCH.has(body.arch)) throw new Error('invalid-arch');
  if (!CPU.has(body.cpuCoresBucket)) throw new Error('invalid-cpu');
  if (!RAM.has(body.ramBucket)) throw new Error('invalid-ram');
  if (!GPU.has(body.gpuVendor)) throw new Error('invalid-gpu');
  if (!display || !/^(?:\d{3,5}x\d{3,5}|unknown)$/.test(display)) throw new Error('invalid-display');
  if (!language || !/^(?:[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}|unknown)$/.test(language)) throw new Error('invalid-language');

  return {
    version,
    osName,
    build,
    arch:body.arch,
    cpuCoresBucket:body.cpuCoresBucket,
    ramBucket:body.ramBucket,
    gpuVendor:body.gpuVendor,
    display,
    language,
  };
}

function allowRate(now = Date.now()) {
  const cutoff = now - 60_000;
  while (rate.length && rate[0] < cutoff) rate.shift();
  if (rate.length >= 30) return false;
  rate.push(now);
  return true;
}

function emailText(p) {
  return [
    'New MalGuard installation',
    '',
    'Product: MalGuard Desktop',
    `Version: ${p.version}`,
    `OS: ${p.osName}`,
    `Windows build: ${p.build}`,
    `Architecture: ${p.arch}`,
    `CPU cores: ${p.cpuCoresBucket}`,
    `RAM: ${p.ramBucket}`,
    `GPU: ${p.gpuVendor}`,
    `Display: ${p.display}`,
    `System language: ${p.language}`,
    `Reported at: ${new Date().toISOString()}`,
    '',
    'Privacy: no username, computer name, hardware serial, MAC address, IP address, geolocation, file path, scan result, or installation identifier is included by MalGuard in this report.'
  ].join('\n');
}

module.exports = async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Type','application/json; charset=utf-8');
  if (req.method !== 'POST') {
    res.setHeader('Allow','POST');
    return res.status(405).json({ok:false,error:'method-not-allowed'});
  }
  if (!allowRate()) return res.status(429).json({ok:false,error:'rate-limited'});

  let payload;
  try {
    payload = parseBody(req);
  } catch (_) {
    return res.status(400).json({ok:false,error:'invalid-report'});
  }

  const apiKey = process.env.RESEND_API_KEY;
  const to = process.env.MALGUARD_INSTALL_NOTIFY_EMAIL;
  const from = process.env.MALGUARD_INSTALL_FROM_EMAIL;
  if (!apiKey || !to || !from) return res.status(503).json({ok:false,error:'email-not-configured'});

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method:'POST',
      headers:{
        authorization:`Bearer ${apiKey}`,
        'content-type':'application/json',
      },
      body:JSON.stringify({
        from,
        to:[to],
        subject:`New MalGuard installation · ${payload.arch} · ${payload.osName}`,
        text:emailText(payload),
      }),
    });
    if (!response.ok) {
      console.error('install hardware report email provider failed:', response.status);
      return res.status(503).json({ok:false,error:'email-provider-failed'});
    }
    return res.status(200).json({ok:true,notified:true});
  } catch (_) {
    console.error('install hardware report email request failed');
    return res.status(503).json({ok:false,error:'email-provider-unavailable'});
  }
};

module.exports._test = {parseBody,emailText,allowRate};
