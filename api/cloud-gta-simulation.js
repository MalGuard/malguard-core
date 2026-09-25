'use strict';

const { runGtaSimulation } = require('../cloud-sandbox/gta-simulation-runner');
const ALLOWED_ORIGIN = 'https://malguard.github.io';

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ ok: false, error: 'method-not-allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body || typeof body.data !== 'string') {
      return res.status(400).json({ ok: false, error: 'file-required' });
    }
    const data = Buffer.from(body.data, 'base64');
    const { Sandbox } = await import('@vercel/sandbox');
    const result = await runGtaSimulation({
      Sandbox,
      data,
      name: String(body.name || 'plugin.asi').slice(0, 160),
    });
    return res.status(200).json(result);
  } catch (error) {
    console.error('cloud-gta-simulation failed:', error && error.message);
    return res.status(400).json({ ok: false, error: 'gta-simulation-failed' });
  }
};
