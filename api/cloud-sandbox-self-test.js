'use strict';

const { runSafeFixture } = require('../cloud-sandbox/vercel-runner');

const ALLOWED_ORIGIN = 'https://malguard.github.io';

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Vary', 'Origin');

  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ ok: false, error: 'method-not-allowed' });
  }

  try {
    const { Sandbox } = await import('@vercel/sandbox');
    const result = await runSafeFixture({ Sandbox });
    return res.status(200).json({
      ok: true,
      phase: 'safe-fixture-self-test',
      report: result.report,
      isolation: result.isolation
    });
  } catch (error) {
    console.error('cloud-sandbox-self-test failed:', error && error.message);
    return res.status(503).json({ ok: false, error: 'sandbox-self-test-failed' });
  }
};
