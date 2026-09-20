'use strict';

const { ALLOWED_FIXTURE, createIsolationJob } = require('./job-policy');

async function runSafeFixture({ Sandbox } = {}) {
  if (!Sandbox || typeof Sandbox.create !== 'function') throw new Error('sandbox-provider-unavailable');
  const job = createIsolationJob(ALLOWED_FIXTURE);
  if (!job.accepted) throw new Error('safe-fixture-policy-rejected');

  let sandbox;
  try {
    sandbox = await Sandbox.create({
      runtime: 'node24',
      timeout: job.isolation.timeoutMs,
      networkPolicy: 'deny-all',
      persistent: false
    });
    await sandbox.writeFiles([{
      path: '/vercel/sandbox/malguard-safe-fixture.txt',
      content: ALLOWED_FIXTURE
    }]);
    const result = await sandbox.runCommand('node', ['-e',
      "const fs=require('fs'),crypto=require('crypto');const p='/vercel/sandbox/malguard-safe-fixture.txt';const b=fs.readFileSync(p);process.stdout.write(JSON.stringify({bytes:b.length,sha256:crypto.createHash('sha256').update(b).digest('hex'),marker:b.toString('utf8').trim()}));"
    ]);
    const stdout = await result.stdout();
    const report = JSON.parse(stdout);
    if (report.sha256 !== job.fixture.sha256 || report.bytes !== job.fixture.bytes || report.marker !== 'MALGUARD_SAFE_SANDBOX_FIXTURE_V1') {
      throw new Error('sandbox-report-integrity-failed');
    }
    return { ok: true, jobId: job.jobId, report, isolation: job.isolation };
  } finally {
    if (sandbox && typeof sandbox.stop === 'function') await sandbox.stop();
  }
}

module.exports = { runSafeFixture };
