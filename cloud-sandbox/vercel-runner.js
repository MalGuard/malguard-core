'use strict';

const { ALLOWED_FIXTURE, createInspectionJob } = require('./job-policy');

async function runInspection({ Sandbox, data, name = 'upload.bin' } = {}) {
  if (!Sandbox || typeof Sandbox.create !== 'function') {
    throw new Error('sandbox-provider-unavailable');
  }

  const job = createInspectionJob(data);
  if (!job.accepted) {
    throw new Error('inspection-policy-rejected:' + job.reason);
  }

  let sandbox;
  try {
    sandbox = await Sandbox.create({
      runtime: 'node24',
      timeout: job.isolation.timeoutMs,
      networkPolicy: 'deny-all',
      persistent: false
    });

    // Relative paths are resolved under /vercel/sandbox by writeFiles().
    // Keep the command cwd in that same workspace so file materialization
    // does not depend on an absolute path being present.
    await sandbox.writeFiles([{ path: 'input.bin', content: data }]);

    const script = "const fs=require('fs'),crypto=require('crypto');" +
      "const b=fs.readFileSync('input.bin');" +
      "const h=b.subarray(0,16).toString('hex');" +
      "let type='unknown';" +
      "if(h.startsWith('4d5a'))type='windows-pe';" +
      "else if(h.startsWith('504b0304'))type='zip';" +
      "else if(h.startsWith('25504446'))type='pdf';" +
      "else if(h.startsWith('89504e470d0a1a0a'))type='png';" +
      "else if(h.startsWith('ffd8ff'))type='jpeg';" +
      "else if(h.startsWith('494433')||h.startsWith('fff')||h.startsWith('ffe'))type='mp3';" +
      "process.stdout.write(JSON.stringify({bytes:b.length,sha256:crypto.createHash('sha256').update(b).digest('hex'),type}));";

    const result = await sandbox.runCommand({
      cmd: 'node',
      args: ['-e', script],
      cwd: '/vercel/sandbox'
    });

    if (result.exitCode !== 0) {
      throw new Error('sandbox-inspection-command-failed');
    }

    const report = JSON.parse(await result.stdout());
    if (report.sha256 !== job.file.sha256 || report.bytes !== job.file.bytes) {
      throw new Error('sandbox-report-integrity-failed');
    }

    return { ok: true, jobId: job.jobId, name, report, isolation: job.isolation };
  } finally {
    if (sandbox && typeof sandbox.stop === 'function') {
      await sandbox.stop();
    }
  }
}

async function runSafeFixture({ Sandbox } = {}) {
  return runInspection({ Sandbox, data: ALLOWED_FIXTURE, name: 'malguard-safe-fixture.txt' });
}

module.exports = { runSafeFixture, runInspection };
