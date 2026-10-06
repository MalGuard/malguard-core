'use strict';

const assert = require('assert');
const {
  MAX_RECENT_LOGS,
  createReadOnlyTools,
} = require('../desktop-app/mcp/read-only-tools.js');

function jsonResponse(body) {
  return {
    ok: true,
    status: 200,
    async json() { return body; },
  };
}

(async () => {
  const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
  const statusPayload = {
    ok: true,
    product: 'MalGuard Desktop',
    version: '0.8.0-beta.7',
    build: 'abc1234',
    guardConfigured: true,
    watching: true,
    watchRoots: ['C:\\Users\\Test\\Games'],
    quarantineRoot: 'C:\\Users\\Test\\SecretQuarantine',
    authKey: secret,
    realtimeProtection: {
      active: true,
      completeProtection: true,
      accessGateProtected: true,
      watcherHealthy: true,
      runtimeProcessHealthy: true,
      state: 'active',
      reason: null,
    },
    guardHealth: { state: 'healthy', internalPath: 'C:\\Users\\Test\\private.txt' },
    sandboxMode: 'windows-sandbox-certified',
    sandboxCertification: {
      state: 'certified',
      ok: true,
      sandboxVersion: '0.6.1',
      certifiedAt: '2026-10-06T12:00:00.000Z',
      isolationBackendReady: true,
      windowsSandboxReady: true,
      executionCertified: true,
      selectedBackend: 'windows-sandbox',
      blockers: [],
      executionProbe: { samplePath: 'C:\\Users\\Test\\probe.cmd' },
      automatic: {
        enabled: true,
        scheduled: false,
        startedAt: '2026-10-06T11:59:00.000Z',
        completedAt: '2026-10-06T12:00:00.000Z',
      },
    },
  };

  let fetchCalls = 0;
  const fetchImpl = async (url, options) => {
    fetchCalls += 1;
    assert.equal(url, 'http://127.0.0.1:18777/api/status');
    assert.equal(options.method, 'GET');
    assert.equal(options.headers.accept, 'application/json');
    return jsonResponse(statusPayload);
  };

  const reports = Array.from({ length: MAX_RECENT_LOGS + 5 }, (_, index) => ({
    id: 'report-' + index,
    time: '2026-10-06T12:00:00.000Z',
    code: 'SYNTHETIC_FAILURE',
    name: 'Error',
    message: 'failed at C:\\Users\\Test\\secret-' + index + '.txt token ' + secret,
    context: {
      area: 'runtime',
      method: 'GET',
      route: '/api/status',
    },
    runtime: {
      node: 'v20.0.0',
      platform: 'win32',
      arch: 'x64',
    },
    stack: 'must never leave diagnostics',
    environment: { TOKEN: secret },
  }));

  const errorReporter = {
    async list(limit) {
      assert.equal(limit, MAX_RECENT_LOGS);
      return reports;
    },
  };

  const tools = createReadOnlyTools({
    fetchImpl,
    errorReporter,
    port: 18777,
    now: () => '2026-10-06T12:34:56.000Z',
  });

  const status = await tools.getMalguardStatus();
  assert.equal(status.ok, true);
  assert.equal(status.product, 'MalGuard Desktop');
  assert.equal(status.version, '0.8.0-beta.7');
  assert.equal(status.realtimeProtection.completeProtection, true);
  assert.equal(status.guardHealth.state, 'healthy');
  const statusText = JSON.stringify(status);
  assert(!statusText.includes('watchRoots'));
  assert(!statusText.includes('quarantineRoot'));
  assert(!statusText.includes('authKey'));
  assert(!statusText.includes('C:\\Users\\Test'));
  assert(!statusText.includes(secret));

  const sandbox = await tools.getSandboxHealth();
  assert.equal(sandbox.ok, true);
  assert.equal(sandbox.sandboxReady, true);
  assert.equal(sandbox.certification.executionCertified, true);
  assert.equal(sandbox.certification.selectedBackend, 'windows-sandbox');
  const sandboxText = JSON.stringify(sandbox);
  assert(!sandboxText.includes('executionProbe'));
  assert(!sandboxText.includes('samplePath'));
  assert(!sandboxText.includes('C:\\Users\\Test'));

  const logs = await tools.getRecentLogs();
  assert.equal(logs.ok, true);
  assert.equal(logs.count, MAX_RECENT_LOGS);
  assert.equal(logs.reports.length, MAX_RECENT_LOGS);
  assert.equal(logs.privacy.pathsRedacted, true);
  assert.equal(logs.privacy.longSecretsRedacted, true);
  assert.equal(logs.privacy.stacksExcluded, true);
  const logText = JSON.stringify(logs);
  assert(!logText.includes('C:\\Users\\Test'));
  assert(!logText.includes(secret));
  assert(!logText.includes('"stack"'));
  assert(!logText.includes('"environment"'));
  assert(!logText.includes('"id"'));
  assert(logText.includes('[path]'));
  assert(logText.includes('[redacted]'));

  const unavailable = createReadOnlyTools({
    fetchImpl: async () => {
      throw new Error('connect failed at C:\\Users\\Test\\private.txt token ' + secret);
    },
    errorReporter,
    now: () => '2026-10-06T12:34:56.000Z',
  });
  const failedStatus = await unavailable.getMalguardStatus();
  assert.equal(failedStatus.ok, false);
  assert.equal(failedStatus.code, 'MALGUARD_LOCAL_UNAVAILABLE');
  assert(!JSON.stringify(failedStatus).includes(secret));
  assert(!JSON.stringify(failedStatus).includes('C:\\Users\\Test'));

  assert.equal(fetchCalls, 2);
  console.log('✓ MCP read-only tools: bounded status, sandbox health, and redacted diagnostics PASS');
})().catch(error => {
  console.error(error.stack || error);
  process.exit(1);
});
