'use strict';

(function () {
  async function runRealSandboxCertification() {
    const button = document.getElementById('finalSandboxTest');
    const summary = document.getElementById('finalSandboxSummary');
    const diagnostics = document.getElementById('finalSandboxDiagnostics');
    const output = document.getElementById('finalSandboxOut');
    if (!summary || !output) return;

    if (button) button.disabled = true;
    summary.className = 'health-card health-checking';
    summary.textContent = 'Verifying real Windows Sandbox execution on this PC…';

    try {
      const response = await fetch('/api/sandbox/self-test', {
        method: 'POST',
        headers: { 'accept': 'application/json' },
        cache: 'no-store',
      });
      const report = await response.json();
      output.textContent = JSON.stringify(report, null, 2);
      if (diagnostics) diagnostics.hidden = false;

      const executionProven = report && report.ok === true
        && report.releaseReady === true
        && report.executionCertified === true
        && report.executionProbe
        && report.executionProbe.sandboxLaunched === true
        && report.executionProbe.attempted === true
        && report.executionProbe.started === true
        && report.executionProbe.exitCode === 0;

      if (executionProven) {
        summary.className = 'health-card health-ready';
        summary.textContent = 'Secure Sandbox verified: MalGuard launched a harmless test file inside the real Windows Sandbox. Plus and Pro behavioral execution is ready.';
      } else {
        summary.className = 'health-card health-setup';
        summary.textContent = 'Secure Sandbox is not certified on this PC yet. MalGuard will not execute suspicious files outside isolation and will keep Plus/Pro fail-closed.';
      }
    } catch (error) {
      summary.className = 'health-card health-setup';
      summary.textContent = 'Real Sandbox certification could not complete. Plus/Pro execution remains safely disabled.';
      output.textContent = JSON.stringify({ code: 'REAL_SANDBOX_CERTIFICATION_UI_ERROR', message: String(error && error.message || error) }, null, 2);
      if (diagnostics) diagnostics.hidden = false;
    } finally {
      if (button) button.disabled = false;
    }
  }

  const button = document.getElementById('finalSandboxTest');
  if (button) button.onclick = runRealSandboxCertification;

  // The first customer UI load performs a real, harmless execution probe. The
  // server keeps the certification process-local, so a later customer scan can
  // rely on the exact backend instance that passed the check.
  runRealSandboxCertification();
})();
