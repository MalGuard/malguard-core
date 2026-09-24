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
        const alternatives = report && report.windowsSandbox && report.windowsSandbox.alternatives;
        const windows = alternatives && alternatives.windowsSandbox;
        const reason = Array.isArray(report && report.blockers) && report.blockers.length
          ? String(report.blockers[0]).replace(/[_-]/g, ' ').slice(0, 140)
          : '';
        summary.textContent = windows && windows.available === false
          ? 'Isolated execution is unavailable on this PC. Standard file scans still work. If supported, enable the Windows Sandbox optional feature and hardware virtualization, restart Windows, then re-check. Plus/Pro will not execute files without verified isolation.'
          : 'Isolated execution has not passed its safety check. Standard file scans still work. Re-check after setting up Windows Sandbox; see Advanced diagnostics for the cause. Plus/Pro will not execute files outside verified isolation.'
            + (reason ? ' Check: ' + reason + '.' : '');
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
