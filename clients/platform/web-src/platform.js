'use strict';

(() => {
  const fileInput = document.getElementById('fileInput');
  const dropzone = document.getElementById('dropzone');
  const fileCard = document.getElementById('fileCard');
  const fileName = document.getElementById('fileName');
  const fileMeta = document.getElementById('fileMeta');
  const clearBtn = document.getElementById('clearBtn');
  const scanBtn = document.getElementById('scanBtn');
  const selfTestBtn = document.getElementById('selfTestBtn');
  const platformBadge = document.getElementById('platformBadge');
  const resultPanel = document.getElementById('resultPanel');
  const verdictTitle = document.getElementById('verdictTitle');
  const verdictBadge = document.getElementById('verdictBadge');
  const resultSummary = document.getElementById('resultSummary');
  const resultFile = document.getElementById('resultFile');
  const resultHash = document.getElementById('resultHash');
  const resultContext = document.getElementById('resultContext');
  const resultJson = document.getElementById('resultJson');

  let selectedFile = null;
  let busy = false;

  const verdictCopy = Object.freeze({
    safe: ['No strong malicious indicators found', 'safe'],
    suspicious: ['Suspicious indicators found', 'suspicious'],
    malicious: ['Malicious indicators found', 'malicious'],
    inconclusive: ['Analysis inconclusive', 'inconclusive'],
    invalid: ['Unsupported or invalid file', 'invalid'],
  });

  function detectPlatform() {
    const ua = navigator.userAgent || '';
    if (/android/i.test(ua)) return 'Android';
    if (/iPhone|iPad|iPod/i.test(ua)) return 'iPhone / iPad';
    if (/Macintosh|Mac OS X/i.test(ua)) return 'macOS';
    return 'MalGuard client';
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return 'Unknown size';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function setBusy(value) {
    busy = Boolean(value);
    fileInput.disabled = busy;
    clearBtn.disabled = busy;
    scanBtn.disabled = busy || !selectedFile;
    selfTestBtn.disabled = busy;
    scanBtn.textContent = busy ? 'Scanning…' : 'Scan securely';
  }

  function setFile(file) {
    selectedFile = file || null;
    resultPanel.hidden = true;
    if (!selectedFile) {
      fileCard.hidden = true;
      fileName.textContent = 'No file selected';
      fileMeta.textContent = '';
      scanBtn.disabled = true;
      fileInput.value = '';
      return;
    }
    fileCard.hidden = false;
    fileName.textContent = selectedFile.name;
    fileMeta.textContent = formatBytes(selectedFile.size);
    scanBtn.disabled = false;
  }

  function findHash(result) {
    const candidates = [
      result && result.engineResult && result.engineResult.hash,
      result && result.detectorResult && result.detectorResult.hash,
      result && result.hash,
    ];
    const hash = candidates.find(value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value));
    return hash || 'Not available for this route';
  }

  function summarize(result) {
    if (result && typeof result.note === 'string' && result.note.trim()) return result.note.trim();
    if (result && result.engineResult && Array.isArray(result.engineResult.reasons) && result.engineResult.reasons.length) {
      return result.engineResult.reasons.slice(0, 4).join(' · ');
    }
    return 'Local static analysis completed. Review the technical details for the full result.';
  }

  function showResult(result, file) {
    const verdict = result && typeof result.finalVerdict === 'string' ? result.finalVerdict : 'inconclusive';
    const copy = verdictCopy[verdict] || verdictCopy.inconclusive;
    verdictTitle.textContent = copy[0];
    verdictBadge.textContent = verdict.toUpperCase();
    verdictBadge.className = `verdict ${copy[1]}`;
    resultSummary.textContent = summarize(result);
    resultFile.textContent = file ? file.name : 'Synthetic engine check';
    resultHash.textContent = findHash(result);
    resultContext.textContent = result && result.execution && result.execution.context
      ? result.execution.context
      : 'web_worker';
    resultJson.textContent = JSON.stringify(result, null, 2);
    resultPanel.hidden = false;
    resultPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function showError(error) {
    const code = error && error.code ? String(error.code) : 'SCAN_FAILED';
    const message = error && error.message ? String(error.message) : String(error || 'Unknown error');
    const result = {
      finalVerdict: 'inconclusive',
      hardeningError: code,
      note: message,
      execution: { context: 'web_worker', failedClosed: true },
    };
    showResult(result, selectedFile);
  }

  async function runScan(file) {
    if (!window.MalGuardWorkerScanner || typeof window.MalGuardWorkerScanner.scan !== 'function') {
      const error = new Error('The MalGuard worker scanner is unavailable.');
      error.code = 'WORKER_SCANNER_UNAVAILABLE';
      throw error;
    }
    return window.MalGuardWorkerScanner.scan(file, 'pro');
  }

  fileInput.addEventListener('change', () => setFile(fileInput.files && fileInput.files[0]));
  clearBtn.addEventListener('click', () => setFile(null));

  for (const eventName of ['dragenter', 'dragover']) {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      if (!busy) dropzone.classList.add('dragging');
    });
  }
  for (const eventName of ['dragleave', 'drop']) {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      dropzone.classList.remove('dragging');
    });
  }
  dropzone.addEventListener('drop', event => {
    if (busy) return;
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) setFile(file);
  });

  scanBtn.addEventListener('click', async () => {
    if (!selectedFile || busy) return;
    setBusy(true);
    try {
      const result = await runScan(selectedFile);
      showResult(result, selectedFile);
    } catch (error) {
      showError(error);
    } finally {
      setBusy(false);
    }
  });

  selfTestBtn.addEventListener('click', async () => {
    if (busy) return;
    setBusy(true);
    try {
      const fixture = new File(['print("MalGuard harmless platform self-test")\n'], 'malguard-self-test.lua', { type: 'text/plain' });
      const result = await runScan(fixture);
      showResult(result, null);
    } catch (error) {
      showError(error);
    } finally {
      setBusy(false);
    }
  });

  platformBadge.textContent = detectPlatform();
  setFile(null);
})();
