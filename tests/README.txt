MalGuard test notes
===================

Automated tests:
  node tests/run-tests.js

Suites:
- script-analyzer.test.js
  Original ScriptAnalyzer + direct app + ZIP integration regression suite.
- regression-corpus.test.js
  22-file Lua/C# false-positive, suspicious, malicious-synthetic and malformed-input corpus.
- web-worker.test.js
  Simulates a DedicatedWorkerGlobalScope in Node VM, loads the real scan-worker.js,
  imports the real MalGuard modules, and exercises Pro Lua, Free Engine and Pro ZIP paths.
  Also tests scan-worker-client.js worker messaging and main-thread compatibility fallback.
- build-validation.test.js
  Parses every JS file, validates JSON/corpus references, index.html script references,
  inline JavaScript, worker-client order, UI routing, and main-thread lexical coexistence.

Manual browser smoke page:
  tests/worker-browser-smoke.html

Serve the project from HTTP(S), then open that page. Browsers generally do not allow
Dedicated Workers correctly from file:// URLs.

Important:
The automated environment used for this build blocks localhost navigation from its
headless browser sandbox. Therefore the real-browser smoke page is included but was
not counted as an executed automated test. The Worker host/protocol itself was tested
with the real project scripts in an isolated VM worker simulation.

IPHONE / REAL-BROWSER VALIDATION
--------------------------------
Serve the project directory over HTTPS and open:
  /tests/iphone-browser-audit.html

This page is intended for Safari/Chrome on iPhone and other real browsers. It displays PASS/FAIL on-screen and records a raw JSON report, so desktop DevTools are not required. It exercises the live MalGuard Self-Test, Dedicated Worker startup and isolation, benign and suspicious scans, ZIP fixture analysis, the client concurrency gate, abort/recovery, and browser Worker crash/termination semantics.

Do not treat file:// execution as a valid browser acceptance result. Use an HTTPS origin (or localhost during desktop development).
