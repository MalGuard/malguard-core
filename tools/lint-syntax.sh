#!/usr/bin/env bash
# Curated node --check for top-level and desktop-app entry JavaScript.
# Broader CI also runs node --check across *.js; keep this list small and maintainable.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

files=(
  app.js
  engine.js
  multilayer.js
  malguard-contract.js
  archive-entry-reader.js
  archive-inspector.js
  gta-mod-detector.js
  scan-worker.js
  scan-worker-client.js
  script-analyzer.js
  self-test.js
  desktop-app/server.js
  desktop-app/local-scan-upload.js
  desktop-app/pro-scan-pipeline.js
  desktop-app/scanner-bridge.js
  desktop-app/settings-store.js
  desktop-app/sandbox/isolation-readiness.js
)

for f in "${files[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "lint:syntax: missing expected file: $f" >&2
    exit 1
  fi
  node --check "$f"
done

echo "lint:syntax: ok (${#files[@]} files)"
