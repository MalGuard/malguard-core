# MalGuard Native App

MalGuard App is a native installable build of the official MalGuard production interface.

- Website: https://malguard.github.io/
- The installed app bundles a locked snapshot of the production website.
- The app must not introduce a second product UI.
- The app must not remove or invent site features.
- Site content, navigation, typography and product status remain the UI source of truth.

## Offline model

Internet is required to download the installer or receive online-only data, but it is not required to launch the installed interface.

At build time:

1. `site-lock.json` identifies one exact commit of `MalGuard/malguard.github.io`.
2. `scripts/prepare-offline-site.js` fetches exactly that commit.
3. Only the same approved production files used by GitHub Pages are copied into the native app.
4. Critical remote runtime assets are rejected. The current remote Earth background is replaced with MalGuard's versioned local Earth asset.
5. `offline-ai/model-lock.json` pins the Local AI model repository, commit, quantization, byte size and SHA-256.
6. `scripts/prepare-offline-ai.js` builds one verified offline AI asset set.
7. The exact same AI asset set is staged into Android, iOS, Windows and macOS packages.
8. Android/iOS and Windows/macOS load the copied local files and local AI model, not the live website or cloud AI endpoint.

Each bundle contains `OFFLINE-SOURCE.json` with the locked website source.

## Targets

- Android / Samsung: Capacitor native container
- iPhone / iPad: Capacitor native container
- Windows: Tauri 2 native desktop container
- macOS: Tauri 2 native desktop container
- Linux: planned from the same local desktop bundle

## Security boundary

Bundled website content receives no privileged native shell, filesystem or process capability by default.

- No shell/command execution permission
- No arbitrary filesystem permission
- No arbitrary native plugin bridge
- Tauri capabilities stay empty until a narrowly-scoped local feature is explicitly reviewed
- The build fails if a required runtime script or CSS/image asset still depends on a remote URL

## Offline capability boundary

The installed app is designed to launch and provide its core local experience without internet:

- The complete MalGuard website interface is bundled locally.
- Browser-local tools such as URL-text inspection and SHA-256 fingerprinting remain local.
- Malware AI uses the existing MalGuard Local tier, Qwen2.5-0.5B-Instruct, bundled inside the app.
- Transformers.js and ONNX Runtime Web assets are bundled locally.
- Runtime model downloading is disabled.
- Runtime external fetches are blocked by the offline app bootstrap unless they are same-origin local requests.

Explicit internet features are not disguised as offline capabilities. Web search, live network intelligence, GitHub/release navigation and other fresh remote data still require connectivity and must fail clearly when offline.

## Distribution

Do not connect a public Get MalGuard button to an artifact until that platform artifact is built, verified and published through the release process.
