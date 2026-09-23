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
5. Android/iOS and Windows/macOS load the copied local files, not the live website.

Each bundle contains `OFFLINE-SOURCE.json` with the locked website source.

## Targets

- Android / Samsung: Capacitor native container
- iPhone / iPad: Capacitor native container
- Windows: Tauri 2 native desktop container
- macOS: Tauri 2 native desktop container
- Linux x64: offline AppImage and DEB preview packages from the same local desktop bundle

## Security boundary

Bundled website content receives no privileged native shell, filesystem or process capability by default.

- No shell/command execution permission
- No arbitrary filesystem permission
- No arbitrary native plugin bridge
- Tauri capabilities stay empty until a narrowly-scoped local feature is explicitly reviewed
- The build fails if a required runtime script or CSS/image asset still depends on a remote URL

## Offline capability boundary

The interface, navigation, documentation and browser-local tools can run without internet once installed. Features that inherently require a remote service, such as cloud AI, web search, release downloads or live network intelligence, still require connectivity until a reviewed local engine exists. Android, Windows, macOS and Linux packages use the same pinned offline website snapshot; iOS uses the same bundle but physical-device distribution still requires Apple signing.

## Distribution

Do not connect a public Get MalGuard button to an artifact until that platform artifact is built, verified and published through the release process.
