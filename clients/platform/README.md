# MalGuard Platform Clients

This package builds three MalGuard client shells from one hardened local-scanner UI:

- Android: Capacitor WebView app, file-picker based local scanning.
- iOS/iPadOS: Capacitor WKWebView app, Files-picker based local scanning.
- macOS: hardened Electron app with Node integration disabled and renderer sandboxing enabled.

The shared scanner uses the existing MalGuard browser worker. Selected content is statically analyzed inside a Dedicated Web Worker and is never executed by these clients.

## Important platform boundary

iOS and Android do not allow a third-party app to inspect every installed app/process or act like a Windows endpoint security driver. This client therefore scans only files explicitly selected by the user. The current macOS client intentionally ships the same local static analysis surface while native macOS endpoint protection is developed separately.

Windows Sandbox behavioral execution is not exposed in these builds. Unsupported capabilities must stay visibly unavailable instead of silently falling back to unsafe execution.

## Build

```text
npm install
npm run build:web
```

Android CI then generates a Capacitor Android project and builds a debug APK. iOS CI generates a Capacitor iOS project and builds an unsigned Simulator app. macOS CI packages arm64 and x64 `.app` bundles. Device/App Store iOS distribution and signed/notarized macOS distribution require platform signing credentials and are intentionally not stored in this repository.
