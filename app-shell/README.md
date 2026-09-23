# MalGuard Native App Shell

MalGuard App is a native installable shell around the official production site:

- Production UI: https://malguard.github.io/
- The app must not introduce a second product UI.
- The app must not remove or invent site features.
- Site content, navigation, typography and product status remain the source of truth.

## Targets

- Android / Samsung: Capacitor native container
- iPhone / iPad: Capacitor native container
- Windows: Tauri 2 native desktop container
- macOS: Tauri 2 native desktop container
- Linux: structure is compatible with Tauri but public distribution remains a later release decision

## Security boundary

This shell intentionally exposes no privileged native bridge to remote web content.

- No shell/command execution permission
- No filesystem permission
- No arbitrary native plugin access
- HTTPS production origin only
- Native capabilities must be reviewed before they are added

## Mobile

See `mobile/`.

The Capacitor shell loads the official HTTPS production origin. The local `www/` directory exists only because Capacitor requires a web directory during project setup; it is not a separate MalGuard UI.

## Desktop

See `desktop/`.

Tauri uses the official production URL as its external frontend. The initial app declares no Tauri capabilities for remote content.

## Distribution

Do not connect Get MalGuard download buttons to a platform until a real platform artifact exists and passes its release checks.
