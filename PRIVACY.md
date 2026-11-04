# MalGuard Privacy Policy

MalGuard is designed to keep supported file analysis local by default.

## Local analysis

Files selected for local scanning are analyzed on the user's device unless the user explicitly chooses a feature that states otherwise.

## Network features

Some optional features may contact configured services for purposes such as:

- checking for signed software updates;
- retrieving threat-intelligence metadata;
- looking up a file hash or other non-file metadata against a configured reputation service.

A file itself must not be uploaded to a third-party service without an explicit user action and clear disclosure.

## Diagnostics

MalGuard's error-reporting design is local-first. Diagnostic information is not automatically published by this repository. Users may choose to export or submit diagnostics when asking for support.

## Anonymous release metrics

Official Windows download buttons may use GitHub Release assets so GitHub can expose aggregate download counts.

This metric is **off by default (opt-in)**. Only when the user enables it, packaged Windows builds make one request after the first successful launch to a small, static GitHub Release beacon asset. MalGuard does not attach a user, device, advertising, or installation identifier to this request, and no scanned file or scan result is included. A local marker stored alongside MalGuard settings prevents the same installation from intentionally sending the beacon again.

GitHub may receive standard network metadata, such as the source IP address, as part of serving the public asset under GitHub's own service policies. Users can opt in by setting `MALGUARD_ENABLE_ANONYMOUS_INSTALL_COUNT=1`; `MALGUARD_DISABLE_ANONYMOUS_INSTALL_COUNT=1` always forces it off.

## Anonymous compatibility report

This report is **off by default (opt-in)**. Only when the user enables it, packaged Windows builds send one coarse compatibility report after the first successful launch. The report contains only the MalGuard version, Windows build, x64/ARM64 architecture, a bucketed CPU-core range, a bucketed RAM range, and the system language.

The report does not include an account name, computer name, hardware serial number, network adapter identifier, precise location, file path, scan result, or installation identifier. MalGuard stores only a local marker so the same installation does not intentionally send the report again.

The server may forward the report as an administrative notification email when the notification service is configured. Users can opt in by setting `MALGUARD_ENABLE_ANONYMOUS_COMPATIBILITY_REPORT=1`; `MALGUARD_DISABLE_ANONYMOUS_COMPATIBILITY_REPORT=1` always forces it off.

## Uninstalling

Remove installer builds with the uninstaller the installer registers in Windows, or delete the folder for portable builds. MalGuard settings and local markers live in the MalGuard settings folder and can be removed with it.

## Changes

If a future release introduces new data collection, telemetry, or external transfer behavior, this policy and the user-facing disclosure must be updated before that behavior is enabled in a public release.
