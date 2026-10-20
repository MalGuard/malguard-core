## Summary

Describe the smallest user-visible or testable change and link the relevant issue (e.g., `Closes #123` only if it truly closes it).

## Change category

- [ ] Documentation / contributor experience
- [ ] Harmless synthetic test
- [ ] Bug fix
- [ ] Security-sensitive behavior (requires extra review)

## Validation performed

List the exact commands and outcomes. Do not mark tests as passed unless you ran them.

- [ ] `node tests/version-consistency.test.js` (if applicable)
- [ ] `node tests/run-all.js` (if applicable)
- [ ] Platform-specific or focused checks (describe below)
- [ ] Not run (explain why)

Test output and limitations:

## Safety and release checklist

- [ ] No real malware was downloaded, uploaded, or executed.
- [ ] No secrets, private keys, sensitive logs, credentials, or personal data were added.
- [ ] No security verdict, fail-closed rule, code-signing requirement, or release-integrity control was weakened.
- [ ] No hidden telemetry, network calls, build dependency, or executable lifecycle script was introduced.
- [ ] Changes to unsigned/signed-release wording remain accurate.
- [ ] I understand that opening a PR does not imply approval, CI success, or release authorization.

## Screenshots or documentation changes (optional)

Include only non-sensitive material.
