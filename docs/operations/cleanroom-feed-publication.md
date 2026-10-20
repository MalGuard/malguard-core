# Authenticated clean-room feed publication

## Failure classification

The `Clean-room MalGuard online desktop and signed intelligence` workflow first
verifies `cleanroom-v1/source.zip` against `source.json`, unpacks it and installs
the hash-locked dependency graph. The CI entrypoint
`tools/ci/publish_cleanroom_feed.py` then runs that verified publisher, forwarding
its arguments. Signing, metadata validation, accumulation limits and rollback
checks stay in the archived publisher.

The entrypoint emits a fixed diagnostic and exits unsuccessfully when the
publisher raises an HTTP error. It does not print the exception's URL, reason,
headers or body, because upstream details can contain sensitive data or workflow
commands. No HTTP failure is converted into a successful or empty publication.
The following GitHub publication step still requires a successful prior step.

| Response | Meaning established by that response | Operator action |
| --- | --- | --- |
| 401 / 403 | The metadata request was denied. The response alone does not establish whether the key, account entitlement or another provider access policy is responsible. | Check the configured `MALGUARD_ABUSECH_AUTH_KEY` and provider-side account access through authorized administration. Never put its value into an issue, log or PR. |
| 429 | The request was rate-limited. | Check permitted usage before retrying; do not bypass limits with extra accounts or fallback endpoints. |
| 5xx | The upstream service returned a server error. | Check service availability before a later retry. |
| Other HTTP error | The metadata request did not complete successfully. | Investigate transport and the documented metadata API; do not disable authentication or redirect rejection. |

Do not infer that a 403 proves a signing-key problem. In the publisher's `main`,
metadata is fetched before `build_snapshot` verifies and uses the provisioned
Ed25519 key. A rejected fetch does not reach that signing operation.

Existing cached signed data must remain subject to the application's freshness,
signature and rollback policy. Do not re-sign old data with a new timestamp to
make a failed refresh look successful. Do not remove the record budget, signature
checks, source integrity check or hash locking to get a green workflow.

The Windows jobs have `if: github.event_name != 'schedule'`. Their `skipped`
status in a scheduled run is intentional and does not demonstrate a failed
Windows build. Evaluate native Windows build/runtime evidence separately.

## Safe verification

Run the entrypoint's isolated subprocess tests without credentials or network:

```sh
python -m unittest discover -s tests/ci -p 'test_cleanroom_feed_ci.py' -v
node tests/workflow-supply-chain.test.js
node tests/public-release-policy.test.js
```

Fixtures are inert Python publishers created in a temporary directory. Tests
check argument/output forwarding, seven HTTP statuses, suppression of upstream
details and annotation injection, nonzero failure status, preservation of the
prior output fixture on failed fetches, and propagation of non-HTTP signing
failures. They do not test the live provider, actual credentials, cryptographic
signing or Windows installation and do not establish malware detection efficacy.

Before restoring production publication, an authorized operator must establish
that the configured provider access works and that the required signing
configuration remains valid. Only a successful authenticated fetch followed by
the existing verification/signing/publishing gates establishes a successful
refresh. Authenticode signing of a Windows installer is a separate process.

## Day 1 checkpoint — 2026-10-20, Asia/Tehran

- Core main inspected: `9ab2907f61103d92f3fc51e6408a1b8381406a1b`.
- Website main inspected: `028ce0faacc184eb9d751c51da9ab4d284286710`.
- Recent commits, all returned open PRs (12 core / 14 website), five recently
  closed PRs and five recent workflow runs per repository were inspected.
- No in-progress core workflow was returned before edits. Open core PR #99
  concerns desktop threat-intelligence files, not this clean-room publication
  entrypoint. Website changes were left to the existing work there.
- VERIFIED: [run 39378461858](https://github.com/MalGuard/malguard-core/actions/runs/39378461858),
  job `118481806230`, failed on `fetch_metadata` with `HTTP Error 403: Forbidden`.
  The unpacked publisher source confirms a metadata-only `recent_detections`
  request to the official API and no sample download in that path.
- REVIEWED: [provider API documentation](https://bazaar.abuse.ch/api/) requires an
  Auth-Key and describes fair-use/commercial access considerations. It does not
  identify why this repository's request was rejected.
- BLOCKED: live provider authorization is unresolved. Credential values and
  provider-account settings were not inspected, changed or requested from the
  user; this execution environment has no configured provider binding.
- NOT TESTED: live authenticated refresh, signing with the production key,
  Windows x64/ARM64 installation and production/download runtime verification.
- No source archive, source manifest, published feed, release asset or website
  was modified by this diagnostic change.

Next: check the PR and its exact-commit CI, resolve authorized provider access
without weakening gates, and continue Day 2's capability/PR inventory and
acceptance protocol from the then-current repository state. A passing diagnostic
test does not resolve the upstream 403 or establish release readiness.
