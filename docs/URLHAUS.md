# Optional URLhaus lookup

This adapter queries URLhaus metadata only. It does not visit the supplied URL,
download samples, submit reports, or change the scanner's verdict. No URL lookup
is added to the UI, server routes, or automatic scan pipeline in this change.

`ThreatIntelService.lookupUrl(url, { consent: true })` exposes a separate method
without changing the existing MalwareBazaar hash response contract. This is a
provisional integration point for issue #130; maintainers can review it before
deciding whether to adopt a provider-keyed result object.

## Consent and credentials

Every lookup requires the literal boolean `consent: true`. Without it, the
adapter returns `not_checked` without reading credentials or making a request.
A future caller must explain the privacy tradeoff and obtain the user's informed
consent before setting this flag. Merely configuring an API key is not consent.

An enabled lookup sends the full supplied URL, including its path and query, to
abuse.ch. URLs can contain confidential identifiers and tokens. Do not enable
lookup for sensitive URLs. URLs containing username/password fields are rejected.
The service uses the existing abuse.ch credential store, sends the key only in
the `Auth-Key` header, and refuses redirects. It does not log indicators,
credentials, response bodies, or exception messages, or cache URL results.

## Result contract

All results contain `provider: 'urlhaus'`, a source attribution URL, and `status`:

| Status | Meaning |
| --- | --- |
| `matched` | A validated URLhaus record matched the exact supplied indicator. |
| `no_match` | URLhaus explicitly returned `no_results`. This is not a safe verdict. |
| `unavailable` | Credentials, network, HTTP, or timeout prevented a result. |
| `invalid_response` | The response was malformed, too large, or inconsistent. |
| `not_checked` | Consent was absent or the indicator failed local validation. |

Matched results include a URLhaus reference, upstream URL status and threat, and
the upstream `date_added` as `upstreamTimestamp` when present in the documented
format (otherwise `null`). The timestamp is when the record was added, not a
freshness guarantee. Offline records still count as matches. Failures never
produce `no_match`, `clean`, or `safe`; downstream callers must preserve that
distinction. This adapter alone does not enforce scanner blocking policy.

The default deadline is 8 seconds across credential retrieval, fetch, and body
reading. Responses are streamed with a 256 KiB default byte limit. No live API
validation is claimed. Exact indicator comparison intentionally rejects response
normalization differences rather than manufacturing a result.

## Tests

```sh
node tests/urlhaus-client.test.js
node tests/run-all.js
```

Tests use mocked fetch and harmless `example.invalid` indicators. No live key,
API request, malware download, or sensitive user data is needed.

API reference: https://urlhaus-api.abuse.ch/ (URL information query, reviewed
October 25, 2026). The adapter uses the documented POST `/v1/url/` endpoint and
form field `url`. Check abuse.ch's current access and fair-use terms before deployment.
