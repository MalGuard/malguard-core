# Running tests

You do not need to start with the full test suite. Run the smallest relevant test
while you work, then use the full suite for broader validation when your platform
supports it.

## Run one focused test

Run a test file directly with Node.js from the repository root:

```bash
node tests/version-consistency.test.js
```

For changes to the script analyzer, you can instead run its synthetic-fixture
test:

```bash
node tests/script-analyzer.test.js
```

Other available test files are listed in [`tests/run-all.js`](../tests/run-all.js).
Do not use real malware, unknown files, secrets, or personal data as test inputs.

## Run the full suite

To run all test programs listed by the test runner:

```bash
node tests/run-all.js
```

Some tests are platform-dependent, so the full suite may not pass in every
development environment. Report unsupported platforms and failures accurately.
Do not bypass or weaken a security check to make the suite pass.

## Report a failure safely

When reporting a failure, include:

- Operating system and version
- Node.js version from `node --version`
- Exact command you ran
- Exact test file that failed
- Sanitized error output and any relevant stack trace
- Whether the focused test, full suite, or both were run

Remove usernames, sensitive local paths, tokens, API keys, user data, and other
secrets before posting logs. Never upload suspicious files or malware samples.
If a failure may reveal a vulnerability, follow [`SECURITY.md`](../SECURITY.md)
and report it privately.

If you could not run a test, note that in the pull request instead of marking it
as passed.
