# Agent Memory Guard — prelaunch RFC (planning only)

**Owner:** MalGuard · **Planning window:** 2026-10-30 through 2026-11-04 UTC · **Implementation starts:** 2026-11-05 · **Target v0.1 review:** 2026-12-04.

> **Status:** PROPOSED / NO IMPLEMENTATION. This is a scoped plan, not an assertion that features exist. GTA Guard remains supported; this project is an independent defensive product under the MalGuard umbrella.

## Problem and positioning

AI coding agents ingest untrusted web results, files, tool outputs, repository instructions, and persisted conversation summaries. A malicious instruction that is saved or repeatedly replayed as agent memory can influence future actions long after the initial input. This product is a **local provenance and policy gate**, designed to help developers inspect and approve memory changes and sensitive tool actions. It is *not* a malware scanner and does *not* promise universal prevention of prompt injection.

**Differentiator:** every stored memory item gets provenance + approval status, and decisions are recorded in a privacy-preserving audit log; enforcement is checked at the actual tool-action boundary. Read-only inspection is not the same as blocking a tool call.

## Scope for v0.1 / explicit non-goals

| v0.1 in scope | Deferred |
| --- | --- |
| Python 3.11+ local service and CLI | SaaS accounts, cloud sync, browser extension |
| SQLite-backed memory records and append-only decision log | General-purpose vector database |
| Deterministic search with SQLite FTS5 and provenance filters | Semantic embeddings until privacy/cost/evaluation justified |
| YAML policy schema with validation, bounded inputs, dry-run simulator | Arbitrary Python/shell expressions in policy files |
| MCP adapter exposing read-only inspection and explicit gated actions | Claiming native interception of every Codex/Claude action |
| Synthetic attack fixtures and repeatable evaluation report | Real malware, real secrets, destructive benchmark commands |
| Documented package build, reproducible install and tagged release | Publishing npm and PyPI packages unless there is a real JS client |

**Safety boundary:** tool execution may occur only through a host/adapter that actually routes requests through the policy engine. If the host can bypass the adapter, clearly label the protection **advisory only**. Deny by default on invalid policy, unknown action, storage failure, missing evidence, timeout, or approval-system failure. Never silently downgrade a denial to a warning.

## Security design

1. **MemoryStore:** SQLite transactions, parametrized statements, per-record ID, source URI/type, acquisition timestamp, SHA-256 digest, actor/approval state, sensitivity flags and immutable revision history. SQLite WAL where appropriate; no plain-text credential collection. Input-size and retention limits.
2. **PolicyEngine:** YAML parsed with a safe loader; versioned JSON-schema-like validation; typed actions (e.g. `shell.execute`, `filesystem.write`, `database.write`, `network.send`, `memory.persist`). An outcome is `ALLOW`, `DENY` or `REQUIRES_APPROVAL`, with stable reason code. **Match canonical structured arguments**, not just substring search for `rm -rf`; use harmless synthetic data in tests.
3. **Approval gate:** obtain explicit approval for sensitive actions from the actual end user; scoped to exact action parameters, actor/session, expiry and one-time nonce. A model's self-approval is invalid. No unattended approval of DB writes.
4. **Audit:** JSON Lines with event ID, UTC timestamp, action type, hashed request ID, policy version, decision, rule ID and redacted evidence. Never log bearer tokens, environment variables, full prompts, personal data or command output by default. Define retention/rotation.
5. **MCP integration:** permissions are restrictive and resources read-only by default. Test Codex CLI and Claude Code separately with publicly documented supported MCP interfaces. A generic MCP server with advice tools is **not** proof of enforcement.
6. **Threat model:** untrusted retrieval/web pages, poisoned local context files, replayed memory, forged source claims, policy bypass and compromised integrations. Out of scope: a malicious host with full local-admin rights, arbitrary unsandboxed execution outside the adapter, provider-side model behavior.

## Four workstreams + maintainer

| Role | Delivery & acceptance |
| --- | --- |
| Maintainer | Own product threat model, minimal API contract, scope control, release approvals, application claims |
| Contributor 1 | SQLite record store, provenance, transactions, FTS5, migrations, tests |
| Contributor 2 | Typed YAML policies, safe parser, deny/approval precedence, negative tests |
| Contributor 3 | Redacted JSON audit log, metrics, eval harness, deterministic fixtures |
| Contributor 4 | CI, packaging, security baselines, release provenance, docs & demo |

**Ownership rule:** a person is assigned only after accepting the role and a realistic time commitment. Do not report five active contributors merely because five roles exist.

## Schedule / acceptance gates

### Prelaunch · Oct 30 – Nov 4
- [ ] Close or explicitly defer current MalGuard AI account-quota/model deployment and site CI problems.
- [ ] Review existing collaborator statuses; invite only where needed, without asserting acceptance.
- [ ] Agree on the threat model and success criteria; no substantive implementation before Nov 5.
- [ ] Decide project repository/name under MalGuard; confirm package-name availability before publication.
- [ ] Gather only synthetic fixtures and non-sensitive reference documentation.

### Week 1 · Nov 5 – Nov 11 — base
- [ ] Independent repository with an OSI-approved license (MIT intended), README, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, threat model.
- [ ] SQLite MemoryStore with provenance; PolicyEngine with typed YAML actions; JSON audit records.
- [ ] Minimal CLI `inspect` / `evaluate`, pip-installable prerelease or reproducible local installation.
- [ ] GitHub Actions using least privileges, dependency scanning, Python unit tests and reproducible synthetic demo.
- **Gate:** all documented deterministic acceptance tests pass on a fresh clone; no unsupported enforcement claims.

### Week 2 · Nov 12 – Nov 18 — adapters
- [ ] MCP inspection adapter; verify Codex CLI and Claude Code connections using documented host configurations.
- [ ] Prove a policy *enforcement* path through an explicit action proxy, or state advisory-only limitations prominently.
- [ ] Add failure, timeout, restart, concurrent approval and auth-boundary tests.
- [ ] Release v0.1 to PyPI **only if** package ownership, publishing credentials and install tests are verified. npm is optional.
- **Gate:** one safe demo per host; disabled adapters cannot be mistaken for working enforcement.

### Week 3 · Nov 19 – Nov 25 — early users
- [ ] Publish a short demo with harmless simulated actions; release two reproducible technical write-ups.
- [ ] Invite external review through appropriate technical communities; respond to genuine issues/PRs.
- [ ] Track installs, real users, reproducible failures and contributor PRs without paid/fake engagement.
- **Gate:** usability feedback and a documented, prioritized bug list. Stars/downloads are observations, not guaranteed milestones.

### Week 4 · Nov 26 – Dec 4 — hardening and evidence
- [ ] Run a **fixed public synthetic fixture corpus** + hold-out set; report per-class blocked, allowed, false-positive, false-negative and inconclusive counts.
- [ ] Add cross-platform smoke tests, dependency update policy, and signed/provenance-aware release if ready.
- [ ] Document policy bypass cases, host limitations and residual risk.
- [ ] Prepare a Cybersecurity Grant proposal and separate Codex for OSS application from **verified** metrics and links.
- **Gate:** reproducible evaluator, pinned commit and version, installable release and accurate limitations. No promise of grant acceptance.

## Evaluation specification

Define ground truth **before** running tests, split by threat class and honest negatives; never update the answer key to improve a score. Report:
- `blocked_true_positive / malicious_total` (attack-block rate);
- `blocked_false_positive / benign_total` (false-block rate);
- `inconclusive / total` (coverage);
- p50/p95 policy latency on a specified machine;
- number of verified host adapters, independent testers, releases and external contributors.

Include failures, baseline comparisons and a reproducibility command; avoid cherry-picked screenshots or inferred real-world protection from synthetic pass rates.

## Application-evidence package (not eligibility promises)

Keep URLs to the license, tagged release, source and test commits, CI run, security policy, reproducible demo, exact measured download counts and actual external contributor work. Track whether Codex was really used on review/maintenance tasks, with evidence of human review. **No star threshold, 90-day activity rule, download level, grant, credits or free Pro access is guaranteed.** Cybersecurity Grant and Codex for OSS are separate applications; do not cite one program's confirmation as the other's.

## Repository merge discipline

MalGuard Core's main-integrity and trusted-release workflows require **two-parent GitHub PR merge commits** on `main`. Do not select squash/rebase merge: it produces a single-parent main commit and blocks trusted release checks even for documentation-only changes. Never weaken or bypass the integrity workflows to make a merge pass. Verify the resulting commit topology and main CI after merge.

## Release blockers

- Hard-coded or leaked credentials, absent production secret rotation, shared user quota, missing tenant isolation.
- Policy bypass, unverified MCP enforcement, unsafe YAML execution, lack of approval binding, uncontrolled logs.
- Red CI, failed install, unexplained provider costs, unauthenticated quota endpoints, non-repeatable demo.
- Team member acceptance not confirmed, untested host support, fabricated metrics.

**Decision log:** 2026-10-30 — prioritize finishing existing MalGuard work and preparing only infrastructure through Nov 4; begin new product implementation on Nov 5.
