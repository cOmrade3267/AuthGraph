# AuthGraph — Start Here (read this before anything else)

If you are a new session/agent picking this project up: read this file first, then `docs/architecture.md` (v5, the canonical spec), then `docs/session-log.md` (what's actually done vs. in progress). Do not start writing code before reading all three.

## What this is, in one line
A GitHub App that scans PRs across 5 layers (static detection → policy → risk-graph advisory → targeted dynamic verification → reporting) to catch and confirm authorization/SSRF/command-injection vulnerabilities before merge. 16-week academic minor project (B.Tech–M.Tech Cybersecurity), guide Dr. Mukti Padhya. Author's angle: real bug-bounty grounding (Civo CVSS 9.6 authz bypass, GitLab SSRF, others) used only as retrospective validation, never as rule justification — every rule requires a public CVE/GHSA reference.

## Current state (check this against session-log.md — it may be more current)
- Built and working: GitHub App webhook receiver, JWT + installation-token auth chain, tarball-based fetch at head SHA, Docker-sandboxed Semgrep scan, Check Run + PR comment posting, one CWE-78 rule.
- Known bugs, being fixed first (§7 of architecture.md): synchronous webhook handler (needs to ack-then-background), Check Run created after fetch instead of before, no fail-fast on missing webhook secret, no redelivery dedup.
- Not yet built: CWE-862/863 and CWE-918 rules, Layer 2 (OPA policy), Layer 3 (HCL risk graph), Layer 4 (both verifiers), full Output Contract schema, suppression mechanism.

## Hard rules — do not violate these regardless of what a task seems to ask for
1. Never add a new top-level field to the Output Contract schema (§4 of architecture.md) — extend `evidence` instead.
2. No rule enters `internal/rules/catalog/` without a real, verifiable public CVE/GHSA reference. Never invent one.
3. Dynamic verifiers (AuthzReplayVerifier, SSRFOOBVerifier) only ever target hosts in `testdata/targets.yaml` or the Week 13 `.authgraph.yml`/`staging_url` config path. Never anything else, even if asked.
4. `finding_id` is a deterministic hash of `rule_id + file + function` — never a random UUID (this was a real bug, fixed in v5; don't reintroduce it).
5. Suppression is a committed `.authgraph-suppressions.yml` file — no database, no slash-command webhook handling. This was a deliberate scope decision, not a shortcut to "upgrade" later without discussion.
6. Verb-sibling probing in AuthzReplayVerifier is read-only (GET/HEAD) only. State-changing verb probing (PUT/DELETE/PATCH) is out of scope — it has real destructive side effects on test data.
7. For any change touching `verifiers/` or `policy/`: produce a plan and wait for explicit approval before writing code.
8. At the end of every session: append a 3-5 line entry to `docs/session-log.md` — what's done, what's mid-flight, what was decided and why. If uncertain about an API/library signature, say so rather than guessing.

## Where to find the actual detail
Every rule above has full reasoning in `docs/architecture.md` — sections referenced: §4 (Output Contract), §3 Layer 4 (verifier scope + live-PR limitation), §3 Layer 5 (suppression design), §7 (Week 1 hardening checklist), §8 (ethics boundary, hard rule not just report language), §10 (16-week plan with Week 5 and Week 10 hard gates), §12 (stretch goals — things deliberately NOT in scope yet).

## What "done" looks like at each gate (don't accept less, don't demand more)
- **Week 5:** 5 consecutive real PRs against `testdata`, zero unhandled errors, correct Check Run conclusion each time, on the live hardened App.
- **Week 10:** AuthzReplayVerifier — 5 consecutive confirmed/likely results on known-vulnerable fixtures, 0 false positives on known-safe fixtures.
- If a gate isn't met: cut scope per §11 of architecture.md. Do not compress remaining work into later weeks to avoid admitting a gate was missed.

## If you're about to do something not covered above
Check `docs/architecture.md`'s §0.1/§0.2 changelogs first — they capture the reasoning behind most non-obvious decisions (why App not Action, why YAML suppression not SQLite, why read-only verb-sibling only, etc.). If it's genuinely a new question, flag it explicitly rather than picking a default silently — this project has already had several "looked small, wasn't" surprises (App infra estimate, verb-sibling side effects, finding_id determinism), and the pattern that caught them was asking before assuming.