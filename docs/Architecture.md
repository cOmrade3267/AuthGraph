# AuthGraph — Architecture & Scope Specification (v5)

**Status:** Locked for build continuation. v5 fixes a correctness bug in v4's suppression design (`finding_id` determinism) plus two scheduling cleanups. This is the single canonical spec.

**Guide:** Dr. Mukti Padhya (preferred, pending confirmation)
**Timeline:** 16 weeks
**Builds on:** SentryGrep (Go-based GitHub App: webhook receiver, JWT/installation-token auth chain, tarball-based commit fetch, Docker-sandboxed Semgrep scan, Checks API, PR comments). This is direct code reuse via git history, not a rebuild.

**Pitch line (interviews/resume):** "Automated confirmation of authorization vulnerabilities via structural response-replay diffing, delivered as a GitHub App that gates PRs before merge, with dynamic verification demonstrated against seeded validation environments."

---

## 0. What Changed From v2 (read this first)

- v2 assumed Layer 1's App infrastructure (webhook/JWT/Checks) was **unbuilt, high-risk, ~1.5–2.5 weeks of new work**. It is actually **already built**, in Go, on branch `test-webhook-trigger`: webhook signature verification, App JWT generation, installation token exchange, tarball fetch at head SHA, Docker-sandboxed scan invocation, Check Run creation/completion, PR comment posting.
- This retires the Action-vs-App debate. **App is the confirmed architecture.** No fallback to Action is planned.
- Known bugs in the current build (must fix in Week 1, not deferred):
  1. **Synchronous webhook handler** — GitHub's delivery has a short timeout window; a 3-minute Docker scan run inline will cause GitHub to report failed/timed-out deliveries even though the server is working correctly. Must become async (ack immediately, process in background).
  2. **Check Run created after fetch/extract, not before** — if fetch or extraction fails, the PR gets no check at all, which is worse than a visible failure. Check Run must be the first thing created after event validation.
  3. **No fail-fast on empty `GITHUB_WEBHOOK_SECRET`** — silently weakens signature verification if unset.
  4. **No webhook redelivery dedup** — GitHub may redeliver the same event; no protection yet against double-processing.
- Everything else in v2 (Layers 2–5, Output Contract, validation methodology, ethics boundary) is unchanged and still applies.

## 0.1 What Changed From v3 to v4

A full review of Layer 4/5 design surfaced gaps in what was still implicit rather than decided. v4 closes them:

1. **Layer 2 testability gap** — confidence-branching untestable until Layer 4 exists (Week 9+), but the Week 5 checkpoint claimed to validate Layer 2. Fixed: synthetic/injected-finding test harness added at Week 4 (§3, Layer 2).
2. **Layer 3/host sandbox boundary** — the "untrusted code never touches host" security claim (§13) only held for the scanner, not for Layer 3's HCL parsing unless deliberately matched. Decision point added (§3, Layer 3).
3. **Target-app orchestration invisible in the plan** — seeding/reset work for `testdata` and 3 validation repos was assumed-free. Made an explicit Week 9 task line (§10).
4. **Webhook processing correctness** — sync handler, Check-Run-after-fetch ordering, missing secret fail-fast, no redelivery dedup. All folded into §7 as the Week 1 hardening checklist, including a "confirm a real webhook has fired at all" precondition (§7.0).
5. **Measurable checkpoint bars** — "solid end-to-end" replaced with concrete pass/fail counts for both Week 5 and Week 10 gates (§7, §10).
6. **Named external risk** — concurrent coursework/Project 23 load and per-validation-repo seeding difficulty now explicit risks in §11, not hoped around.
7. **Layer 4's live-PR scope was entirely unaddressed.** Both verifiers require a running instance; nothing deploys a PR branch; no config mechanism existed. Now stated as an explicit v1 limitation (§3, Layer 4), with a **minimal proof-of-concept required at Week 13** (not just documented as future work) so the config-driven path is demonstrated at least once, not purely theoretical (§10, §13).
8. **Static-to-dynamic correlation was undefined.** Nothing connected a Layer 1 file/line/function finding to an HTTP request AuthzReplayVerifier could send. Added: router-registration extractor, scoped to one Go framework for v1, with 1:many route handling stated (§3, Layer 4).
9. **Verb-sibling probing was unsafe as scoped.** State-changing (PUT/DELETE/PATCH) replays have real destructive side effects, incompatible with repeatable checkpoint testing. Scoped down to read-only (GET/HEAD) siblings for v1; state-changing probing moved to stretch goals pending transactional test fixtures (§3, Layer 4; §12).
10. **"Gates PRs before merge" was a slight overclaim.** Checks API reports status; actual merge blocking requires the installing repo to separately enable branch protection. Now stated explicitly in Layer 5 and in the viva framing (§3, Layer 5; §13).
11. **Suppression had no persistence layer, and the natural design (SQLite + slash command) didn't fit the Week 12 timeline.** Redesigned as a committed `.authgraph-suppressions.yml` — git history as audit log, no database, no new webhook event type (§3, Layer 5). Cross-push re-flagging (no dedup without persistence) stated as an accepted v1 limitation, not a bug.
12. **Lower-priority stated limitations** — concurrency behavior under simultaneous scans, and no retry on transient scan failure — added as one-line report disclosures rather than left silent (§3, Layer 5).

## 0.2 What Changed From v4 to v5

1. **`finding_id` correctness bug fixed.** A random UUID silently breaks the v4 suppression design (no persistence layer to translate IDs between scans of the same finding). Changed to a deterministic hash of `rule_id + file + function` (§4).
2. **§10 table cleanup.** Week 9's orchestration and verifier-build rows merged into one sequential row, so the plan reads as one week's work rather than two overlapping ones.
3. **Layer 3 sandbox-boundary decision given real slack.** Moved from "before Week 6" (zero buffer, lands exactly when Layer 3 work starts) to explicitly inside Week 5's checkpoint buffer, so it's resolved before Week 6 begins.

---

## 1. What AuthGraph Is

A GitHub App that scans pull requests across five layers — static detection, policy evaluation, risk-graph advisory, targeted dynamic verification, and reporting — to catch and confirm security vulnerabilities before merge, with a bias toward **low false-positive, high-confidence findings** over broad coverage. Delivered as an installable App (webhook-driven), not a per-repo CI script.

## 2. What AuthGraph Is Explicitly NOT

(Unchanged from v2 — restated for completeness.)

- **Not a general-purpose DAST tool.** Layer 4 only verifies findings Layer 1 already flagged.
- **Not multi-language for v1.** Go only. Second-language port is a stretch goal (§12).
- **Not application-type-agnostic.** Verifiers require a running Go HTTP service, REST-style JSON, bearer-token auth, 2 seedable test identities, and (for SSRF) an outbound-request-taking feature.
- **Not tied to the author's personal CVEs as justification.** Every rule cites a public CVE/GHSA reference, validated first. Personal findings live only in `evaluation/case-studies.md`.
- **Not zero-config.** AuthzReplayVerifier requires a per-target ownership-field mapping.
- **Not authorized to test arbitrary live targets.** See §9.
- **Not a synchronous webhook handler.** (New — see §0.) Webhook processing is ack-then-background, not blocking.

## 3. Layer-by-Layer Scope

### Layer 1 — Static Detection + App Delivery (Gate, blocking)

**Already built, reused as-is (with Week 1 hardening — see §7):**
- Webhook receiver with HMAC-SHA256 signature verification (`X-Hub-Signature-256`)
- App JWT generation from private key + App ID
- Installation access token exchange
- Tarball-based fetch of PR code at `head.sha` (avoids TOCTOU issues a branch-ref clone would have)
- Docker-sandboxed scanner invocation (`docker run --rm -v target:ro,z ...`) — this isolation is a genuine plus, worth highlighting in the report as a deliberate security choice (untrusted PR code never touches the host directly)
- Check Run lifecycle (`in_progress` → `completed` with conclusion + Markdown output)
- PR comment posting as a secondary, human-readable channel
- Original CWE-78 rule

**New in this phase:**
- Rule catalog restructured to CWE-first schema (§5)
- CWE-862/863 (authz) and CWE-918 (SSRF) rules added, each validated against a public CVE/GHSA reference first
- Week 1 hardening fixes from §0/§7

**CWE classes in scope (3):**
1. CWE-862/863 — Broken/missing authorization (BOLA/IDOR) — anchor class, grounded in Civo
2. CWE-918 — SSRF — grounded in GitLab finding
3. CWE-78 — Command injection — grounded in Civo CLI fix, already implemented

**Rule requirement (enforced):** No rule enters the catalog without a public CVE/GHSA reference, validated against that reference *before* checking it also catches the author's own finding.

### Layer 2 — Policy (OPA/Rego)
Unchanged from v2. Consumes Layer 1 findings + Layer 3 risk-graph signal. Confidence-aware policy logic: a `confirmed` finding at medium severity can block; an `unconfirmed` finding at high severity only warns pending Layer 4 verification. Missing Layer 3 signal treated as neutral.

**Testability gap, closed at Week 4.** Confidence only takes non-default values once a Layer 4 verifier runs, and Layer 4 doesn't exist until Week 9+. Without a fix, the Week 5 checkpoint can only prove Layer 2's plumbing works with every finding stuck at `unconfirmed` — it cannot prove the confidence-branching logic itself is correct, and a broken branch could pass Week 5 undetected until Week 10. **Fix, built at Week 4:** a synthetic/injected-finding test harness — manually construct findings at each confidence level (`confirmed`, `likely`, `unconfirmed`, `inconclusive`) crossed with each severity, and assert Layer 2 branches correctly, independent of Layer 4 existing. Cheap, and it's what actually validates the interesting part of Layer 2 rather than just the glue.

### Layer 3 — Advisor / Risk Graph
Unchanged from v2. Real HCL parsing (`hashicorp/hcl`), small resource graph (nodes = resources, edges = references), detects new public ingress + new/widened IAM attachment + one graph-traversal-derived signal if time allows. Mermaid DFD rendered from actual graph structure. Explicitly not a general IaC scanner (no Checkov/tfsec breadth).

**Sandbox boundary — decide now, not when asked in viva.** §13's security framing claims "untrusted PR code never touches the host," grounded in the Docker-sandboxed scanner invocation. If Layer 3's HCL parser reads the fetched tarball directly on host to build the resource graph, that claim no longer holds for the whole pipeline. Two options: (a) run Layer 3 parsing inside the same sandboxed container pattern as the scanner, keeping the claim true system-wide; or (b) narrow the stated claim to "untrusted *code execution* is sandboxed" (true regardless) rather than "untrusted code never touches host" (false if Layer 3 parses on host). Pick one before Week 6 and make §13's answer match it exactly.

### Layer 4 — Dynamic Verification
Verifier interface + registry. **AuthzReplayVerifier** and **SSRFOOBVerifier**. Both trigger only on Layer 1 findings — confirmation, not exploration.

**Live-PR scope limitation — stated explicitly, not left implicit.** Both verifiers need a *running instance* to send requests against. `testdata` and locally-checked-out validation repos provide this; an arbitrary real PR on an installed repo does not — nothing auto-deploys a PR branch (deliberately, per §2's DAST exclusion), and there is no staging-URL configuration mechanism in v1. **Honest v1 scope: dynamic verification runs in demo/validation context only, not against live arbitrary PRs.** A per-repo `.authgraph.yml` with a `staging_url:` field that Layer 4 reads (no-op if absent) is documented future work, not built. This goes in the report/README explicitly — it's the first thing a sharp reviewer will probe ("if I open a real PR right now, what does Layer 4 actually test?").

**Static-to-dynamic correlation — the mechanism connecting Layer 1 to Layer 4, previously unspecified.** Layer 1 output is file/line/function; AuthzReplayVerifier needs an HTTP method + path to replay. This requires a **router-registration extractor**: parsing Go route registrations to map handler functions to routes. Scoped to one framework for v1 (whichever `testdata` actually uses, e.g. `chi`) — other routers explicitly unsupported. If a flagged handler backs multiple registered routes (1:many), test all of them rather than arbitrarily picking one.

**AuthzReplayVerifier verb-sibling scope — read-only verbs only for v1.** When a route is flagged on GET, probe GET/HEAD siblings using the same replay + diff logic. **PUT/DELETE/PATCH verb-sibling checks are explicitly NOT built for v1** — a DELETE replay has a real destructive side effect on the target resource, which makes it unsafe to run repeatedly against `testdata` for reproducible checkpoint testing (Week 10's "5 consecutive clean runs" bar) without either transactional rollback support (real engineering work, out of scope) or a full reseed after every run (too expensive to satisfy reliably). State-changing verb-sibling probing is documented future work, same category as SecretLivenessVerifier's earlier cut.

Note: SSRFOOBVerifier's OOB listener needs a public endpoint regardless of the App-vs-Action question — this was never resolved by the App decision and still needs its own small always-on host (see §8).

### Layer 5 — Reporting + Feedback
Mostly built already (Check Run + PR comment, per Layer 1). Remaining work: wire the fuller Output Contract (§4) through instead of the current flat `ScanReport`/`Finding` structs, add DFD + verification evidence to the rendered output. **Rendering rule unchanged:** one renderer driven by the Output Contract schema, no per-finding-type custom formatting.

**Decision needed now (was left ambiguous in the current build):** Check Run and PR comment currently render the *same* content twice. Decide deliberately — e.g., PR comment only fires when `TotalFindings > 0`, Check Run always fires — and document the reasoning in `docs/architecture.md` so it isn't accidental duplication.

**Suppression — config-file based, not a database.** A slash-command PR-comment workflow (`/authgraph suppress <finding_id>`) would need a second webhook event type (`issue_comment`) and a persistence layer (SQLite, with a `suppressions` table) neither of which exist and neither of which fit comfortably into the Week 12 slot alongside everything else. **v1 design instead: suppressions live in a committed `.authgraph-suppressions.yml`** in the target repo (`finding_id`/`rule_id` + reason). Reviewers suppress via a normal commit; git history is the audit log; no new webhook handling, no schema, no persistence layer. Weaker UX than a slash command, but honestly scoped for the timeline. Full slash-command + persisted suppression state is documented future work (§12).

**No cross-push state, by design for v1.** Without a persistence layer, a second push to the same PR re-scans from scratch with no memory of the first scan — findings that already existed on the previous commit will be re-flagged/re-commented rather than deduped. Stated limitation, not a bug: PR-comment volume on repeatedly-pushed PRs is a known, accepted tradeoff of the stateless v1 design, worth one sentence in the report's limitations section.

**Other stated limitations (one line each in the report, not fixes):**
- **Concurrency:** whether Docker-sandboxed scans serialize on a single host or run in parallel (and risk resource exhaustion) is unaddressed — fine to punt at demo scale, state it.
- **Retry on transient failure:** no re-run mechanism if a scan fails on a Docker pull hiccup or network blip; the PR sits with a failed/incomplete check until a new commit forces a re-scan.
- **"Block" is advisory unless the installing repo enables branch protection.** AuthGraph reports a Check Run conclusion; GitHub does not prevent merge unless the repo owner has configured that specific check as a required status check under branch protection — a repo-admin setting AuthGraph cannot configure on the installer's behalf. State this explicitly in the report: "AuthGraph reports check status; enforcing it as a merge requirement is a repo-level setting the installer must enable." Otherwise the pitch line's "gates PRs before merge" is a slight overclaim.

## 4. Output Contract (v1) — Every Finding, No Exceptions

```json
{
  "finding_id": "deterministic-hash",
  "cwe": "CWE-862",
  "rule_id": "authz-missing-ownership-check",
  "title": "Missing ownership check before resource access",
  "severity": "high | medium | low",
  "confidence": "confirmed | likely | unconfirmed | inconclusive",
  "location": { "file": "path/to/handler.go", "line": 42, "function": "GetOrder" },
  "evidence": { "static": "...", "dynamic": "..." },
  "references": ["CVE-XXXX-XXXX or GHSA URL"],
  "risk_context": { "internet_facing": true, "source": "Layer 3 graph, or null" },
  "suppressed": false,
  "suppression_reason": null
}
```

**`finding_id` is deterministic, not a random UUID.** A random UUID breaks the §3/Layer 5 suppression design: with no persistence layer translating IDs between scans (deliberately cut in the YAML redesign), a fresh random ID on every scan means a suppression entry that matched finding X on scan N silently stops matching the identical underlying issue on scan N+1. **Fix: `finding_id` = a stable hash of `rule_id + file + function`** (function-level, not line-level — line numbers shift with unrelated edits elsewhere in the file, so line-based hashing would cause the same false-unsuppression problem this fix exists to prevent). Same underlying finding produces the same ID on every scan of the same code, so `.authgraph-suppressions.yml` entries stay valid across pushes.

The current build's `Finding`/`ScanReport` structs (in `scan.go`) are a **precursor** to this, not the final schema — they're flatter (no `confidence`, no `risk_context`, no `evidence` split, no deterministic ID). Migrating to the full Output Contract, including the deterministic `finding_id` scheme, is Week 1–2 work, done once, before Layer 2 is wired in, so nothing downstream is built against the old shape.

## 5. Rule Schema (Layer 1 Catalog)

*(Unchanged from v2.)*

```go
type Rule struct {
    RuleID           string
    CWE              string
    Title            string
    Languages        []string // ["go"]
    SeverityBase     string
    References       []string // REQUIRED, non-empty
    DetectionPattern string
    VerifierID       *string
}
```

## 6. Repo Structure

```
authgraph/  (fork of sentrygrep, restructured in place)
├── cmd/
│   └── server/main.go          # webhook entry, now async (see §7)
├── internal/
│   ├── webhook/                 # signature verification, event parsing (from main.go)
│   ├── auth/                    # App JWT + installation token exchange
│   ├── fetch/                   # tarball fetch + extraction at head SHA
│   ├── sandbox/                 # Docker-sandboxed scan invocation
│   ├── rules/
│   │   ├── schema.go             # Rule struct (§5)
│   │   └── catalog/
│   │       ├── cwe-862-authz/
│   │       ├── cwe-918-ssrf/
│   │       └── cwe-78-cmdinject/
│   ├── policy/                   # Layer 2: OPA/Rego
│   ├── advisor/                  # Layer 3: HCL parser + graph + DFD
│   ├── verifiers/                # Layer 4
│   │   ├── verifier.go
│   │   ├── authz_replay.go
│   │   └── ssrf_oob.go
│   ├── report/
│   │   └── schema.go              # Output Contract (§4) as Go struct — replaces current ScanReport
│   └── github/
│       ├── checkrun.go            # existing, hardened
│       └── comment.go             # existing, hardened
├── secrets/                        # gitignored — private key, webhook secret
├── evaluation/
│   ├── validation-repos.md
│   ├── validation-methodology.md
│   └── case-studies.md
├── testdata/
└── docs/
    ├── architecture.md             # this document
    └── session-log.md
```

## 7. Week 1 Hardening Checklist (do before any new Layer 1 rules)

0. **Confirm the App has actually received and processed a real webhook end-to-end** via a public tunnel (ngrok/smee.io) or a small real deployment — not just local/synthetic payloads. This is a precondition for observing whether items 1–2 below actually behave correctly under GitHub's real delivery timing (timeouts, redelivery), not just whether the Go code compiles.
1. Make `webhookHandler` async: verify signature + parse event synchronously, `w.WriteHeader(http.StatusOK)` immediately, run fetch/scan/report in a goroutine.
2. Move `createCheckRun` to immediately after event validation, before tarball fetch. On any downstream failure, update that same Check Run to `completed`/`failure` with an error summary instead of leaving no signal.
3. Fail fast at startup if `GITHUB_WEBHOOK_SECRET` is empty.
4. Add basic webhook delivery dedup (track `X-GitHub-Delivery` header, ignore repeats within a short window). **Accepted limitation, stated not hidden:** this is in-memory and single-instance — breaks on restart or under >1 replica. Fine for an academic single-instance deployment; note this explicitly in §11 rather than let it be discovered later.
5. Confirm `secrets/` was never committed: `git log --all --full-history -- secrets/`. Confirm `bot/sentrygrep-bot` (compiled binary) is removed from tracking and gitignored.
6. Decide and document the Check-Run-vs-PR-comment duplication question (§3, Layer 5).

**"Solid end-to-end" — measurable bar, not a vibe.** For the Week 5 gate this means: 5 consecutive real PRs against `testdata`, zero unhandled errors, correct Check Run conclusion each time, verified via the live App (not local mocks). The Week 10 gate uses the equivalent bar for AuthzReplayVerifier (§10).

## 8. Ethics & Authorization Boundary

*(Unchanged from v2, restated in full — this is a hard rule, not report language.)*

> AuthGraph's dynamic verifiers (AuthzReplayVerifier, SSRFOOBVerifier) perform active verification techniques — replayed authenticated requests and outbound-request triggering. These verifiers are only ever run against: (a) `testdata/` fixtures the author built and controls, or (b) external validation repositories, run locally against the author's own checkout, never against a live/hosted instance the author does not control or have explicit permission to test. Any future extension toward scanning external, non-consented targets would require explicit authorization equivalent to a bug bounty program's scope agreement — out of scope for this project.

SSRFOOBVerifier's correlation-token OOB listener needs its own small, always-on public endpoint (cheap VM/Fly.io/Railway) — independent of the App's own hosting, and can be stood up whenever Layer 4 work begins (~Week 9–10).

## 9. Validation Methodology

*(Unchanged from v2.)* Pre-fix/post-fix commit diffing against 3 external Go repos with known CVE/GHSA advisories: checkout vulnerable commit, confirm detection (and confirmation, where a verifier applies); checkout patched commit, confirm the finding disappears or downgrades. Precision/recall computed from this before/after set, reported honestly including misses.

## 10. 16-Week Plan (revised)

| Weeks | Deliverable |
|---|---|
| 1 | **Hardening, not new features.** §7 checklist in full. Migrate `ScanReport`/`Finding` to the full Output Contract (§4) as Go structs. Confirm end-to-end: real PR → async webhook → Check Run created immediately → scan → Check Run completed with new schema. |
| 2–3 | Rule catalog restructured to CWE-first (§5). Write & validate CWE-862/863 and CWE-918 rules — public CVE reference first, own finding second. |
| 4 | Layer 2 — OPA/Rego, confidence-aware policy, wired to the new Output Contract. Decide/document missing-Layer-3-signal behavior. |
| 5 | **Checkpoint.** Layers 1+2+5 solid end-to-end on the hardened App, real PR test, stub Layer 3, zero verifiers acceptable. **Also resolve the Layer 3 sandbox-boundary decision (§3, Layer 3) in this week's buffer** — before Week 6 starts, not during it. |
| 6–8 | Layer 3 — HCL parsing, resource graph, Mermaid DFD, severity feed to Layer 2. |
| 9 | **Target-app orchestration, then verifier build (sequential, same week).** First: stand up `testdata` demo app, run migrations, seed 2 test identities with owned resources, confirm a reproducible reset between runs. Then: verifier interface + AuthzReplayVerifier (ownership-field diff, negative control, read-only verb-sibling probing) against the now-seeded `testdata`. Stand up SSRFOOBVerifier's OOB listener infra. |
| 10 | **Checkpoint.** AuthzReplayVerifier fully working against `testdata` — measurable bar: 5 consecutive confirmed/likely results on known-vulnerable fixtures, 0 false positives on known-safe fixtures — before touching SSRFOOBVerifier. |
| 11 | SSRFOOBVerifier (correlation-token OOB, timeout-windowed confirmation). |
| 12 | Layer 5 — full Output Contract rendering, suppression logging, DFD + verification evidence in Check Run output. Mid-project buffer. |
| 13 | Ethics boundary code-level enforcement (allowlist check in `verifiers/verifier.go`, tested to refuse non-allowlisted hosts). **Minimal live-path proof-of-concept:** deploy one `testdata` instance to the same small host used for SSRFOOBVerifier's OOB listener; add `.authgraph.yml`/`staging_url:` reader to Layer 4 (no-op if absent); run AuthzReplayVerifier against the deployed instance once via the config path, not just local. No auto-deploy, no per-PR provisioning — proves the config-driven mechanism is real, not just documented future work. Demo video (90s: PR → blocked IDOR → replay evidence). |
| 14–15 | External validation study: 3 Go repos, pre-fix/post-fix methodology (§9), precision/recall reported. |
| 16 | Report writing, buffer. Optional: technical writeup on AuthzReplayVerifier technique. |

**Week 5 and Week 10 are both hard gates.** If either isn't met, cut scope per §11 before proceeding rather than compressing into final weeks.

## 11. Minimum Viable Fallback

Layer 1 (hardened App) + Layer 2 + Layer 5 fully solid, Layer 3 as a thin 2-signal stub (not the HCL/graph upgrade), Layer 4 with AuthzReplayVerifier only (no verb-sibling, no SSRFOOBVerifier). Still complete, defensible, honestly scoped.

**Named risks, not hoped-around:**
- **External time pressure.** This plan assumes near-full-time availability across 16 weeks; the author is concurrently running Project 23 and coursework. A bad exam week or bounty deadline colliding with Week 5 or Week 10 is an anticipated scenario, not a surprise — if a gate slips for reasons unrelated to AuthGraph's own risk, that's expected, and scope should be cut per this section rather than compressed into later weeks.
- **Per-validation-repo seeding risk.** Weeks 14–15's 3 external repos likely need different seeding approaches per repo, since none were built with AuthGraph's fixtures in mind. A repo that's genuinely hard to seed drops to Layer-1-only validation for that repo rather than blocking the whole study — decide this per-repo as encountered, don't let one difficult repo stall Weeks 14–15.
- **In-memory webhook dedup** (§7.4) is a stated, accepted limitation for a single-instance academic deployment — not a gap to fix under time pressure.

## 12. Stretch Goals

- Second-language port (Python/Flask) of rule catalog + verifiers
- Route-table-derived candidate discovery (Layer 4 extension)
- Technical writeup/CFP submission on the AuthzReplayVerifier technique
- Per-repo `.authgraph.yml` `staging_url:` config, enabling Layer 4 verification against real installed-repo PRs (closes the live-PR scope limitation in §3, Layer 4)
- State-changing (PUT/DELETE/PATCH) verb-sibling probing with transactional test fixtures
- Slash-command suppression (`/authgraph suppress`) with persisted state (SQLite), replacing the v1 config-file approach
- (Retired as a stretch goal: "migrate to GitHub App" — already done.)

## 13. Report/Viva Framing

- *"Does this work like a real DAST tool?"* — No, by design; Layer 4 confirms Layer 1 findings, doesn't explore.
- *"Is this just your own CVEs wrapped in tooling?"* — No: CWE + public reference only for rule justification; personal findings retrospective and separate; validation study on repos the author didn't personally find bugs in.
- *"Does this work on any codebase?"* — No: Go, HTTP/REST, bearer-token auth, stated explicitly, second-language port as stretch.
- *"Did you test this against systems you don't control?"* — No, and here's the stated boundary (§8).
- *"If I open a real PR right now, what does Layer 4 actually test?"* — By default, nothing dynamic — Layer 4 requires a running instance to verify against, and no auto-deploy exists (deliberately, §2). Where a repo owner configures `.authgraph.yml` with a `staging_url:`, Layer 4 verifies against that instance instead; this minimal config-driven path is built and demonstrated once (Week 13), not just documented — full per-PR auto-provisioning remains a stretch goal (§12).
- *"Does merging actually get blocked, or just flagged?"* — AuthGraph reports Check Run status via the standard Checks API; the installing repo must separately enable branch protection requiring that check to pass. AuthGraph cannot configure this on the installer's behalf.
- *"Why a GitHub App instead of a simpler CI Action?"* — Deliberate: App enables install-once, multi-repo protection (matches the multi-repo validation study), demonstrated via real webhook/JWT/Checks API integration, Docker-sandboxed execution of untrusted PR code.