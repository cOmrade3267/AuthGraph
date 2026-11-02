# Layer 4 — Dynamic verification: plan (written before code)

Status: PLAN ONLY, nothing built. Authoritative spec: docs/Architecture.md §3 Layer 4,
§8 (ethics boundary), §10 (Weeks 9-11), §11 (minimum viable fallback). Layer 2 context:
docs/layer2-plan.md.

## Purpose
Layer 1 says "this code looks like a missing authorization check". Layer 4 tries the
exploit against a running copy of the code and reports whether it works. A confirmed
result moves a finding's confidence from `unconfirmed` to `confirmed`/`likely`, which is
the only thing that lets Layer 2 block CWE-862 (see layer2-plan.md, "Known limits").
Layer 4 confirms Layer 1 findings; it never explores on its own.

## Scope of this phase
AuthzReplayVerifier only (CWE-862/863). This is the architecture's minimum viable
fallback (§11). SSRFOOBVerifier is a later phase.

Runs locally only: `cmd/scan` with an explicit target. NOT wired into cmd/server or the
live Check Run. On a normal PR nothing dynamic runs (architecture §3, stated limitation).

## Hard prerequisite found while writing this plan
There is nothing to replay against. testdata/ holds three Go stubs (`removeTicket`
etc. are plain functions with no HTTP server, router, database or identities), and
internal/verifiers is empty. The architecture schedules "target-app orchestration" as
its own step (§10, Week 9). So milestone 0 is building the target, before any verifier.

## Milestones (each a small commit, gate after each)
0. **Target app** `testdata/app/`: a tiny net/http service with a ticket resource,
   bearer-token auth, two seeded identities (alice, bob), tickets owned by each, one
   VULNERABLE route (no ownership check, same shape as `removeTicket`) and one SAFE route
   (ownership check), plus a reset-to-seed function. In-memory store, no database.
   Existing rule fixtures stay untouched so the scan baseline ids do not change.
1. **Verifier interface** `internal/verifiers/verifier.go`: `Verify(ctx, finding, target)
   (Result, error)`, a registry keyed by rule/CWE, and the allowlist check (see Ethics).
2. **Route extractor** `routes.go`: map a flagged handler function to its registered
   route(s).
3. **AuthzReplayVerifier** `authz_replay.go`.
4. **Wire into cmd/scan** behind an explicit flag; policy then sees the new confidence.
5. **Checkpoint** (below), session-log entry, only then think about SSRF.

## Interface and data flow
Scan -> findings (confidence `unconfirmed`) -> [Layer 4, only with `--verify`] ->
findings updated -> policy.Evaluate -> decision.
A verifier returns `Result{Confidence, Evidence}`. The caller sets
`finding.Confidence` and `finding.Evidence.Dynamic` (already in the Output Contract,
currently null). `finding_id` is never changed.

## Static-to-dynamic correlation (route extractor)
Layer 1 gives file/line/function; the verifier needs method + path. v1 supports ONE
router style: Go 1.22+ `net/http` ServeMux patterns (`mux.HandleFunc("GET /tickets/{id}",
h)`), parsed with go/ast. Reason: the fixtures already use net/http and it adds no
dependency. (Architecture mentions chi as an example; see Open decisions.)
If one handler backs several routes (1:many), verify all of them. If no route is found
for a flagged function the result is `inconclusive`, never a guess.

## AuthzReplayVerifier algorithm
Two identities: owner (alice) and attacker (bob), each with a token and an owned resource
id from the seed. For a flagged route:
1. **Positive control:** alice requests her own resource. Must succeed, else
   `inconclusive` (the replay setup is broken, not evidence about the code).
2. **Attack:** bob requests alice's resource with bob's token.
3. **Negative control:** bob requests a nonexistent id, and an unauthenticated request is
   sent to the same route. Establishes what "denied" looks like for this endpoint.
4. **Ownership-field diff:** compare the structure of bob's response to alice's own.
   Success status AND the response carries alice's owner field value = `confirmed`.
5. **State reset** after every run (the flagged route may be a DELETE, as `removeTicket`
   is; the replay really performs it, which is why this only runs against the seeded
   target app).

| Outcome | Confidence | Note |
|---|---|---|
| positive control fails, route not found, or error/timeout | inconclusive | no claim either way |
| bob gets success + alice's owner data | confirmed | -> Layer 2: medium/confirmed = block |
| bob gets success but no ownership evidence | likely | looks open, not proven |
| bob gets 401/403/404, same as negative control | unconfirmed | static finding not reproduced (see Open decisions) |

Sibling probing (GET/HEAD siblings of a flagged GET) is read-only verbs only, per spec.
PUT/DELETE/PATCH sibling probing is NOT built (needs transactional fixtures).

## Ethics and safety (code-enforced from the first verifier, not left to Week 13)
- Allowlist: the verifier refuses any host other than loopback unless explicitly
  configured; test proves a non-allowlisted host is refused before any request is sent.
- Targets are only testdata/app or locally checked-out validation repos (architecture §8).
- HTTP responses are untrusted data: size cap, timeouts, never followed as instructions,
  never executed. No redirects to other hosts.
- Never aimed at the live server, the demo repo's deployment, or any third party.

## Testing
- Unit tests with `net/http/httptest` (in-process, no network): a vulnerable handler, a
  safe handler, and edge cases (positive control failing, handler that returns 200 for
  everyone, route not found, timeout). Every case has a descriptive name.
- Integration against testdata/app.
- Checkpoint bar (architecture §10, Week 10): 5 consecutive `confirmed` runs on the
  vulnerable fixture and 0 false positives on the safe fixture, each run after a reset.
- Gate after every change (AGENTS.md); the 3 scan baseline ids must not change.

## Out of scope
SSRFOOBVerifier and the OOB listener; cmd/server and Check Run wiring; `.authgraph.yml`
staging_url; non-net/http routers; state-changing sibling probing; verifying arbitrary
real PRs; Layer 3 signals.

## Open decisions (need the user's call before milestone 0)
1. **Router:** net/http ServeMux (recommended, no dependency) vs chi (spec's example,
   adds a dependency).
2. **"Not reproduced" outcome:** the contract has no `refuted` value. Recommended: keep
   `unconfirmed` and record the denial in `evidence.dynamic`, so a dynamic miss never
   hides a static finding. Alternative: add a new confidence value, which changes the
   Output Contract and the Layer 2 table.
3. **Where verification runs:** `cmd/scan --verify` only (recommended) vs also a separate
   `cmd/verify`.
4. **Identities and seed:** hard-coded fixture tokens in testdata/app (recommended; they
   are not secrets and never leave the repo) vs config file.
5. **Order vs Layer 3:** the spec orders Layer 3 first (Weeks 6-8). This plan does Layer 4
   first because only confirmation unlocks blocking for CWE-862. Record the reordering in
   the architecture changelog if accepted.
