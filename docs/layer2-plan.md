# Layer 2 — Policy: plan (written before code)

**Status (2026-11-01): implemented, deployed, live-tested.** The original plan below
is kept; sections marked *Updated* record where the shipped behavior differs from it.
See docs/session-log.md for the verification record.

## Purpose
Turn each Layer 1 finding (Output Contract, spec §4) into one decision:
block | warn | note. Implemented in OPA/Rego (internal/policy), called from Go.

## Scope of this phase
*Updated.* Originally: library plus test harness, wired into cmd/scan only, not
cmd/server. Shipped: library, harness, cmd/scan, **and** the live Check Run
(cmd/server logs the decisions; ghapi.CompleteCheckRun derives its conclusion from
the policy). Wiring was brought forward from Week 5 after a shadow-mode run on the
real App showed the decisions (see "Rollout" below).

## Inputs
Per finding: severity (high|medium|low), confidence
(confirmed|likely|unconfirmed|inconclusive), risk_context (null until Layer 3),
suppressed (bool). A null risk_context is neutral. In this phase a present
risk_context is accepted but does not change any decision (Layer 3 modifiers are
defined when Layer 3 exists), so the harness asserts identical decisions with
and without it.

## Value mapping (scanner -> contract)
- severity: ERROR->high, WARNING->medium, INFO->low. The agent must verify this
  against the real report.json before coding and report any mismatch.
- confidence: every static-only finding is `unconfirmed` until Layer 4 exists.
  *Updated:* one exception, assigned in Go (internal/sandbox/scan.go,
  `assignConfidence`): a CWE-78 finding whose Semgrep rule confidence is HIGH is
  `likely`. CWE-862 and CWE-918 stay `unconfirmed`. A non-`unconfirmed` value is
  never changed. scanner.py and the rules are untouched.
- scanner severity names are accepted as-is (ERROR/WARNING/INFO) and mapped in
  internal/policy; an unknown severity or confidence is an error, never a pass.

## Decision table
| severity | confirmed | likely | unconfirmed | inconclusive |
|---|---|---|---|---|
| high   | block | block | warn | warn |
| medium | block | warn  | warn | note |
| low    | warn  | note  | note | note |

Spec-fixed cells: confirmed/medium = block; unconfirmed/high = warn.
All other cells are project decisions made on 2026-11-01.
Overall decision = strictest finding decision. Suppressed findings are excluded
before evaluation. Empty report = note.

## Behavior change vs before
Before, any ERROR failed the Check Run. Under this policy a static-only finding
(unconfirmed) can never block. *Updated:* CWE-78 (likely/high) still blocks, so
the live behavior for the demo fixtures is unchanged (CWE-78 fails the check).
CWE-862 and CWE-918 findings are `warn`, which maps to a `neutral` Check Run, until
Layer 4 can confirm them. Intentional: bias toward low false-positive,
high-confidence gating.

Check Run mapping (live): block->failure, warn->neutral, note->success; a policy
evaluation error -> failure ("Policy evaluation failed"), fail closed.

## Rollout (what actually happened)
1. Shadow mode deployed first: decisions logged only, Check Run unchanged. Result on
   the demo PR: overall=warn would_conclude=neutral for a PR the old logic failed.
2. That showed nothing could block, so CWE-78 was allowed to emit `likely`.
3. Check Run switched to the policy conclusion and deployed. Live result on
   authgraph-demo PR #2: vulnerable commit -> failure, fix commit -> success.

## Known limits
- Only CWE-78 can block today. The anchor class (CWE-862/863) can only warn until a
  Layer 4 verifier confirms it, so Layer 4 (AuthzReplayVerifier) is what unlocks
  blocking for it. Layer 3 does not change this: `risk_context` is accepted but has
  no effect on any decision yet.
- "Block" is advisory unless the installing repo requires the check in branch
  protection (architecture spec section 3, Layer 5).

## Testability gap and harness (Week 4)
Confidence only takes non-default values once Layer 4 exists (Week 9+). The
harness builds synthetic findings for every severity x confidence cell, with and
without risk_context (24 cases), plus: empty report, one suppressed finding,
mixed severities (strictest wins). Table-driven Go test calling the real policy.

## Out of scope
Layer 3 signals and risk_context modifiers, suppression-file parsing (the policy
skips findings already marked suppressed, but nothing sets the flag yet), dynamic
verification, rendering the decision in the PR comment / Check Run summary
(Layer 5).
