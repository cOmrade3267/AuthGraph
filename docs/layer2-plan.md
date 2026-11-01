# Layer 2 — Policy: plan (written before code)

## Purpose
Turn each Layer 1 finding (Output Contract, spec §4) into one decision:
block | warn | note. Implemented in OPA/Rego (internal/policy), called from Go.

## Scope of this phase
Library plus test harness, wired into cmd/scan only. NOT wired into cmd/server:
the live Check Run behavior is unchanged until Week 5.

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
  No rule emits `likely` yet. Revisit if a precise rule should earn it.

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
Check Run mapping (applies when wired later): block->failure, warn->neutral,
note->success.

## Behavior change vs today
Today any ERROR fails the Check Run. Under this policy a static-only CWE-78
finding (unconfirmed/high) warns instead of blocking, until Layer 4 can confirm
it or a rule is allowed to emit `likely`. Intentional: bias toward low
false-positive, high-confidence gating. Not applied to the live server yet.

## Testability gap and harness (Week 4)
Confidence only takes non-default values once Layer 4 exists (Week 9+). The
harness builds synthetic findings for every severity x confidence cell, with and
without risk_context (24 cases), plus: empty report, one suppressed finding,
mixed severities (strictest wins). Table-driven Go test calling the real policy.

## Out of scope
Layer 3 signals, suppression-file parsing, dynamic verification, server wiring.
