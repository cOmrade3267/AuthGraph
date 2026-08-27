# AuthGraph — Rule Development Methodology (Week 2 and beyond)

This is a repeatable process, not a one-time Week 2 task list. Use it for every rule in every CWE class, including CWE-918 next and anything added later. Each stage has a clear "done" signal so you always know whether to move forward or go back.

---

## Stage 1 — Sourcing candidate vulnerabilities

**Goal:** produce a shortlist of 1-3 real, plausible candidates per CWE class, fast, without reading deeply yet.

### Sources, in order of signal quality for this project
1. **GitHub Advisory Database** (`github.com/advisories`) — best default. Filter by CWE ID directly in search; results include ecosystem tags so you can spot Go-relevant ones quickly.
2. **GitLab Advisory Database** (`advisories.gitlab.com`) — mirrors GHSA data but organizes by ecosystem/package path (e.g. `golang/github.com/...`), which makes it faster to scan for Go-specific results than GitHub's own UI.
3. **OSV.dev** — good for cross-referencing; has a clean API if you ever want to script candidate discovery instead of searching manually.
4. **Academic datasets (CVEfixes, Big-Vul)** — useful for volume/breadth, but noisier and sometimes stale-labeled. Treat as a discovery net, never a trust source — this is what Stage 2 exists to catch.

### What makes a candidate worth shortlisting (quick filter, ~30 seconds per candidate)
- Ecosystem tag says Go, or the affected package path is clearly a `.go` project
- CWE label matches what you're building (862/863, 918, etc.) — but don't fully trust the label yet, that's Stage 2
- There's a linked fix commit or PR, not just a prose description — if there's nothing to actually read the code change, skip it, you can't verify it
- Prefer real, actively-maintained projects (Gitea, memos, etc.) over abandoned/tiny repos — larger projects' advisories tend to be better-documented and their fix commits easier to interpret

### Diversity heuristic (worth applying for anchor classes specifically)
For a class you're going deep on (like CWE-862/863), deliberately pick candidates that differ in *where* the bug lives — one in a route handler, one in a middleware/access-control layer, one in a data-access/query layer. Three candidates that are all "missing an `if user.ID != resource.OwnerID` check in a handler" don't actually test generality; three candidates with different *shapes* do.

**Stage 1 exit signal:** you have a short URL list, one line of description each, no deep reading done yet.

---

## Stage 2 — Manual verification (the stage that already caught a real mistake)

**Goal:** confirm each candidate is what it claims to be, before it ever touches a `References` field.

This is the stage the earlier session's AI IDE work skipped once already — a syntactically valid, genuinely real PR link that was the wrong artifact (fixed the vulnerability, but didn't credit the reporter, so it wasn't verifiable as *your* Civo disclosure specifically). The lesson generalizes: **plausible and real is not the same as verified.**

### Protocol, per candidate
1. **Read the actual advisory text in full** — not the search snippet, the real page. Confirm the CWE label matches the actual described behavior (advisories are sometimes mistagged, especially older ones or ones migrated from a different classification scheme — the GitHub Blog source found earlier even mentions CWE-863 recently absorbed a lot of reclassified CWE-284/285 entries, so older advisories may carry a stale label).
2. **Open the linked fix commit or PR and read the actual diff.** Confirm: is this really an added authorization/ownership check? Does the "before" code genuinely lack it? A rule built against a misread diff will detect the wrong pattern.
3. **Note the exact code shape** in plain language: "checks `req.UserID` against session but not against the resource's owner field before delete" — this sentence is what Stage 3's rule actually needs to target.
4. **Reject and move to the next candidate** if the advisory is too vague, the fix commit isn't available, or on reading it turns out to be a different bug class than labeled.

### Cheap trust-but-verify shortcut for volume
If you're screening many candidates, skim Stage 2 step 1 for all of them first (filter fast), then do the deeper step 2 diff-read only on the ones that survive — don't read every fix commit in full for candidates you're likely to reject anyway.

**Stage 2 exit signal:** for each surviving candidate, you can write one accurate sentence describing the exact vulnerable code pattern, and you've personally looked at the real diff, not a summary of it.

---

## Stage 3 — Writing the rule with an AI IDE

**Goal:** get a Semgrep rule that targets the verified pattern(s), without letting the agent invent scope you didn't ask for.

### Prompting discipline
- **Feed the agent your Stage 2 sentence, not the CVE ID alone.** "Write a Semgrep rule for CVE-2026-58438" invites the agent to guess at the pattern from a title. "Write a Semgrep rule matching: a handler that removes an issue dependency without checking the requesting user has access to both the source and target repository" gives it the actual target.
- **Give it the real vulnerable code snippet from the diff, redacted/simplified**, as a docstring or comment above the pattern — this anchors the rule to reality instead of a generic guess at "what authorization bugs usually look like in Go."
- **Ask for the rule and the fixture in the same prompt, or as two tightly sequential prompts** — a rule without a fixture to test against is unverified by construction.
- **One rule (or tightly related rule family) per prompt.** Don't ask for CWE-862 and CWE-918 rules in the same request — mixing concerns makes the diff harder to review and easier to approve carelessly.

### What to explicitly ask the agent to avoid
- Don't let it write the rule *and* silently pick which CVE justifies it — that's exactly the failure mode already caught once. Specify the exact reference URL(s) yourself, from your verified Stage 2 list, and tell it to use only those.
- Don't accept a rule that only matches your own fixture's exact variable names/structure — ask explicitly: "make the pattern general enough to match structurally similar code with different variable names," and verify this yourself in Stage 4 rather than trusting the claim.

**Stage 3 exit signal:** a rule file + at least one vulnerable fixture exist, `go build`/`semgrep --validate` (or equivalent syntax check) passes.

---

## Stage 4 — Testing before implementation (this is the stage most likely to be rushed — don't)

**Goal:** prove the rule actually detects the vulnerable pattern and doesn't fire on safe code, using Semgrep directly, before it ever touches the live pipeline.

### The testing pyramid for a rule
1. **Positive fixture(s)** — one vulnerable file per verified candidate (for CWE-862/863, that's up to 3 distinct files matching the 3 different candidate shapes). Confirm the rule fires on each.
2. **Negative/safe fixture(s) — equally important, often skipped.** For each vulnerable fixture, write the *patched* version (often near-identical to the actual fix commit's "after" state) and confirm the rule stays silent. A rule that can't tell vulnerable from fixed code is not a working rule, it's a keyword match.
3. **Semgrep's built-in test framework** — use `semgrep --test` against a `.yaml` rule with paired `ruleid:`/`ok:` annotated test files. This is the mechanically enforced version of steps 1-2, and it's exactly the kind of "enforced, not aspirational" check your architecture doc already insists on elsewhere (§5's References check). Worth wiring this into the same `go test ./internal/rules/...` pattern you already built for the reference-URL check, so a future rule can't be added without both a reference *and* a passing positive/negative test pair.
4. **Adjacent/near-miss fixtures (optional, high value for anchor classes)** — a file that looks superficially similar but is a different bug entirely (e.g., an ownership check that exists but checks the wrong field) — confirms the rule isn't so broad it flags unrelated code, without needing a full false-positive study yet.

### A false-positive sanity check worth doing before trusting the rule broadly
Run the finished rule against a real, unrelated Go codebase you already have on hand (your own `testdata`, or even AuthGraph's own source) — not to find real bugs, just to see if it fires where it clearly shouldn't. Zero findings expected; any surprise finding is worth a quick look before moving on.

**Stage 4 exit signal:** `semgrep --test` (or your equivalent) passes clean — vulnerable fixtures fire, safe fixtures don't, and a spot-check against unrelated real code produces no surprise noise.

---

## Stage 5 — Final implementation into the pipeline

**Goal:** the rule is a real, enforced part of the catalog, proven through the actual deployed App, not just local tests.

1. Write `meta.yaml` with `references` pointing only at your Stage 2-verified URLs.
2. Run `go test ./internal/rules/...` — confirm the mechanical reference check passes.
3. Deploy the updated scanner image (rebuild the Docker image on EC2, since `rules/` is baked into it — same process as Week 1's image rebuild).
4. Open a **real PR** on the AuthGraph repo containing your positive fixture's pattern (or close to it) in a real `.go` file — confirm the live Check Run / PR comment shows a genuine finding referencing that file, not just a local `docker run` success.
5. Commit, push, update `docs/session-log.md` with: candidates found → verified → rule written → tested → deployed → confirmed live.

**Stage 5 exit signal:** a real GitHub PR shows a real finding from this rule, end to end, through the actual App — matching the same standard Week 1 held itself to.

---

## Value-adds worth adopting going forward

1. **Rule provenance log.** Keep a short running note (in `evaluation/case-studies.md` or a new `evaluation/rule-provenance.md`) of *why* each rule looks the way it does — which candidates were considered, which were rejected and why, which shaped the final pattern. This is cheap to maintain incrementally and expensive to reconstruct later for the report or a viva question like "why does this rule look like this?"
2. **Reuse this exact five-stage process as a template**, literally copy-pasting this file's structure per CWE class, so CWE-918 (and anything added later) doesn't require re-deriving methodology — just re-running it.
3. **Track effort per rule.** A rough "candidates found: N, rejected: N, time spent: ~X" note per rule helps you notice early if a rule class is taking disproportionately long (a signal to simplify scope) versus going fast (a signal you might be under-verifying — worth a gut check against Stage 2's discipline).
4. **Treat Stage 4's negative fixtures as the actual differentiator for your report.** Almost any AppSec tool can claim "detects X" backed by a positive example. Being able to say "and verified it does not fire on the patched version of the same real-world vulnerability" is a meaningfully stronger claim, and it's nearly free once you're already doing Stage 4 properly.
5. **Batch Stage 1/2 across rules when possible.** Since you're deferring CWE-862/863's Stage 2 reading, consider doing it in the same sitting as CWE-918's Stage 1/2 — context-switching cost between "search mode" and "deep-read mode" is real, and batching similar-mode work is more efficient than interleaving.