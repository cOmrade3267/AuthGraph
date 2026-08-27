# AuthGraph — Session Handoff (as of end of Week 1 / start of Week 2)

Read this first, then `docs/architecture.md` (v5) for the full spec, then `docs/session-log.md` for the detailed session-by-session history. This file exists because `docs/START_HERE.md` (the original primer) is now stale on several points — treat *this* file as more current where they conflict, and fold corrections back into START_HERE.md when convenient.

## Repo / identity state (corrections to START_HERE.md)
- **SentryGrep and AuthGraph are now separate repos**, not one evolving into the other as originally planned. `github.com/cOmrade3267/sentrygrep` (legacy, Python + Go bot prototype) and `github.com/cOmrade3267/AuthGraph` (current, active development) are independent.
- AuthGraph has its **own GitHub App registration**, own App ID, own private key, own webhook secret — none shared with SentryGrep's App (`sentrygrepDev`). Do not reuse SentryGrep's credentials for anything.
- Go module: `github.com/cOmrade3267/authgraph`.

## Infrastructure — real, deployed, permanent (not ngrok)
- **AWS EC2**, region `eu-north-1` (Stockholm), instance `authgraph-webhook`, currently `t3.micro`, **Elastic IP 13.61.197.83** (permanent — do not confuse with the instance's default public IP, which changes on stop/start).
- **EBS volume resized to 16GB** (was 8GB, filled up from swap + OS/Docker footprint — if disk issues recur, check `df -h` before assuming a code bug).
- **2GB swap file** added (`/swapfile`) — required for Semgrep to run without SIGSEGV on 1GB RAM. If Semgrep crashes with exit code -11 / SIGSEGV, check swap is still active (`free -h`) before debugging code.
- **DuckDNS**: `authgraph.duckdns.org` → points at the Elastic IP. (A stray unused `authgraph-webhook.duckdns.org` entry also exists from an earlier mistake — safe to ignore/delete, not in use.)
- **Caddy** reverse-proxies `authgraph.duckdns.org` → `localhost:16666`, auto-manages a real (production, not staging) Let's Encrypt TLS cert.
- **systemd service** `authgraph.service` runs the Go binary as user `ubuntu`, `WorkingDirectory=/home/ubuntu/authgraph`, `Environment="GITHUB_WEBHOOK_SECRET=..."` (must be quoted in the unit file — unquoted values with special characters like `@` are silently dropped by systemd, this bit us once already).
- **Docker + the `sentrygrep-scanner` image** are built directly on the EC2 instance (not pulled from a registry). Dockerfile, `scanner.py`, `requirements.txt`, `rules/` were manually scp'd over from the SentryGrep repo and live in `/home/ubuntu/authgraph/` on the server (not tracked in the AuthGraph git repo — this is a real gap, worth fixing eventually by either vendoring these into the repo properly or documenting the manual-copy step).
- GitHub App webhook URL is set to `https://authgraph.duckdns.org/webhook` — this is now permanent, no more ngrok URL-drift issues.

## Standard deploy loop (used repeatedly, will keep being used)
```bash
cd ~/Desktop/AuthGraph
GOOS=linux GOARCH=amd64 go build -o authgraph-bot ./cmd/server
ssh -i ~/Desktop/authgraph-key.pem ubuntu@13.61.197.83 "sudo systemctl stop authgraph"
scp -i ~/Desktop/authgraph-key.pem authgraph-bot ubuntu@13.61.197.83:/home/ubuntu/authgraph/
ssh -i ~/Desktop/authgraph-key.pem ubuntu@13.61.197.83 "sudo systemctl start authgraph"
```
Then verify via `sudo journalctl -u authgraph -f` on the server while triggering a real PR, and/or checking GitHub's Recent Deliveries → Response panel for real timing.

## Git workflow note
This repo gets commits from two sources: local pushes, and PR merges done via GitHub's web UI (used for testing). **Always `git pull --no-rebase origin main` before pushing** — divergent-branch rejections have happened multiple times from skipping this. `pull.rebase false` should be set as a git config default in this repo; if a pull ever asks the reconcile-strategy question again, that config didn't stick — re-set it.

## Week 1 — complete and verified (not just claimed)
All of §7.0–§7.6 in architecture.md done and manually verified against the real deployed App, not just locally:
- Async webhook handler (ack in 0.49s vs. 9.36s blocking before the fix)
- Check Run created before fetch, `FailCheckRun` added and tested (deliberately broke the Docker image, confirmed a real `failure` conclusion appears instead of a stuck check)
- Fail-fast on empty `GITHUB_WEBHOOK_SECRET`
- In-memory delivery dedup on `X-GitHub-Delivery`, verified via double-Redeliver on GitHub
- Also fixed along the way: a 403 on PR comment posting (App was missing Pull Requests read/write permission — now granted and accepted)

Full detail of each fix and its verification is in `docs/session-log.md`, dated entries around 2026-08-21 and 2026-08-22.

## Known small gaps, accepted, not blocking
- `FailCheckRun`'s own error return is discarded at call sites — if the failure-update itself fails, that's not logged.
- Dedup map is in-memory/single-instance, lost on restart. Documented limitation, fine at this scale.
- Docker build context (Dockerfile, scanner.py, rules, requirements.txt) lives on the EC2 instance but isn't tracked in the AuthGraph git repo — should be fixed at some point so the repo is fully self-contained.
- Check Run and PR comment both fire on every scan with identical content (never made conditional, per architecture.md §3 Layer 5's flagged decision point — still open).

## Where we are now: starting Week 2
Objective: migrate to the CWE-first `Rule` schema and build CWE-862/863 (deep, multi-CVE validated — this is the anchor class) and CWE-918 (single-CVE) rules, alongside migrating the existing CWE-78 rule. Full phased plan is in `AuthGraph-Week2-Plan.md` (five phases: schema migration → CWE-862/863 candidate research via dataset + manual verification → rule authoring against verified candidates → CWE-918 single-CVE path → full pipeline validation).

**Key methodology decision made this session:** for CWE-862/863 specifically (and only this class), source candidate CVEs efficiently via a community dataset (GitHub Advisory Database query, or CVEfixes/Big-Vul), but every candidate must be manually verified by reading the actual advisory and vulnerable-code diff before being trusted as a `References` entry — dataset labels alone are not sufficient per architecture.md §5's mechanical-reference-check rule. CWE-918 and CWE-78 stay at single-reference validation; this asymmetry is deliberate (CWE-862/863 is the highest-scrutiny, most heterogeneous class) and should be recorded in architecture.md's changelog, not left looking arbitrary.

## Hard rules, unchanged, still apply
All 8 rules from `docs/START_HERE.md` still apply without modification — deterministic `finding_id`, YAML-file suppression (not a database), read-only-verb-only verb-sibling probing, testdata-only verifier targets, plan-before-code for `verifiers/`/`policy/`, session-log discipline, etc. Nothing about Week 1's infrastructure work changed any of those decisions.