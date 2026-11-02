# AuthGraph — Complete Code Guide

A study reference for understanding the whole project: what it does, how a pull request
flows through it, what every file is for, and how it is deployed and tested.
Written from the code as of `main` after PRs #17-#19 (Layers 1, 2 and 5 live). Function
names are used instead of line numbers so the guide stays correct as the code moves.

Read in order the first time. Later, use sections 3 and 5 as a lookup.

---

## 1. What it is, in one paragraph

AuthGraph is a **GitHub App**. When someone opens or updates a pull request on a repository
where the app is installed, GitHub sends our server a signed webhook. The server downloads
that exact version of the code, scans it with **Semgrep** inside a **Docker** container using
three custom rules (missing authorization, SSRF, command injection), converts the raw hits
into a stable structured report, runs each finding through a **policy** written in
**OPA/Rego** that outputs `block`, `warn` or `note`, and finally writes the verdict back to
GitHub as a **Check Run** (failure / neutral / success) plus a readable **PR comment**.

Five planned layers; three are built:

| Layer | Job | Status |
|---|---|---|
| 1 | Detect (Semgrep rules) + deliver (GitHub App plumbing) | live |
| 2 | Decide (OPA/Rego policy) | live |
| 3 | Advise (Terraform risk graph) | plan only (`docs/layer3-plan.md`) |
| 4 | Verify (replay the attack against a running app) | plan only (`docs/layer4-plan.md`) |
| 5 | Report (Check Run + PR comment) | partly live |

---

## 2. The mental model

```
 GitHub                           our server (EC2)                          Docker
 ------                           ----------------                          ------
 PR opened/updated
   | signed webhook (HTTPS)
   v
 [DuckDNS name] -> [Caddy :443 TLS] -> [authgraph app :16666]
                                         1 verify signature, dedup, reply 200
                                         2 (background) JWT -> installation token
   <---- create Check Run (in_progress)--3
   ----> download tarball @ head SHA ---4
                                         5 unpack to temp dir ------------> [scanner container]
                                                                              semgrep + our rules
                                         6 read report.json <---------------- writes report.json
                                         7 add function name, finding_id, confidence (Go)
                                         8 policy: block | warn | note per finding
   <---- complete Check Run -------------9 failure / neutral / success
   <---- post PR comment ---------------10 findings with decision, snippet, refs
```

Three ideas explain most of the design:

1. **Never execute the PR's code.** It is only read: unpacked to disk, then parsed by Semgrep
   in a container with a read-only mount.
2. **Separate "found something" from "what to do about it".** Layer 1 produces findings;
   Layer 2 alone decides the consequence. That is what lets confidence matter later.
3. **Stable identity.** Every finding gets a deterministic ID so suppressions can survive
   new pushes.

---

## 3. Repository map (every part)

```
cmd/
  server/main.go        the webhook server (entry point of the live app)
  scan/main.go          local CLI: scan a folder, print findings + decisions (no GitHub)
internal/
  auth/auth.go          GitHub App identity: JWT + installation token
  fetch/fetch.go        download the PR tarball from GitHub
  fetch/extract.go      unpack it safely; split "owner/repo"
  sandbox/scan.go       run the scanner container; enrich findings; assign confidence
  sandbox/confidence_test.go
  report/schema.go      the Output Contract as Go types (ScanReport, Finding, ...)
  policy/policy.rego    Layer 2 decision table (Rego)
  policy/policy.go      Evaluate(), ConclusionFor(); embeds and runs the Rego
  policy/policy_test.go the 24-cell harness + edge cases
  ghapi/checkrun.go     Check Run create / complete / fail + conclusion mapping
  ghapi/comment.go      PR comment posting + the Markdown renderer
  ghapi/*_test.go       conclusion and rendering tests
  rules/schema.go       Rule metadata type + LoadRule (reads meta.yaml)
  rules/schema_test.go  TestAllRulesHaveReferences
  rules/catalog/<cwe>/  rule.yaml (Semgrep), meta.yaml (refs), rule.go (Semgrep test fixture)
  advisor/ verifiers/ webhook/   empty placeholder folders for Layers 3, 4 (nothing in them)
scanner/
  scanner.py            runs semgrep, parses output into the report JSON
  Dockerfile            python:3.11-slim + semgrep + scanner.py + rules
  build.sh              copies catalog rules into scanner/rules/ then docker build
  requirements.txt      semgrep==1.167.0, PyYAML
testdata/               three fixture files = the regression baseline (3 known findings)
docs/                   Architecture.md (spec), START_HERE.md, Methodology.md,
                        session-log.md, layer2/3/4 plans, this guide
AGENTS.md               rules for AI agents working in the repo
secrets/                private key (git-ignored, never committed)
```

`scanner/rules/` is **generated** by `build.sh` and git-ignored. Edit rules only under
`internal/rules/catalog/`.

---

## 4. One pull request, traced end to end

Names in `code font` are functions you can open.

1. **GitHub -> Caddy -> app.** GitHub POSTs to `https://authgraph.duckdns.org/webhook`.
   Caddy terminates TLS and forwards to `localhost:16666`.
2. **`webhookHandler`** (cmd/server/main.go), in this order:
   - only POST allowed;
   - read the raw body;
   - `verifySignature`: HMAC-SHA256 of the body with `GITHUB_WEBHOOK_SECRET`, compared in
     constant time (`hmac.Equal`) to the `X-Hub-Signature-256` header; missing header = reject (401);
   - dedup on `X-GitHub-Delivery` (5-minute window, in memory, mutex-protected);
   - ignore anything except `pull_request` events;
   - parse JSON into `PullRequestEvent` (action, number, head SHA, repo name, installation id);
   - `shouldTriggerScan`: only `opened`, `synchronize`, `reopened`;
   - reply `200 {"status":"accepted"}` **immediately**, then `go processEvent(event)`.
   Replying first matters: GitHub times out slow webhooks; a scan takes seconds.
3. **`processEvent`** (background goroutine):
   1. `auth.GenerateAppJWT` -> `auth.GetInstallationToken` (section 5.2). Failure here only
      logs: no Check Run exists yet, so nothing can be marked failed.
   2. `fetch.SplitFullName("owner/repo")`.
   3. `ghapi.CreateCheckRun` -> a Check Run named "AuthGraph Security Scan" in `in_progress`.
      If this fails the scan still runs, just without a status.
   4. `os.MkdirTemp`, `fetch.FetchTarball(... head SHA)`, `fetch.ExtractTarball`.
      Any failure -> `ghapi.FailCheckRun` with a reason, then return.
   5. `sandbox.RunDockerScan(tmpDir)` -> a `*report.ScanReport` (section 5.4).
   6. Log counts, then `policy.Evaluate` and log each decision (this is only logging).
   7. `ghapi.CompleteCheckRun` -> internally calls `checkRunConclusion` ->
      `policy.Evaluate` again -> `policy.ConclusionFor` -> PATCH the Check Run.
   8. `ghapi.FormatReportAsComment` -> `ghapi.PostPRComment`.
   9. `defer os.RemoveAll(tmpDir)` cleans the unpacked code.
4. The developer sees the Check Run status on the PR and the comment under it.

---

## 5. Component deep dives

### 5.1 `cmd/server/main.go` — the front door
- `getWebhookSecret` reads the env var. `main` **refuses to start** if it is empty
  (otherwise signature checking would silently accept anything).
- `privateKeyPath` is a constant relative path (`secrets/authgraph-dev...pem`), resolved
  against the process working directory — which is why the systemd unit sets
  `WorkingDirectory=/home/ubuntu/authgraph`. (A comment above it still says "points at
  SentryGrep's key"; that TODO is stale.)
- Dedup state: `seenDeliveries` map + mutex; `purgeOldDeliveries` runs on each request.
  A delivery is recorded *before* processing, so a failed run is not retried by redelivery
  within 5 minutes. It resets on restart and does not work across multiple servers.
- Routes: `/webhook` (POST) and `/` (health: `{"status": "AuthGraph bot is running"}`).
- Every `processEvent` is a new goroutine, so concurrent PRs run concurrent scans
  (no queue, no limit).

### 5.2 `internal/auth` — proving who we are
A GitHub App authenticates in two steps:
- `GenerateAppJWT`: signs a JWT with the app's RSA private key (RS256). Claims: issuer =
  the App ID constant (`githubAppID`), issued-at = now minus 60 s (clock-skew allowance),
  expires = now plus 9 minutes (GitHub's maximum is 10). This JWT identifies the **app**.
- `GetInstallationToken`: POSTs the JWT to `/app/installations/{id}/access_tokens` and gets a
  token (valid about an hour) for **that installation**. Every later API call uses it.
The private key never leaves the server; GitHub verifies the signature with the public key.

### 5.3 `internal/fetch` — getting the code
- `FetchTarball`: GET `/repos/{owner}/{repo}/tarball/{ref}` with the installation token,
  where `ref` is the **head commit SHA** (not a branch name), so the scanned code is exactly
  what was pushed. 30-second timeout.
- `ExtractTarball`: gunzip + untar into the temp dir. GitHub wraps everything in a
  `owner-repo-sha/` folder; the first path segment is stripped. Safety: a path-traversal
  check (`target must stay inside destDir`); only directories and regular files are
  written, so symlinks and special files are ignored. There is **no size cap** on extraction.

### 5.4 `internal/sandbox/scan.go` — scanning and enriching
`RunDockerScan(targetDir)`:
1. Makes a temp output dir; runs `docker run --rm -v <target>:/target:ro,z -v <out>:/output:z
   sentrygrep-scanner --target /target --output /output/report.json`, 3-minute timeout.
   (`:z` relabels for SELinux, needed on Fedora.)
2. Exit codes: 0 and 1 are fine (1 = scanner found something at/over its own threshold);
   2 or more = real error. Timeout = error.
3. Reads `report.json` into `report.ScanReport`.
4. `enrichFindings` for each finding:
   - maps `/target/...` back to the host path and parses that Go file with `go/parser`;
   - `findEnclosingFunction` finds the `FuncDecl` whose line range contains the finding;
   - sets `Location.Function`;
   - computes `finding_id = hex(sha256(rule_id|file|function))[:16]`; if the function cannot
     be found it falls back to `rule_id|file|line` and logs a warning;
   - `assignConfidence`: if still `unconfirmed`, CWE is `CWE-78` and Semgrep's own rule
     confidence is HIGH, set `likely`. Nothing else is ever upgraded here.

Why Go computes the ID and not Python: Semgrep does not report function names, but Go can
parse the source. `scanner.py` still writes a provisional ID that Go overwrites.

### 5.5 `scanner/` — the container
- `Dockerfile`: `python:3.11-slim`, installs `semgrep==1.167.0` and PyYAML, copies
  `scanner.py` and `rules/`, entrypoint `python3 scanner.py`.
- `build.sh` (run from the repo root only): deletes and recreates `scanner/rules/`, copies each
  catalog folder's `rule.yaml` + `meta.yaml` into it (fails if either is missing), then
  `docker build -t sentrygrep-scanner scanner/`. The image name is a leftover from the
  predecessor project.
- `scanner.py`:
  - `run_semgrep`: runs `semgrep --config p/golang` (Semgrep's **community Go ruleset**,
    downloaded from the Semgrep registry at run time, so the container needs outbound
    internet) **plus** each `rule.yaml` under `rules/` as `--config`. Exit code above 1 is
    an error.
  - `load_rule_references`: reads each rule folder's `meta.yaml` references and maps every
    rule `id` in `rule.yaml` to them.
  - `get_references_for_rule`: finds references by exact id or by suffix (Semgrep prefixes
    the id with a path-derived string; the suffix match handles that and rule variants).
    Community-ruleset findings have no references.
  - `parse_results`: for each Semgrep hit builds one finding dict: severity as Semgrep gave
    it (`ERROR`/`WARNING`/`INFO`), CWE from the rule metadata (first entry, text before the
    colon, else `UNCLASSIFIED`), `confidence: "unconfirmed"`, `semgrep_confidence` from
    metadata, `risk_context` nulls, `suppressed: false`, location, and evidence. The snippet
    is **read from the source file** because Semgrep returns "requires login" for the lines
    when not logged in; reads are limited to files inside the target. Findings are sorted
    by severity.
  - `write_report` writes the JSON; `main` also prints a summary and exits 1 if anything is
    at or above `--threshold` (default ERROR). Go tolerates that exit code.

### 5.6 `internal/report/schema.go` — the Output Contract
Plain Go structs mirroring the JSON: `ScanReport` (timestamp, totals, `by_severity`,
`by_cwe`, `findings`) and `Finding`. Who fills each field:

| Field | Set by | Meaning |
|---|---|---|
| `finding_id` | Go (`enrichFindings`) | stable id, see 5.4 |
| `rule_id` | Semgrep | which rule matched |
| `severity` | Semgrep rule | ERROR / WARNING / INFO |
| `cwe` | rule metadata | e.g. CWE-862 |
| `confidence` | scanner.py -> Go | `unconfirmed`, or `likely` for CWE-78 high |
| `semgrep_confidence` | rule metadata | Semgrep's own rating |
| `risk_context` | nobody yet (Layer 3) | `internet_facing`, `source`; null today |
| `suppressed`, `suppression_reason` | nobody yet (Layer 5 feature) | false / null |
| `location` | scanner.py + Go | file, line, col, end_line, function |
| `evidence.static` | scanner.py | message and code snippet |
| `evidence.dynamic` | nobody yet (Layer 4) | null |
| `references` | scanner.py from meta.yaml | public advisories |

### 5.7 `internal/policy` — Layer 2
- `policy.rego`: package `authgraph.policy`; a `table` of severity -> confidence -> decision
  and `decision := table[input.severity][input.confidence]`. There is **no default**: an
  unknown combination leaves `decision` undefined on purpose, so Go can fail instead of
  silently passing.

  | severity \ confidence | confirmed | likely | unconfirmed | inconclusive |
  |---|---|---|---|---|
  | high | block | block | warn | warn |
  | medium | block | warn | warn | note |
  | low | warn | note | note | note |

  Only `confirmed/medium = block` and `unconfirmed/high = warn` come from the spec; the rest
  are project decisions (2026-11-01).
- `policy.go`:
  - `//go:embed policy.rego` puts the Rego inside the binary (no separate OPA server).
  - `query()` compiles it once (`sync.Once`) with `rego.New(...).PrepareForEval`.
  - `Evaluate(report)`: for each non-suppressed finding, `normSeverity` (ERROR/high -> high,
    WARNING/medium -> medium, INFO/low -> low, anything else = error), builds the input map
    (a `risk_context` that is all-nil is passed as null; if present it is passed but the Rego
    ignores it), evaluates, requires a string result, and tracks the overall decision by rank
    (block 2 > warn 1 > note 0). Empty report = `note`. Suppressed findings are skipped and
    do not appear in the result.
  - `ConclusionFor`: block -> `failure`, warn -> `neutral`, note -> `success`, anything else
    -> `failure` (fail closed).

### 5.8 `internal/ghapi` — talking back to GitHub
- `CreateCheckRun`: POST `/check-runs`, status `in_progress`, returns the id.
- `checkRunConclusion`: runs the policy; on error -> `failure` titled "Policy evaluation
  failed"; else conclusion from `ConclusionFor`, title "N finding(s), policy: X" (or
  "No issues found" for zero).
- `CompleteCheckRun`: PATCH the check to `completed` with that conclusion; the summary text
  is the same Markdown as the PR comment.
- `FailCheckRun`: PATCH to `completed` / `failure` with a reason. Its own error is ignored by
  callers (known gap).
- `PostPRComment`: POST to `/issues/{n}/comments` (PRs are issues for comments); expects 201.
- `FormatReportAsComment` (+ `renderFinding`): headline with the overall policy decision, then
  per finding: decision icon, decision, CWE, severity, confidence, `path:line`, function,
  message, snippet in a code fence, references. Lists at most 10, counts the rest and the
  suppressed ones, ends with a decision key. Untrusted text is neutralized: `oneLine` collapses
  whitespace and escapes `<`, `>` and `@`; `inlineCode` swaps backticks; `fenced` picks a fence
  longer than any backtick run in the snippet; `trimSnippet` caps 15 lines / 1500 characters;
  `relPath` strips the `/target/` prefix.

### 5.9 `cmd/scan/main.go` — the local twin
Takes a directory, runs the same `RunDockerScan`, prints each finding
(`SEVERITY CWE file:line fn=<name> id=<id>` plus references), then `policy.Evaluate` and prints
`id=<finding_id> decision=<d>` per finding and `overall decision=<d>`. Exit codes: 1 if overall
is block, 0 otherwise, 2 on any error. This is how everything is regression-tested without
GitHub: `go run ./cmd/scan testdata`.

---

## 6. The rules, line by line

All three live in `internal/rules/catalog/<folder>/` as `rule.yaml` (the Semgrep rule),
`meta.yaml` (id, CWE, title, references), and `rule.go` (a Semgrep **test fixture**: lines
marked `// ruleid:` must match, `// ok:` must not; `semgrep --test` pairs `rule.go` with
`rule.yaml` by file name).

### 6.1 CWE-862 `authz-missing-ownership-check` (WARNING, Semgrep confidence MEDIUM)
Matches this shape inside one function:
```
$RESOURCE, $ERR := $FETCH_FN(...)     (or = instead of :=)
...
$MUTATE_FN(..., $RESOURCE, ...)
```
with constraints:
- `$FETCH_FN` name matches `Get|Find|Fetch|Load|Lookup|Resolve|Retrieve ... By ID|Key|Name|Slug|Index`
  (case-insensitive), e.g. `GetTicketByID`;
- `$MUTATE_FN` name matches `Delete|Remove|Update|Modify|Destroy|Drop|Revoke`;
- **excluded** if the lookup key is a string literal (not user-controllable);
- **excluded** if, after the fetch, any call whose name contains `Permission`, `Authorize`,
  `CanRead`, `CanWrite`, `CanAccess`, `Ownership`, `CheckAccess`, `IsOwner`, `HasAccess`,
  `HasPermission`, `IsAuthorized`, `IsAllowed`, `VerifyAccess`, `CheckPermission` or
  `RequirePermission` appears.
Limits (stated in the rule): matches by naming convention, not data flow; cannot tell a
user-supplied numeric id from a constant; does **not** catch route/middleware-level gaps
(the second Gitea advisory).

### 6.2 CWE-918 `ssrf-unvalidated-url-request` (WARNING, MEDIUM)
Matches `http.Get($URL)`, `http.Post($URL, ...)`, `http.Head($URL)`, `http.NewRequest($M, $URL, ...)`,
`http.NewRequestWithContext($C, $M, $URL, ...)` where the URL is a variable. Excluded when:
the URL is a string literal; a call named like `validate/sanitize/check/isprivate/issafe/ensure`
combined with `url/request/addr/host/ip` appears earlier in the function; or the URL came from
`fmt.Sprintf` with a fixed `http(s)://` prefix (only a path segment is interpolated).

### 6.3 CWE-78 three rules (all ERROR, Semgrep confidence HIGH)
All concern `exec.Command` / `exec.CommandContext` with a shell and `-c`:
- `...-concat`: the command string is built inline with `+` or `fmt.Sprintf`;
- `...-indirect`: built into a variable on an earlier line, then passed to the shell;
- `...-direct`: any variable passed straight to `sh -c` (excludes a literal string).
Because several variants can match one line, two findings can share the same function and
therefore the same `finding_id` (accepted limitation). CWE-78 `meta.yaml` references: the Civo
CLI v1.5.4 release and PR 595.

### 6.4 Why `meta.yaml` and the reference test
`TestAllRulesHaveReferences` (internal/rules) walks every catalog folder with a `meta.yaml`
and fails if `rule_id` or `cwe` is empty, there are no references, or any reference starts
with `TODO`. It checks presence, not that a link is correct — verifying a reference by reading
it is a manual step (Methodology, Stage 2).

---

## 7. Worked example: the three baseline findings

`go run ./cmd/scan testdata` (fixtures in `testdata/`):

| Finding | Why it matches | Severity | Confidence | Table cell | Decision |
|---|---|---|---|---|---|
| CWE-78 `cwe78_check.go`, fn `vulnerable` (`511e932569afaf29`) | variable passed to `sh -c` | ERROR -> high | `likely` (CWE-78 + Semgrep HIGH) | high/likely | **block** |
| CWE-862 `authz_check.go`, fn `removeTicket` (`f3edc922dd9db12d`) | `GetTicketByID` then `DeleteTicket`, no permission call | WARNING -> medium | unconfirmed | medium/unconfirmed | **warn** |
| CWE-918 `ssrf_check.go`, fn `fetchPeerInfo` (`9fa48477df57d893`) | `http.Get(peerURL)`, no validation | WARNING -> medium | unconfirmed | medium/unconfirmed | **warn** |

Overall = strictest = **block** -> `cmd/scan` exits 1; on a real PR the Check Run is `failure`.
Remove the CWE-78 file and overall becomes `warn` -> `neutral`. Fix everything -> `note` -> `success`.

---

## 8. Infrastructure and deployment

**Where:** one AWS EC2 `t3.micro`, region `us-east-1`, Ubuntu 26.04, 908 MB RAM + 2 GB swap
file, 15 GB disk. (`START_HERE.md` still says `eu-north-1`; that is stale.)

| Part | What it does | Where configured |
|---|---|---|
| DuckDNS `authgraph.duckdns.org` | stable name for the changing IP | DuckDNS account |
| Caddy | HTTPS front door, auto TLS, reverse proxy to `localhost:16666` | `/etc/caddy/Caddyfile` |
| systemd `authgraph.service` | runs `/home/ubuntu/authgraph/authgraph-bot` as user `ubuntu`, `WorkingDirectory=/home/ubuntu/authgraph`, `Restart=on-failure` after 3 s, `NoNewPrivileges=true`, env `GITHUB_WEBHOOK_SECRET` | unit file (secret stays out of git) |
| Docker | runs the scanner image `sentrygrep-scanner`, **built on the server** from `scanner/` | server |
| Swap file | Semgrep crashed (SIGSEGV) on 1 GB RAM without it | server |

On the server, `/home/ubuntu/authgraph/` holds: `authgraph-bot` (live binary), backups
(`.bak` original, `.shadow`, `.enforce` previous builds), `scanner/`, `secrets/`.

**Deploying a new Go binary** (the human does this; keep a backup; the final `start` always runs):
```
GOOS=linux GOARCH=amd64 go build -o authgraph-bot.new ./cmd/server
scp -i <key> authgraph-bot.new ubuntu@<host>:/home/ubuntu/authgraph/authgraph-bot.new
ssh -i <key> ubuntu@<host> 'cd /home/ubuntu/authgraph && test -s authgraph-bot.new &&
  chmod +x authgraph-bot.new && cp -p authgraph-bot authgraph-bot.prev &&
  sudo systemctl stop authgraph; mv authgraph-bot.new authgraph-bot;
  sudo systemctl start authgraph; sleep 3; systemctl is-active authgraph'
```
**Rollback:** stop, copy a `.prev`/`.enforce`/`.shadow` file over `authgraph-bot`, start.
**Rule or scanner change** needs the Docker image rebuilt on the server (the rules are baked
in); a Go-only change does not. **Logs:** `sudo journalctl -u authgraph -f`.
Check the Docker build output: a step marked `CACHED` did not re-run, so a `scanner.py` change
is not live until its `COPY` step re-runs.

**GitHub side:** the App `authgraph-dev` (webhook URL `https://authgraph.duckdns.org/webhook`)
is installed on selected repositories; see slide "How GitHub fits in" for roles. Branch
protection (a repository setting) is what turns a failed Check Run into a blocked merge.

---

## 9. Testing — what proves what

| Command | Proves |
|---|---|
| `go build ./...` | everything compiles |
| `go test ./internal/policy -v` | every severity x confidence cell (24 cases, with/without risk_context), empty report, suppressed, mixed severities, unknown values error, `ConclusionFor` |
| `go test ./internal/ghapi` | conclusion mapping (incl. fail-closed) and the Markdown renderer (injection cases) |
| `go test ./internal/sandbox` | `assignConfidence` rules |
| `go test ./internal/rules` | every rule has references (`TestAllRulesHaveReferences`) |
| `bash scanner/build.sh` | rules copied and the image builds |
| `go run ./cmd/scan testdata` | end to end through Docker + policy; must print the three baseline ids |

**The gate** (run after every change; AGENTS.md):
`go build ./... && go test ./... && bash scanner/build.sh && go run ./cmd/scan testdata`
with the three baseline ids unchanged. Not covered by automated tests: the webhook handler,
auth, fetch, and the live GitHub calls (they were verified by live PRs and logs).

---

## 10. Security properties and known gaps

**Holds today:** signed webhooks only; server won't start without the secret; duplicate
deliveries ignored; PR code never executed; scanned read-only in a container; tarball path
traversal blocked; untrusted text sanitized in comments; policy errors fail closed; private key
git-ignored and never in history.

**Known gaps (do not claim otherwise):**
- Only CWE-78 can reach `block`; CWE-862/918 stay `warn` until Layer 4 can confirm them.
- A new comment per push; no state between pushes; dedup is in memory, one instance.
- Tarball extraction has no size cap; every webhook starts an unbounded goroutine and a
  container (no queue).
- The container has no memory limit, and its network cannot simply be disabled because
  `scanner.py` downloads the community ruleset (`p/golang`) at run time; bundling those rules
  would come first.
- Rule coverage is by naming convention (false negatives and positives possible); the authz rule
  misses middleware-level gaps.
- `FailCheckRun`'s error is ignored; `finding_id` collides for the same rule twice in one
  function; the `privateKeyPath` TODO comment is stale; "sentrygrep" names remain on the image.
- The Check Run and the comment show the same content (a Layer 5 decision still open).
- IDs depend on the `/target/` mount path and the rule ids staying the same; changing either
  would change every `finding_id` and break suppressions.

---

## 11. How to change things (recipes)

- **Change a policy decision:** edit the `table` in `policy.rego`, update the `want` map in
  `policy_test.go`, run `go test ./internal/policy`. No other code changes.
- **Change when CWE-78 (or another rule) earns `likely`:** edit `assignConfidence`
  (internal/sandbox/scan.go) and its test.
- **Add a rule:** new folder under `internal/rules/catalog/` with `rule.yaml`, `meta.yaml`
  (real, read-and-verified references) and a `rule.go` fixture with `ruleid:`/`ok:` cases;
  `semgrep --test`; `go test ./internal/rules`; `bash scanner/build.sh`; run the gate;
  rebuild the image on the server.
- **Change what the comment shows:** `FormatReportAsComment`/`renderFinding` in
  `internal/ghapi/comment.go`, then update `comment_test.go`.
- **Make a new layer affect the verdict:** new data goes into `report.Finding`
  (e.g. `confidence` from Layer 4, `risk_context` from Layer 3); the policy table already
  reads `confidence`; `risk_context` is accepted by `Evaluate` but unused in the Rego.

---

## 12. Glossary

- **CWE-862/863:** missing / incorrect authorization (BOLA/IDOR family). **CWE-918:** SSRF.
  **CWE-78:** OS command injection.
- **Semgrep:** pattern-matching static analyzer; rules are YAML.
- **GitHub App / installation / installation token / JWT:** the app's identity, its install on
  a repo owner, the short-lived token for API calls, and the signed proof used to get it.
- **Webhook:** GitHub's HTTP POST telling us an event happened. **HMAC:** keyed hash that proves
  the sender knew the shared secret.
- **Check Run / conclusion:** the status line on a PR; `failure`, `neutral`, `success`.
- **Branch protection:** repository setting that can require a check before merging.
- **OPA / Rego:** policy engine and its language; here a lookup table compiled into the binary.
- **Confidence:** how sure we are a finding is real: `confirmed`, `likely`, `unconfirmed`,
  `inconclusive`. **Severity:** impact level from the rule: ERROR/WARNING/INFO.
- **Fail closed:** on an error, choose the safe outcome (fail the check), not the permissive one.
- **Shadow mode:** compute and log a decision without acting on it.
- **Output Contract:** the fixed JSON shape of a finding.

---

## 13. Self-test — can you answer these?

1. Why does the webhook reply 200 before scanning? What would happen otherwise?
2. What stops a forged webhook? Why is the secret check done before parsing JSON?
3. Why is the code fetched by commit SHA and not by branch name?
4. What exactly is mounted into the container, and with what permissions?
5. Why is the `finding_id` computed in Go, and why function-level, not line-level?
6. Why can't CWE-862 block today, and what would change that?
7. Walk the three baseline findings to their decisions, including the table cell.
8. What does "fail closed" mean in this code? Name two places it applies.
9. Why did we need shadow mode, and what did it reveal?
10. Which parts of a comment come from the attacker-controlled repo, and how are they made safe?
11. What does `TestAllRulesHaveReferences` check, and what can it not check?
12. Why does the container need internet today, and why does that block `--network none`?
13. What is on the EC2 box, and what does each service do? How do you roll back a bad deploy?
14. Where would a Layer 4 result plug in, and which existing code already consumes it?
15. What are the three biggest limits you would state before a panel asks?

Answers are all in this document; if you cannot find one, that section needs a second read.
