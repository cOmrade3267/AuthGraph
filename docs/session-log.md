## YYYY-MM-DD — branch: <branch-name>
**Done:** <what was written>
**Verified:** <how — real PR? which environment? or "not yet, pending AWS pass">
**Mid-flight:** <one line, or "none">
**Decided:** <the actual decision + why>
**Next:** <what picks this up next session>

2026-08-22: §7.1 (async webhook handler) and §7.2 (Check-Run-before-fetch, 
FailCheckRun on downstream errors) implemented, deployed, and verified.
- Verified async: real GitHub delivery response time dropped from 9.36s 
  (blocking) to 0.49s ({"status":"accepted"} ack).
- Verified failure path: deliberately broke Docker image (docker rmi 
  sentrygrep-scanner), triggered PR #10, confirmed Check Run showed 
  failure conclusion with reason instead of hanging. Restored image, 
  confirmed PR #11 scans normally again.
- Fixed unrelated bug found during testing: App was missing Pull requests 
  read/write permission, causing 403 on PR comment posting.
Known small gap: FailCheckRun's own error return is discarded at call 
sites — not logged if FailCheckRun itself fails. Low priority.
Next: §7.3 (fail-fast on empty webhook secret), §7.4 (delivery dedup).