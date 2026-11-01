# AuthGraph

A GitHub App that scans pull requests for authorization vulnerabilities (CWE-862/863 is the anchor class) using Semgrep in a Docker sandbox, with planned dynamic confirmation by response-replay diffing.

**Status**
- Layer 1 (static detection and App delivery): built. Three rules (CWE-78, CWE-862, CWE-918), each backed by a public CVE/advisory and enforced by a test.
- Output Contract (deterministic `finding_id`, references, evidence): merged.
- Layer 2 (policy): next. Layers 3–5: planned. See `docs/Architecture.md`.

**Run locally**
```bash
bash scanner/build.sh && go run ./cmd/scan testdata
```

**Limits:** Go only; dynamic verification is demo-scope; "block" is advisory unless branch protection requires the check. Live webhook deployment is currently torn down.
