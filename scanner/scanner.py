#!/usr/bin/env python3
"""
SentryGrep Scanner — runs Semgrep with custom + default rules, parses results.

Usage:
    python3 scanner.py --target ./path/to/go/code
    python3 scanner.py --target ./path/to/go/code --threshold WARNING
    python3 scanner.py --target ./path/to/go/code --output report.json

Exit codes:
    0 — no findings above threshold
    1 — findings above threshold (CI should fail)
    2 — scanner error (semgrep not found, bad config, etc.)
"""

import argparse
import hashlib
import json
import subprocess
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# WHY this ordering?  We define severity as a numeric scale so we can do
# threshold comparisons like "fail if anything >= WARNING".  The mapping
# is intentionally simple — three levels, matching Semgrep's own model.
# ---------------------------------------------------------------------------
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def run_semgrep(target: str, rules_dir: str) -> dict:
    """
    Run Semgrep and return parsed JSON output.
    """
    cmd = [
        "semgrep",
        # Use community Go rules
        "--config", "p/golang",
        "--json",
        "--quiet",
    ]
    
    # We must explicitly pass rule.yaml files so semgrep doesn't choke on meta.yaml
    rules_path = Path(rules_dir)
    if rules_path.is_dir():
        for rule_file in rules_path.rglob("rule.yaml"):
            cmd.extend(["--config", str(rule_file)])
    else:
        cmd.extend(["--config", rules_dir])
        
    cmd.append(target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("ERROR: 'semgrep' not found. Install: pip install semgrep", file=sys.stderr)
        sys.exit(2)

    if result.returncode > 1:
        print(f"ERROR: Semgrep failed (exit {result.returncode}):", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(2)

    return json.loads(result.stdout)


def get_references_for_rule(rules_dir: str, rule_id: str) -> list:
    """
    Look up the references in meta.yaml for the given rule_id.
    We assume rules are in subdirectories, e.g. rules/cwe-78/rule.yaml and rules/cwe-78/meta.yaml
    """
    # The rule_id in semgrep might look like 'scanner.rules.cwe-78-cmdinject.rule.go-cwe-78-shell-command-injection-direct'
    # or it might just be the ID defined in the yaml file.
    # Semgrep check_id usually ends with the actual rule id from the yaml.
    # It's easier to just search all meta.yaml files in rules_dir.
    path = Path(rules_dir)
    if not path.is_dir():
        return []
    
    for meta_file in path.rglob("meta.yaml"):
        try:
            with open(meta_file, "r") as f:
                meta = yaml.safe_load(f)
                # Compare against the actual rule_id or check if it matches the folder name
                # Since multiple rule IDs could be in one rule.yaml, 
                # let's just use the meta.yaml in the same folder if we know the rule ID belongs to it.
                # Actually, the simplest is if the meta_file has a 'rule_id' field matching our suffix.
                # Wait, the meta.yaml has a 'rule_id' field? Let's check. 
                # Yes, in the setup it usually does. If not, we can fall back to checking if rule_id contains the folder name.
                # Let's just return the references if we find a match, or if there's only one.
                # Let's check meta.yaml contents.
                # If rule_id from Semgrep ends with the rule_id in meta.yaml
                if meta and "rule_id" in meta and rule_id.endswith(meta["rule_id"]):
                    return meta.get("references", [])
        except Exception:
            pass
    return []


def parse_results(raw: dict, rules_dir: str) -> dict:
    findings = []
    by_severity = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    by_cwe = {}

    for result in raw.get("results", []):
        severity = result["extra"]["severity"]
        metadata = result["extra"].get("metadata", {})

        cwe_list = metadata.get("cwe", [])
        if cwe_list:
            cwe = cwe_list[0].split(":")[0].strip()
        else:
            cwe = "UNCLASSIFIED"

        snippet = result["extra"].get("lines", "").strip()
        rule_id = result["check_id"]
        filepath = result["path"]
        line = result["start"]["line"]
        
        # Try to extract function name from extra.metavars or somewhere if available
        # Semgrep doesn't typically output function name natively unless captured in a metavar.
        # We will use function name if we can, else just fallback.
        # Actually, let's check if 'function' or similar is in extra
        function_name = None
        # We don't have a reliable function name in standard Semgrep JSON without custom metavars,
        # so fallback to rule_id|file|line
        
        hash_input = f"{rule_id}|{filepath}|{line}"
        if function_name:
            hash_input = f"{rule_id}|{filepath}|{function_name}"
            
        finding_id = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:16]
        
        semgrep_confidence = metadata.get("confidence", "UNKNOWN")

        finding = {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": severity,
            "cwe": cwe,
            "confidence": "unconfirmed",
            "semgrep_confidence": semgrep_confidence,
            "risk_context": {
                "internet_facing": None,
                "source": None
            },
            "suppressed": False,
            "suppression_reason": None,
            "location": {
                "file": filepath,
                "line": line,
                "col": result["start"]["col"],
                "end_line": result["end"]["line"],
                "function": function_name
            },
            "evidence": {
                "static": {
                    "message": result["extra"]["message"],
                    "snippet": snippet
                },
                "dynamic": None
            },
            "references": get_references_for_rule(rules_dir, rule_id)
        }

        findings.append(finding)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))

    return {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_cwe": by_cwe,
        "findings": findings,
    }


def write_report(report: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(f"Report written to {path} ({report['total_findings']} findings)")


def print_summary(report: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  SentryGrep Scan Report — {report['scan_timestamp']}")
    print(f"{'='*60}")
    print(f"  Total findings: {report['total_findings']}")
    print()

    print("  By Severity:")
    for sev in ["ERROR", "WARNING", "INFO"]:
        count = report["by_severity"].get(sev, 0)
        bar = "█" * count
        print(f"    {sev:8s}  {count:3d}  {bar}")
    print()

    print("  By CWE:")
    for cwe, count in sorted(report["by_cwe"].items(), key=lambda x: -x[1]):
        print(f"    {cwe:30s}  {count:3d}")
    print()

    print("  Top findings:")
    for f in report["findings"][:10]:
        print(f"    [{f['severity']:7s}] {f['location']['file']}:{f['location']['line']} — {f['cwe']}")
        if f["evidence"]["static"]["snippet"]:
            first_line = f["evidence"]["static"]["snippet"].split("\n")[0][:72]
            print(f"             {first_line}")
    if report["total_findings"] > 10:
        print(f"    ... and {report['total_findings'] - 10} more")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SentryGrep: Run Semgrep with custom CWE rules and parse results."
    )
    parser.add_argument(
        "--target", required=True,
        help="Path to the Go codebase to scan"
    )
    parser.add_argument(
        "--rules", default="rules",
        help="Path to custom rules directory (default: rules/)"
    )
    parser.add_argument(
        "--output", default="report.json",
        help="Output file for the JSON report (default: report.json)"
    )
    parser.add_argument(
        "--threshold", default="ERROR",
        choices=["ERROR", "WARNING", "INFO"],
        help="Fail (exit 1) if any finding meets or exceeds this severity"
    )

    args = parser.parse_args()

    raw = run_semgrep(args.target, args.rules)
    report = parse_results(raw, args.rules)

    write_report(report, args.output)
    print_summary(report)

    threshold_rank = SEVERITY_RANK[args.threshold]
    for finding in report["findings"]:
        if SEVERITY_RANK.get(finding["severity"], 0) >= threshold_rank:
            print(f"FAIL: {finding['severity']} finding exceeds threshold ({args.threshold})")
            sys.exit(1)

    print(f"PASS: No findings at or above {args.threshold} severity")
    sys.exit(0)


if __name__ == "__main__":
    main()
