// Package policy is Layer 2: it turns Layer 1 findings into block|warn|note
// decisions using the Rego table in policy.rego (see docs/layer2-plan.md).
package policy

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/cOmrade3267/authgraph/internal/report"
)

const (
	Block = "block"
	Warn  = "warn"
	Note  = "note"
)

//go:embed policy.rego
var regoSource string

// FindingDecision is the decision for one non-suppressed finding.
type FindingDecision struct {
	FindingID string
	Decision  string
}

// Result holds per-finding decisions (suppressed findings omitted, input order
// kept) and the overall decision (strictest wins; empty = note).
type Result struct {
	Findings []FindingDecision
	Overall  string
}

var (
	prepOnce sync.Once
	prepared rego.PreparedEvalQuery
	prepErr  error
)

func query() (rego.PreparedEvalQuery, error) {
	prepOnce.Do(func() {
		prepared, prepErr = rego.New(
			rego.Query("data.authgraph.policy.decision"),
			rego.Module("policy.rego", regoSource),
		).PrepareForEval(context.Background())
	})
	return prepared, prepErr
}

// normSeverity maps the scanner's Semgrep names (ERROR/WARNING/INFO) and the
// contract names (high/medium/low) to the contract names.
func normSeverity(s string) (string, error) {
	switch strings.ToLower(s) {
	case "error", "high":
		return "high", nil
	case "warning", "medium":
		return "medium", nil
	case "info", "low":
		return "low", nil
	}
	return "", fmt.Errorf("unknown severity %q", s)
}

func rank(d string) int {
	switch d {
	case Block:
		return 2
	case Warn:
		return 1
	}
	return 0
}

// Evaluate returns a decision for every non-suppressed finding in r.
// Unknown severity or confidence values are an error, never a silent pass.
func Evaluate(r report.ScanReport) (Result, error) {
	q, err := query()
	if err != nil {
		return Result{}, fmt.Errorf("policy: prepare: %w", err)
	}

	res := Result{Overall: Note}
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		sev, err := normSeverity(f.Severity)
		if err != nil {
			return Result{}, fmt.Errorf("policy: finding %s: %w", f.FindingID, err)
		}

		var rc any // null risk_context is neutral
		if f.RiskContext.InternetFacing != nil || f.RiskContext.Source != nil {
			rc = map[string]any{
				"internet_facing": f.RiskContext.InternetFacing,
				"source":          f.RiskContext.Source,
			}
		}
		input := map[string]any{
			"severity":     sev,
			"confidence":   f.Confidence,
			"risk_context": rc,
			"suppressed":   f.Suppressed,
		}

		rs, err := q.Eval(context.Background(), rego.EvalInput(input))
		if err != nil {
			return Result{}, fmt.Errorf("policy: finding %s: eval: %w", f.FindingID, err)
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			return Result{}, fmt.Errorf("policy: finding %s: no decision for severity=%q confidence=%q",
				f.FindingID, sev, f.Confidence)
		}
		d, ok := rs[0].Expressions[0].Value.(string)
		if !ok {
			return Result{}, fmt.Errorf("policy: finding %s: non-string decision %v",
				f.FindingID, rs[0].Expressions[0].Value)
		}

		res.Findings = append(res.Findings, FindingDecision{FindingID: f.FindingID, Decision: d})
		if rank(d) > rank(res.Overall) {
			res.Overall = d
		}
	}
	return res, nil
}
