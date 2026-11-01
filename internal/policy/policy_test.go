package policy

import (
	"fmt"
	"testing"

	"github.com/cOmrade3267/authgraph/internal/report"
)

// want is the decision table from docs/layer2-plan.md, written out
// independently of policy.rego so the test checks the Rego, not itself.
var want = map[string]map[string]string{
	"high":   {"confirmed": Block, "likely": Block, "unconfirmed": Warn, "inconclusive": Warn},
	"medium": {"confirmed": Block, "likely": Warn, "unconfirmed": Warn, "inconclusive": Note},
	"low":    {"confirmed": Warn, "likely": Note, "unconfirmed": Note, "inconclusive": Note},
}

func finding(id, sev, conf string, withRisk bool) report.Finding {
	f := report.Finding{FindingID: id, Severity: sev, Confidence: conf}
	if withRisk {
		b, s := true, "Layer 3 graph"
		f.RiskContext = report.RiskContext{InternetFacing: &b, Source: &s}
	}
	return f
}

func TestDecisionTable(t *testing.T) {
	for _, sev := range []string{"high", "medium", "low"} {
		for _, conf := range []string{"confirmed", "likely", "unconfirmed", "inconclusive"} {
			for _, withRisk := range []bool{false, true} {
				risk := "null_risk_context"
				if withRisk {
					risk = "with_risk_context"
				}
				name := fmt.Sprintf("%s_severity_%s_confidence_%s_gives_%s", sev, conf, risk, want[sev][conf])
				t.Run(name, func(t *testing.T) {
					res, err := Evaluate(report.ScanReport{Findings: []report.Finding{finding("f1", sev, conf, withRisk)}})
					if err != nil {
						t.Fatal(err)
					}
					if len(res.Findings) != 1 || res.Findings[0].Decision != want[sev][conf] {
						t.Fatalf("got %+v, want decision %s", res.Findings, want[sev][conf])
					}
					if res.Overall != want[sev][conf] {
						t.Fatalf("overall = %s, want %s", res.Overall, want[sev][conf])
					}
				})
			}
		}
	}
}

func TestScannerSeverityNamesMapToContract(t *testing.T) {
	cases := map[string]string{"ERROR": Warn, "WARNING": Warn, "INFO": Note} // all unconfirmed
	for sev, wantDec := range cases {
		t.Run("scanner_"+sev+"_unconfirmed_gives_"+wantDec, func(t *testing.T) {
			res, err := Evaluate(report.ScanReport{Findings: []report.Finding{finding("f", sev, "unconfirmed", false)}})
			if err != nil {
				t.Fatal(err)
			}
			if res.Overall != wantDec {
				t.Fatalf("overall = %s, want %s", res.Overall, wantDec)
			}
		})
	}
}

func TestEmptyReportIsNote(t *testing.T) {
	res, err := Evaluate(report.ScanReport{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall != Note || len(res.Findings) != 0 {
		t.Fatalf("got %+v, want overall note and no findings", res)
	}
}

func TestSuppressedFindingIsIgnored(t *testing.T) {
	f := finding("s1", "high", "confirmed", false) // would block if evaluated
	f.Suppressed = true
	res, err := Evaluate(report.ScanReport{Findings: []report.Finding{f}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall != Note || len(res.Findings) != 0 {
		t.Fatalf("got %+v, want suppressed finding ignored (overall note)", res)
	}
}

func TestMixedSeveritiesStrictestWins(t *testing.T) {
	t.Run("low_note_plus_medium_warn_plus_high_confirmed_block_overall_block", func(t *testing.T) {
		res, err := Evaluate(report.ScanReport{Findings: []report.Finding{
			finding("a", "low", "unconfirmed", false),
			finding("b", "medium", "unconfirmed", false),
			finding("c", "high", "confirmed", false),
		}})
		if err != nil {
			t.Fatal(err)
		}
		got := []string{res.Findings[0].Decision, res.Findings[1].Decision, res.Findings[2].Decision}
		if got[0] != Note || got[1] != Warn || got[2] != Block || res.Overall != Block {
			t.Fatalf("got per-finding %v overall %s, want [note warn block] block", got, res.Overall)
		}
	})
	t.Run("low_note_plus_medium_warn_overall_warn", func(t *testing.T) {
		res, err := Evaluate(report.ScanReport{Findings: []report.Finding{
			finding("a", "low", "unconfirmed", false),
			finding("b", "medium", "unconfirmed", false),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Overall != Warn {
			t.Fatalf("overall = %s, want warn", res.Overall)
		}
	})
	t.Run("suppressed_block_plus_unsuppressed_warn_overall_warn", func(t *testing.T) {
		s := finding("s", "high", "confirmed", false)
		s.Suppressed = true
		res, err := Evaluate(report.ScanReport{Findings: []report.Finding{s, finding("w", "high", "unconfirmed", false)}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Overall != Warn || len(res.Findings) != 1 {
			t.Fatalf("got %+v, want only the warn finding, overall warn", res)
		}
	})
}

func TestUnknownValuesAreErrorsNotPasses(t *testing.T) {
	t.Run("unknown_severity_returns_error", func(t *testing.T) {
		if _, err := Evaluate(report.ScanReport{Findings: []report.Finding{finding("x", "CRITICAL", "confirmed", false)}}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unknown_confidence_returns_error", func(t *testing.T) {
		if _, err := Evaluate(report.ScanReport{Findings: []report.Finding{finding("x", "high", "maybe", false)}}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestConclusionFor(t *testing.T) {
	cases := map[string]string{Block: "failure", Warn: "neutral", Note: "success", "": "failure", "bogus": "failure"}
	for decision, wantConc := range cases {
		t.Run("decision_"+decision+"_maps_to_"+wantConc, func(t *testing.T) {
			if got := ConclusionFor(decision); got != wantConc {
				t.Fatalf("ConclusionFor(%q) = %s, want %s", decision, got, wantConc)
			}
		})
	}
}
