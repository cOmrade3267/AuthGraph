package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllRulesHaveReferences walks internal/rules/catalog/*/meta.yaml and
// verifies every rule has a non-empty RuleID, CWE, and at least one real
// (non-TODO) public reference. This test intentionally fails the build
// until placeholder references are replaced with real CVE/GHSA URLs.
func TestAllRulesHaveReferences(t *testing.T) {
	catalogDir := filepath.Join("catalog")

	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		t.Fatalf("failed to read catalog directory %s: %v", catalogDir, err)
	}

	found := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metaPath := filepath.Join(catalogDir, entry.Name(), "meta.yaml")
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			continue // directory without meta.yaml — skip (e.g. stub dirs)
		}

		found++
		dir := filepath.Join(catalogDir, entry.Name())
		rule, err := LoadRule(dir)
		if err != nil {
			t.Errorf("%s: failed to load meta.yaml: %v", entry.Name(), err)
			continue
		}

		if rule.RuleID == "" {
			t.Errorf("%s: rule_id is empty", entry.Name())
		}

		if rule.CWE == "" {
			t.Errorf("%s: cwe is empty", entry.Name())
		}

		if len(rule.References) == 0 {
			t.Errorf("%s: references is empty — every rule must cite at least one public CVE/GHSA", entry.Name())
			continue
		}

		for i, ref := range rule.References {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ref)), "TODO") {
				t.Errorf("%s: references[%d] is a TODO placeholder — replace with a real CVE/GHSA URL before merging", entry.Name(), i)
			}
		}
	}

	if found == 0 {
		t.Fatal("no meta.yaml files found in catalog — expected at least one rule")
	}
}
