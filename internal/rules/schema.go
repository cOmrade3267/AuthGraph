package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule represents the metadata for a single detection rule in the catalog.
// Each rule maps to a CWE class and must have at least one public CVE/GHSA
// reference (see §5 of docs/Architecture.md).
type Rule struct {
	RuleID     string   `yaml:"rule_id"`
	CWE        string   `yaml:"cwe"`
	Title      string   `yaml:"title"`
	Languages  []string `yaml:"languages"`
	References []string `yaml:"references"`
	VerifierID *string  `yaml:"verifier_id,omitempty"`
}

// LoadRule reads meta.yaml from the given directory and unmarshals it
// into a Rule.
func LoadRule(dir string) (*Rule, error) {
	path := filepath.Join(dir, "meta.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading meta.yaml from %s: %w", dir, err)
	}

	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parsing meta.yaml from %s: %w", dir, err)
	}

	return &rule, nil
}
