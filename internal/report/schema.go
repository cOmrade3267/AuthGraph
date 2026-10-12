package report

type RiskContext struct {
	InternetFacing *bool   `json:"internet_facing"`
	Source         *string `json:"source"`
}

type Location struct {
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Col      int     `json:"col"`
	EndLine  int     `json:"end_line"`
	Function *string `json:"function"`
}

type StaticEvidence struct {
	Message string `json:"message"`
	Snippet string `json:"snippet"`
}

type Evidence struct {
	Static  StaticEvidence `json:"static"`
	Dynamic interface{}    `json:"dynamic"` // null for now
}

type Finding struct {
	FindingID         string      `json:"finding_id"`
	RuleID            string      `json:"rule_id"`
	Severity          string      `json:"severity"`
	CWE               string      `json:"cwe"`
	Confidence        string      `json:"confidence"`
	SemgrepConfidence string      `json:"semgrep_confidence"`
	RiskContext       RiskContext `json:"risk_context"`
	Suppressed        bool        `json:"suppressed"`
	SuppressionReason *string     `json:"suppression_reason"`
	Location          Location    `json:"location"`
	Evidence          Evidence    `json:"evidence"`
	References        []string    `json:"references"`
}

type ScanReport struct {
	ScanTimestamp string         `json:"scan_timestamp"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCWE         map[string]int `json:"by_cwe"`
	Findings      []Finding      `json:"findings"`
}
