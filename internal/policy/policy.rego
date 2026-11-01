package authgraph.policy

import rego.v1

# Layer 2 decision table (docs/layer2-plan.md).
# Input: one finding {severity, confidence, risk_context, suppressed}.
# Output: decision = block | warn | note.
#
# risk_context is accepted but does not influence the decision in this phase
# (Layer 3 modifiers are defined when Layer 3 exists); null is neutral.
#
# There is deliberately no default: an unknown severity/confidence leaves
# `decision` undefined so the Go caller can fail instead of silently passing.

table := {
	"high": {
		"confirmed": "block",
		"likely": "block",
		"unconfirmed": "warn",
		"inconclusive": "warn",
	},
	"medium": {
		"confirmed": "block",
		"likely": "warn",
		"unconfirmed": "warn",
		"inconclusive": "note",
	},
	"low": {
		"confirmed": "warn",
		"likely": "note",
		"unconfirmed": "note",
		"inconclusive": "note",
	},
}

decision := table[input.severity][input.confidence]
