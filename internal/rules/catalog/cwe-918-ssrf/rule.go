package ssrf_test

// =============================================================
// Combined Semgrep test file for ssrf-unvalidated-url-request
// Contains all positive (ruleid:) and negative (ok:) test cases.
// Semgrep --test matches this file to rule.yaml by basename.
// =============================================================

import (
	"fmt"
	"net/http"
)

// --- Ech0 shape: vulnerable (no validation before HTTP call) ---

func SendRequest(peerURL string) {
	// ruleid: ssrf-unvalidated-url-request
	resp, err := http.Get(peerURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Ech0 shape: safe (validation call before HTTP request) ---

func ValidatePublicHTTPURL(rawURL string) error {
	return nil // stub
}

func SendSafeRequest(peerURL string) {
	ValidatePublicHTTPURL(peerURL)
	// ok: ssrf-unvalidated-url-request
	resp, err := http.Get(peerURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Kyverno shape: vulnerable (struct field URL into NewRequest, no validation) ---

type ServiceCall struct {
	URL    string
	Method string
}

func executeAPICall(svc ServiceCall) {
	// ruleid: ssrf-unvalidated-url-request
	req, err := http.NewRequest(svc.Method, svc.URL, nil)
	if err != nil {
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Kyverno shape: safe (validateURL called before NewRequest) ---

func validateURL(rawURL string) error {
	return nil // stub
}

func executeAPICallSafe(svc ServiceCall) {
	validateURL(svc.URL)
	// ok: ssrf-unvalidated-url-request
	req, err := http.NewRequest(svc.Method, svc.URL, nil)
	if err != nil {
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Hardcoded URL (should NOT fire — not user-controlled) ---

func fetchHealthcheck() {
	// ok: ssrf-unvalidated-url-request
	resp, err := http.Get("http://localhost:8080/healthz")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Novel validation function name (not in the original hardcoded 5) ---
// This case would have been a false positive with the old rule.
// checkOutboundURL matches the metavariable-regex pattern (check + URL).

func checkOutboundURL(rawURL string) error {
	return nil // stub
}

func fetchPeerWithCheckURL(peerURL string) {
	checkOutboundURL(peerURL)
	// ok: ssrf-unvalidated-url-request
	resp, err := http.Get(peerURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// --- Fixed-host URL via fmt.Sprintf (should NOT fire) ---
// Models the false-positive shape from AuthGraph's own code:
//   url := fmt.Sprintf("https://api.github.com/repos/%s/%s/...", owner, repo)
//   http.NewRequest("POST", url, ...)
// The scheme+host is a string literal; only path segments are interpolated.
// This is not SSRF — the attacker cannot control the destination host.



func createCheckRun(owner, repo, sha string) {
	url := fmt.Sprintf("https://known-fixed-host.example/repos/%s/%s/check-runs/%s", owner, repo, sha)
	// ok: ssrf-unvalidated-url-request
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
