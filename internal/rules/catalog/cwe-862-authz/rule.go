package authz_test

// =============================================================
// Combined Semgrep test file for authz-missing-ownership-check
// Contains all positive (ruleid:) and negative (ok:) test cases.
// Semgrep --test matches this file to rule.yaml by basename.
// =============================================================

import "context"

// --- Fixture 1: Vulnerable (RemoveDependency shape, CVE-2026-58438) ---
// Fetch cross-repo issue by global ID, then delete — NO permission check.
// This is the exact shape from Gitea's RemoveDependency before the fix.

type Issue struct {
	ID     int64
	RepoID int64
	IsPull bool
}

func GetIssueByID(ctx context.Context, id int64) (*Issue, error) {
	return nil, nil // stub
}

func RemoveIssueDependency(ctx context.Context, issue, dep *Issue) error {
	return nil // stub
}

func removeDependency(ctx context.Context, issue *Issue, depID int64) {
	// ruleid: authz-missing-ownership-check
	dep, err := GetIssueByID(ctx, depID)
	if err != nil {
		return
	}
	RemoveIssueDependency(ctx, issue, dep)
}

// --- Fixture 2: Safe (AddDependency shape — permission check before mutate) ---
// Same fetch-by-ID + mutate structure, but with GetDoerRepoPermission
// called between fetch and mutate — this is the fixed/safe version.

func GetDoerRepoPermission(ctx context.Context, repoID int64) (bool, error) {
	return true, nil // stub
}

func UpdateIssueDependency(ctx context.Context, issue, dep *Issue) error {
	return nil // stub
}

func updateDependencySafe(ctx context.Context, issue *Issue, depID int64) {
	// ok: authz-missing-ownership-check
	dep, err := GetIssueByID(ctx, depID)
	if err != nil {
		return
	}
	allowed, err := GetDoerRepoPermission(ctx, dep.RepoID)
	if err != nil || !allowed {
		return
	}
	UpdateIssueDependency(ctx, issue, dep)
}

// --- Fixture 3: Hardcoded constant key (not user-reachable) ---
// The lookup key is a string literal — not user-controllable.
// Excluded by the pattern-not matching string-literal arguments.
// Note: numeric-literal IDs cannot be generically excluded in
// Semgrep OSS (no "any integer literal" matcher) — stated limitation.

type Config struct {
	Name string
}

func GetConfigByName(ctx context.Context, name string) (*Config, error) {
	return nil, nil // stub
}

func DeleteConfig(ctx context.Context, cfg *Config) error {
	return nil // stub
}

func cleanupDefaultConfig(ctx context.Context) {
	// ok: authz-missing-ownership-check
	cfg, err := GetConfigByName(ctx, "system-default")
	if err != nil {
		return
	}
	DeleteConfig(ctx, cfg)
}

// --- Fixture 4: Generalization test — different function names ---
// Confirms the rule isn't hardcoded to Gitea-specific names.
// FetchUserByID matches the fetch regex, DestroyAccount matches the
// mutate regex. Same discipline as the checkOutboundURL test in CWE-918.

type User struct {
	ID   int64
	Name string
}

func FetchUserByID(ctx context.Context, id int64) (*User, error) {
	return nil, nil // stub
}

func DestroyAccount(ctx context.Context, user *User) error {
	return nil // stub
}

func deleteUserAccount(ctx context.Context, userID int64) {
	// ruleid: authz-missing-ownership-check
	user, err := FetchUserByID(ctx, userID)
	if err != nil {
		return
	}
	DestroyAccount(ctx, user)
}
