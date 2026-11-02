# Layer 3 — Advisor / risk graph: plan (written before code)

Status: PLAN ONLY, nothing built. Authoritative spec: docs/Architecture.md §3 Layer 3, §10
(Weeks 6-8), §11 (minimum viable fallback: Layer 3 as a thin 2-signal stub). Context:
docs/layer2-plan.md (what `risk_context` does today: nothing).

## Purpose
Read the infrastructure-as-code in a PR, build a small graph of what is exposed to what,
report risky changes, and draw a data-flow diagram. Explicitly NOT a general IaC scanner
(no Checkov/tfsec breadth). Terraform / AWS only for v1.

## Grounding: what the real input looks like
Studied github.com/cOmrade3267/terraform-aws-dev-lab (public, ~530 lines of .tf; read only,
never run: no `terraform init/plan`, no provisioners, no scripts). Facts that shape the design:

| Construct in the repo | Where | Implication |
|---|---|---|
| SG ingress SSH from `var.my_ip` (validated /32), plus ingress from the VPC CIDR | main.tf | A variable reference is not a literal. Resolve what we can, treat the rest as UNKNOWN, never as public. |
| SG **egress** `0.0.0.0/0` all protocols | main.tf | Must NOT trigger "public ingress" (false-positive trap). |
| Default route `0.0.0.0/0` to an internet gateway | modules/network | A route is not an SG rule. "Internet-facing" needs route + public IP + SG together. |
| Instance in the public subnet (`map_public_ip_on_launch = true`) | main.tf, module | Public subnet alone does not mean reachable: the SG here only admits one /32. |
| Resources and outputs cross a local module boundary (`module.dev_network.vpc_id`) | main.tf, modules/network | Parser must follow `./modules/...` calls. Remote module sources: unresolved, flagged, never fetched. |
| IAM policies written two ways: `jsonencode({...})` and `data "aws_iam_policy_document"` | iam.tf, oidc.tf | Support both. `jsonencode` bodies contain unresolvable refs (bucket ARNs): evaluate statically, refs become UNKNOWN. |
| `Action = ["ec2:*", "s3:*"]`, `Resource = "*"` on the CI role | oidc.tf | A genuine wildcard-IAM signal. |
| `iam:PassRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy` on `Resource = "*"` | oidc.tf | Privilege-escalation combination (can grant itself more). Stronger than a bare wildcard. |
| `ec2:DescribeVpcs` on `Resource = "*"` | iam.tf | Read-only action: must NOT be flagged (false-positive trap). |
| OIDC trust limited to one repo and branch via a `sub` condition | oidc.tf | A condition narrows trust; record it as a mitigating fact, do not ignore it. |
| S3 public-access-block all true, encryption, versioning | s3.tf | Negative control: no public-bucket finding. |
| Resource block inside `/* ... */` | main.tf | Comments must not produce resources (a real HCL parser handles this). |
| `provisioner "local-exec"`, `file(pathexpand("~/.ssh/..."))` | main.tf | The loader must NEVER evaluate functions like `file()` or run provisioners. See Safety. |

Ground truth for the first fixtures (from reading the repo): public ingress = none;
wildcard IAM = oidc.tf (ec2:*, s3:*); privilege-escalation combination = oidc.tf; internet-
facing instance = no (public subnet, but SG not open); public bucket = no.

## Scope of this phase (recommended)
A thin, honest advisor, advisory only:
1. **Public ingress:** an SG ingress rule (inline `ingress {}` or `aws_vpc_security_group_ingress_rule`)
   with `0.0.0.0/0` or `::/0`. Egress never counts.
2. **Wildcard IAM:** an Allow statement with `Action` containing `*` or `svc:*`, or the
   privilege-escalation combination (PassRole / Put/AttachRolePolicy / CreateRole family on `*`).
   Read-only actions on `*` do not count.
3. **One traversal signal:** `internet_facing` for an instance = public subnet (public IP + route
   to an IGW) AND a SG with public ingress. Plus a Mermaid data-flow diagram from the same graph.

Advisory means: shown in the PR comment, NO effect on the Check Run or policy decision in this
phase. Reason: promoting a new signal to blocking needs validation on real repos first
(architecture §9), and the demo must not gain a new way to fail.

## Design
- Package `internal/advisor`: `Load(dir)` -> resources and edges; `Signals(graph)`; `Mermaid(graph)`.
- Parser: `github.com/hashicorp/hcl/v2` (the reference HCL implementation; the spec names it).
  New dependency, justified: hand-rolled HCL parsing would be wrong on comments, heredocs, nested
  blocks and expressions. It pulls in `go-cty` and a few transitive modules.
- Graph: nodes = resources, edges = references (`aws_instance` -> subnet, SG, instance profile ->
  role -> policies -> bucket), following local modules.
- Output: an `advisor.Result` (signals, internet-facing facts, Mermaid text), rendered by the
  existing Layer 5 renderer as one extra section. The Output Contract and `finding_id` scheme are
  not changed in this phase.

## Safety and the sandbox decision (spec §3: decide now)
HCL is parsed, never executed. Hard rules: an evaluation context with NO functions (so
`file()`, `templatefile()`, `pathexpand()` fail to unknown instead of reading the host); never run
`terraform`; never run provisioners; local modules only; cap total bytes, file count, nesting depth
and wall time; PR text is data, never instructions.

Decision for the user:
- (a) Run the advisor inside a container like the scanner (`--network none`, read-only mount).
  Keeps "untrusted PR code never touches the host" true for the whole pipeline. Cost: a second image;
  the server has no Go sources, so it needs a prebuilt static binary copied in. More deploy work.
- (b) Parse in-process and narrow the public claim to: "untrusted code *execution* is sandboxed; IaC
  is parsed, never executed, by memory-safe Go under size and time limits." Recommended for v1:
  small, and true as worded. If chosen, update the report/viva wording so it matches exactly.

## "New" vs "present" (needs a decision)
The spec says "new public ingress / new or widened IAM". The fetch step only downloads the PR head,
so v1 can only say what is PRESENT at head. A true diff needs a second download of the base commit
and a graph diff. Recommended: report presence for v1, label it so, and add the base diff later.

## Where it hooks in
`cmd/scan --iac` first (local, testable), then cmd/server after the existing scan, rendered in the
comment. Separate from the Layer 1 findings; no change to `scanner/` or the rules.

Cross-signal reality check: `risk_context` (internet_facing, source) exists to annotate Layer 1 Go
findings, but no repo today contains both a Go service and its Terraform, so there is no real input
for that link yet. v1 therefore stands alone as an IaC advisory on Terraform PRs. Even once linked,
the effect on blocking is nil with the current table: a severity bump changes block only for
`likely`/`confirmed` findings, and only CWE-78 reaches `likely`. Layer 3's value now is the advisory
and the diagram, not gating (Layer 4 is what unlocks blocking for CWE-862).

## Testing
- Fixtures taken from the real constructs above (minimal copies under `testdata/terraform/`; the
  existing Go fixtures and the 3 scan baseline ids must not change).
- Positive: open ingress `0.0.0.0/0`; `Action ec2:*`; PassRole+PutRolePolicy on `*`.
- Negative (equally required, per Methodology Stage 4): egress `0.0.0.0/0`; `var.my_ip` ingress;
  `ec2:DescribeVpcs` on `*`; public-access-block all true; commented-out resource; remote module.
- Safety tests: a `file("/etc/passwd")` expression is not evaluated; oversized or deeply nested input
  is rejected within limits; no function in the eval context.
- Descriptive table-driven names; gate after every change (AGENTS.md).

## Milestones (small commits)
0 fixtures + expected results; 1 loader (restricted eval, local modules, limits); 2 graph;
3 signals (public ingress, wildcard IAM, privilege-escalation combination); 4 internet-facing
traversal; 5 Mermaid; 6 `cmd/scan --iac`; 7 render in the comment; 8 (later) server wiring, policy modifier.

## Rule references
Every signal needs a real public reference (same rule as Layer 1). None are chosen yet: candidates
(AWS IAM best-practices guidance, CIS AWS Foundations controls for open SSH and wildcard IAM, public
policy docs for the matching Checkov checks) must each be opened and read before being cited
(Methodology Stage 2). No URL is quoted here because none has been verified.

## Out of scope
Other clouds or IaC tools (CloudFormation, Pulumi); `terraform plan` JSON; remote modules;
cross-account reasoning; blocking on advisor signals; the base-commit diff; linking to Go findings;
severity feed into the Layer 2 table.

## Open decisions (need the user's call before milestone 0)
1. Sandbox: (a) container or (b) in-process with a narrowed claim (recommended).
2. Presence at head (recommended) vs base diff.
3. Advisory-only for v1 (recommended) vs the signals affecting the Check Run.
4. Demo target: install the AuthGraph App on terraform-aws-dev-lab (needs the owner to grant access;
   the repo has no live infrastructure, so there is nothing real to expose) vs fixtures only.
5. New dependency hashicorp/hcl/v2 acceptable.
