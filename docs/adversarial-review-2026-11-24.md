# Adversarial Review Report

Scope reviewed
- `k8s-audit.sh` (OpenShift refactor behavior and failure modes)
- `README.md` and `CONTRIBUTING.md` (declared purpose/contract vs implementation)

Date
- 2026-11-24

Reviewer context
- M (authoring agent): Hermes
- R/C model split: UNVERIFIED (single-agent run in this session)

## Findings

1) [HIGH] operational/correctness — false-clean report when cluster is unreachable
- file:line: `k8s-audit.sh:70-74`, `k8s-audit.sh:129-160`
- what breaks:
  - If API access fails (bad kubeconfig, auth failure, disconnected context), the script silently falls back to empty datasets and emits mostly/entirely PASS findings.
  - This can produce a misleading "clean" security signal for OpenShift/Kubernetes clusters that were never actually audited.
- evidence:
  - Command run:
    - `KUBECONFIG=/dev/null bash k8s-audit.sh --json`
  - Observed output (captured in this review):
    - exit code `0`
    - counts `16 pass, 0 warn, 0 fail`
    - `#14 cluster-admin bindings` reported `0 binding(s)`
    - stderr had `0` lines
- confidence: high
- would-change-mind:
  - Script emits a hard FAIL/non-zero on API/auth/context failure, or includes an explicit "data source unavailable" finding that prevents clean status.
- specific fix:
  - Add an upfront connectivity preflight (for selected client):
    - `kctl version --request-timeout=...` and/or `kctl auth can-i get pods --all-namespaces`
    - for `oc`, verify `oc whoami` and `oc project`.
  - If preflight fails, exit non-zero and record a top-level failure like `#0 Cluster access unavailable`.

2) [MEDIUM] correctness — several pod checks can over-count a single pod with multiple matching containers
- file:line: `k8s-audit.sh:105`, `k8s-audit.sh:113`, `k8s-audit.sh:126`
- what breaks:
  - Filters using `.spec.containers[]? | <cond>` inside `select(...)` can emit multiple truthy results per pod, causing duplicate pod entries and inflated finding counts.
  - This distorts severity triage and remediation prioritization.
- evidence:
  - Reproduction using jq against one pod with two matching containers:
    - current pattern result: `current ["p","p"]`
    - safe pattern result: `safe ["p"]`
  - Repro command executed in this review (Python+jq harness).
- confidence: high
- would-change-mind:
  - Filters switched to pod-level existential form (`any(.spec.containers[]?; <cond>)`) and sample repro no longer duplicates.
- specific fix:
  - Rewrite affected checks to pod-level `any(...)` form, e.g.:
    - `any(.spec.containers[]?; (.securityContext.allowPrivilegeEscalation // true) == true)`
    - `any(.spec.containers[]?; ((.securityContext.capabilities.drop // []) | index("ALL")) == null)`
    - `any(.spec.containers[]?; (.resources.limits == null))`

3) [LOW] spec-compliance/documentation — README contract still claims kubectl-only
- file:line: `README.md:6`, `README.md:36`
- what breaks:
  - Repo now supports OpenShift-aware execution with `oc` preference and `K8S_CLI` override in implementation, but docs still present kubectl-only runtime requirements.
  - Operators may misconfigure expectations for OpenShift clusters.
- evidence:
  - `k8s-audit.sh` contains `oc` preference and OpenShift-specific namespace behavior (`k8s-audit.sh:47-65`, `k8s-audit.sh:137`, `k8s-audit.sh:239-240`).
  - README currently states "using only `kubectl` + `jq`" and requirements list only `kubectl`.
- confidence: high
- would-change-mind:
  - README/usage explicitly documents `oc` detection order and OpenShift namespace handling.
- specific fix:
  - Update README intro/requirements/usage notes to:
    - `K8S_CLI` override -> `oc` -> `kubectl`
    - OpenShift mode skips `openshift-*` namespaces in check #8.

## UNVERIFIED
- Whether CI gates run against a real cluster context (vs offline/no-auth) before publishing clean reports.
  - attempted checks: repository scan for CI workflow and script behavior; no live CI run artifacts in this session.
- Whether there is an intended policy to treat control-plane/system namespaces as in-scope for OpenShift tenant audits.
  - attempted checks: reviewed script and docs only.

## Per-lens verdicts
- security: COVERED (read pod security/RBAC checks and data-path handling; no direct code execution risk found in reviewed paths)
- correctness: COVERED (validated counting semantics and parsing behavior with local reproductions)
- spec-compliance: COVERED (compared README/CONTRIBUTING contract with script behavior)
- performance: COVERED (no critical performance regressions found; script remains single-pass for pods, but repeats some RBAC queries)
- abuse: COVERED (identified abuse path: offline/unauthed context yields deceptive clean report)
- operational: COVERED (validated failure-mode behavior under bad kubeconfig)
- governance: SKIPPED (no repo `ADVERSARIAL_REVIEW.md` protocol file present; no commit-signoff policy assessment performed)

Out-of-scope
- Full CIS/NSA benchmark coverage beyond this script’s 16 checks
- Live remediation validation on a real OpenShift cluster
- Any files outside `k8s-audit.sh`, `README.md`, and `CONTRIBUTING.md`
