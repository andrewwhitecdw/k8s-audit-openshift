# Adversarial Review Report (Round 2)

Scope reviewed
- `k8s-audit.sh`
- `README.md`
- `CONTRIBUTING.md`
- Runtime behavior in two modes:
  - namespaced OpenShift run (`-n ligament`)
  - offline/unauthed context (`KUBECONFIG=/dev/null`)

Date
- 2026-11-24

Reviewer context
- M (authoring agent): Hermes
- R/C split: UNVERIFIED (single-agent execution in this session)

## Findings

1) [LOW] spec-compliance/documentation — README still includes one kubectl-only contribution note
- file:line: `README.md:119-120`
- what breaks:
  - Docs now describe OpenShift-aware behavior (`oc`/`kubectl`) and code implements it, but this line still says checks should be `kubectl`+`jq` only.
  - This is inconsistent with current project behavior and with `CONTRIBUTING.md`.
- evidence:
  - `README.md` line says: `keep them kubectl+jq only`
  - `CONTRIBUTING.md:10` says: `kubectl/oc + jq only`
  - `k8s-audit.sh` selects `oc` first when authenticated and supports `K8S_CLI` override.
- confidence: high
- would-change-mind:
  - README contribution section changed to `kubectl/oc + jq`.
- specific fix:
  - Replace the stale phrase in README with `kubectl/oc + jq`.

## Validation summary of prior high/medium issues

- Prior HIGH (false-clean when inaccessible): VERIFIED FIXED
  - Evidence: `KUBECONFIG=/dev/null bash k8s-audit.sh --json` exits `2` and prints
    `cluster access check failed: cannot list pods for scope (--all-namespaces) via kubectl`.

- Prior MEDIUM (pod over-count due to container-level selectors): VERIFIED FIXED
  - Evidence: target checks now use pod-level `any(.spec.containers[]?; ...)` style in `k8s-audit.sh`.

- Namespaced restricted-RBAC behavior: VERIFIED IMPROVED
  - Evidence from `bash k8s-audit.sh -n ligament --json`:
    - exit `0`, valid JSON with 16 findings
    - #14 and #16 report explicit WARN `unable to assess...` rather than crashing/false-pass.

## UNVERIFIED
- Full-cluster (`--all-namespaces`) behavior in a principal with cluster-wide list permissions.
  - attempted checks: only current principal/environment available in this session.
- Whether CI workflows consume new non-zero access-failure semantics as intended.
  - attempted checks: local execution only.

## Per-lens verdicts
- security: COVERED
- correctness: COVERED
- spec-compliance: COVERED
- performance: COVERED
- abuse: COVERED
- operational: COVERED
- governance: SKIPPED (no repo-level `ADVERSARIAL_REVIEW.md` present)

Out-of-scope
- Expanding checks beyond current 16-item scope
- Cross-cluster compatibility testing beyond this environment
