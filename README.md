# k8s-audit

**A fast, dependency-light Kubernetes security audit you can run in one command.**

`k8s-audit` runs a set of high-signal security checks against your current cluster
using `oc` or `kubectl` + `jq` (in that order), and prints a clean report grouped by security domain —
privileged containers, missing NetworkPolicies, over-broad RBAC, `:latest` images,
missing resource limits, and more.

It's read-only, sends nothing anywhere, and needs no install beyond a shell.

![k8s-audit sample output — a colored terminal report grouped by security domain](demo.svg)

## Why this exists

Everything in Kubernetes security is technically "free" — CIS Benchmark, kube-bench,
Kubescape, Trivy. But those tools flag *hundreds* of items and leave you to figure out
which ones matter and how to fix them. `k8s-audit` is the opinionated 30-second first
pass: ~16 checks that catch the most common real-world exposures, each mapped to
a specific item in the [k8s-security.pro 50-point checklist](https://k8s-security.pro).

It's built and maintained by the team behind **[k8s-security.pro](https://k8s-security.pro)** —
a production hardening kit (50-point audit, 25 YAML templates, Helm chart, Kustomize
overlays, CIS & SOC2 mappings). This repo is the free, open-source front door to it.

## Install

No install required — just clone and run:

```bash
git clone https://github.com/k8s-security-pro/k8s-audit.git
cd k8s-audit
./k8s-audit.sh
```

Requirements: `jq` plus one cluster client (`oc` preferred when authenticated, otherwise `kubectl`) pointed at your cluster.
You can force the client with `K8S_CLI=<binary>`.

If cluster access is unavailable (bad context/auth/network), `k8s-audit` exits non-zero instead of reporting a false clean pass.
On OpenShift (`oc` selected and authenticated), check #8 treats `openshift` and `openshift-*` as platform namespaces and skips them.

## Usage

```bash
./k8s-audit.sh                 # audit all namespaces
./k8s-audit.sh -n payments     # a single namespace
./k8s-audit.sh --json          # machine-readable output (for CI / dashboards)
./k8s-audit.sh --html          # also write k8s-audit-report.html (shareable, single file)
./k8s-audit.sh --html audit-2026-09.html   # pick the file name
./k8s-audit.sh --csv           # write k8s-audit-report.csv
./k8s-audit.sh --sarif         # write k8s-audit-report.sarif (code scanning)
./k8s-audit.sh --baseline-out baseline.json
./k8s-audit.sh --baseline-in baseline.json --drift-only --json
./k8s-audit.sh --include-ns '^prod-' --exclude-ns 'prod-sandbox'
./k8s-audit.sh --fail-on 2,3,5,7b,8
./k8s-audit.sh --check-pack core,openshift
./k8s-audit.sh --github-annotations
./k8s-audit.sh --evidence-dir audit-evidence
```

Additional options

- `--profile strict|balanced|legacy` choose policy profile metadata in output.
- `--check-pack core,openshift` enables optional OpenShift checks (SCC grants, Route TLS posture, NetworkPolicy quality, legacy SA token mounts, escalation-chain detection).
- `--include-ns` / `--exclude-ns` filter namespace-scoped checks by regex.
- `--fail-on` controls CI gate by check IDs instead of all FAIL findings.
  - Default is `AUTO` (`2,3,5,7b,8,OS_ESC_CHAIN`); use `ALL` to fail on any FAIL severity.
- `--csv`, `--sarif` produce shareable/exportable machine formats.
- `--baseline-in` + `--drift-only` show only new findings versus baseline.
- `--baseline-out` writes a reusable baseline snapshot.
- `--github-annotations` emits GitHub Actions annotations for findings.
- `--evidence-dir` writes raw evidence payloads used by checks.

Exit code is non-zero when a check in the fail gate trips. Default gate is `AUTO`
(`2,3,5,7b,8,OS_ESC_CHAIN`); use `--fail-on ALL` to fail on any FAIL-severity check, or
`--fail-on 2,3,7b` to choose your own — so you can gate CI on what matters to you.

### Shareable HTML report

`--html` writes a self-contained dark-theme report (no external assets, prints cleanly)
with the pass/warn/fail summary and every finding grouped by domain. Attach it to a PR,
drop it in a Slack thread, or keep it in your audit evidence folder. It works together
with `--json`, so one run can feed both a dashboard and a human.

## Use it in CI

Drop this into `.github/workflows/k8s-security-audit.yml` to gate a PR (full example in
[`.github/workflows/`](.github/workflows/k8s-security-audit.yml)):

```yaml
- name: Kubernetes security audit
  run: |
    curl -sSL https://raw.githubusercontent.com/k8s-security-pro/k8s-audit/main/k8s-audit.sh -o k8s-audit.sh
    chmod +x k8s-audit.sh
    ./k8s-audit.sh --check-pack core,openshift --json --csv --sarif --github-annotations
  continue-on-error: false
```

- Upload `k8s-audit-report.json/.csv/.sarif` as workflow artifacts for dashboards and code scanning.
- Point `--fail-on` at the check IDs you own as a team; tighten it as the cluster hardens.
- Use `--baseline-in` + `--drift-only` against a committed baseline to rotate the gate from
  "no new findings" to "no new findings of these kinds" without a full green pass requirement.

## Recommended OpenShift usage

For a tenant namespace on OpenShift, enable the OpenShift pack with the gating policy and
machine-readable outputs in one run:

```bash
./k8s-audit.sh -n payments \
  --check-pack core,openshift \
  --profile strict \
  --fail-on AUTO \
  --json --csv --sarif \
  --github-annotations
```

Baseline + drift workflow (fail only on new regressions vs a known-good snapshot):

```bash
# 1. capture a known-good baseline
./k8s-audit.sh -n payments --check-pack core,openshift --baseline-out baseline-payments.json

# 2. later runs: surface only findings not present in the baseline
./k8s-audit.sh -n payments --check-pack core,openshift \
  --baseline-in baseline-payments.json --drift-only --json
```

Tighten the gate once the cluster is stable, for example `--fail-on 2,3,5,7b,8,OS_ESC_CHAIN,14,16`.

## What it checks (16 of 50)

| # | Domain | Check |
|---|--------|-------|
| 2 | Pod Security | Privileged containers |
| 3 | Pod Security | `allowPrivilegeEscalation` not disabled |
| 4 | Pod Security | Running as root (`runAsNonRoot` unset) |
| 4b | Pod Security | `readOnlyRootFilesystem` not set |
| 5 | Pod Security | `hostNetwork` / `hostPID` / `hostIPC` |
| 6 | Pod Security | ServiceAccount token auto-mounted |
| 7 | Pod Security | Capabilities not dropped (`ALL`) |
| 7b | Pod Security | Dangerous capabilities added (`SYS_ADMIN`, `NET_ADMIN`, …) |
| 9 | Pod Security | `hostPath` volumes mounted |
| 8 | Network | Namespaces without a NetworkPolicy (no default-deny) |
| 14 | RBAC | `cluster-admin` bindings |
| 15 | RBAC | Workloads using the `default` ServiceAccount |
| 16 | RBAC | Roles granting `*` verbs on `*` resources |
| 20 | Cluster Hardening | Workloads in the `default` namespace |
| 22 | Cluster Hardening | Containers without resource limits |
| 28 | Supply Chain | Images using `:latest` or untagged |

OpenShift pack (adds 5 checks with `--check-pack core,openshift` on an `oc` cluster)

| # | Domain | Check |
|---|--------|-------|
| OS-SCC | OpenShift Security | Privileged/`anyuid` SCC grant patterns |
| OS-Route | OpenShift Security | Routes without TLS or with insecure `Allow` policy |
| OS-NetPol | OpenShift Security | Namespaces lacking a default-deny-style NetworkPolicy |
| OS-SAToken | OpenShift Security | Workloads mounting token-like secrets (legacy SA tokens) |
| OS-EscChain | OpenShift Security | Privileged + hostPath + default ServiceAccount chains |

## Use it with Claude

The [k8s-security-audit skill](https://github.com/k8s-security-pro/k8s-audit-skill)
runs this script plus extra RBAC, secrets and exposure checks from Claude Code,
then writes a prioritized fix plan with YAML, mapped to CIS, SOC 2 and ISO 27001:

```
/plugin marketplace add k8s-security-pro/k8s-audit-skill
/plugin install k8s-security-audit@k8s-security-pro
```

## Going deeper

`k8s-audit` deliberately stops at the high-signal dozen. For the complete picture:

- **The full 50-point audit + copy-paste remediation YAML, Helm chart, Kustomize
  overlays, and CIS/SOC2 compliance mappings → [k8s-security.pro](https://k8s-security.pro)**
- Deeper CIS/NSA scanning → [kube-bench](https://github.com/aquasecurity/kube-bench),
  [Kubescape](https://github.com/kubescape/kubescape), [Trivy](https://github.com/aquasecurity/trivy)
  (if these are on your `PATH`, `k8s-audit` points you at the right command).

## Contributing

Issues and PRs welcome — especially new high-signal checks (keep them `kubectl/oc`+`jq`
only, read-only, and mapped to a checklist domain). New to the project? Look for the
[`good first issue`](https://github.com/k8s-security-pro/k8s-audit/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
label — each one is a small, self-contained check with the jq filter sketched out for you.
See [CONTRIBUTING.md](CONTRIBUTING.md) for how a check is structured.

## License

MIT © [k8s-security.pro](https://k8s-security.pro)
