#!/usr/bin/env bash
#
# k8s-audit — a fast, dependency-light Kubernetes security audit.
#
# Runs a set of high-signal security checks against your current cluster using
# only kubectl/oc + jq, grouped by the 9 domains of the k8s-security.pro 50-point
# checklist. If kube-bench / Trivy / kubescape are installed, it points you to
# them for deeper CIS/NSA coverage.
#
# Nothing is sent anywhere. Read-only: it never mutates your cluster.
#
#   Usage:  ./k8s-audit.sh [-n NAMESPACE] [--json] [--html [FILE]]
#
#   --html [FILE]  also write a single-file HTML report you can share
#                  (default: k8s-audit-report.html). Safe to attach to a
#                  PR, Slack thread or audit evidence folder.
#
# Full 50-point checklist, remediation YAML, Helm & Kustomize:
#   https://k8s-security.pro
#
# MIT License — (c) k8s-security.pro
set -euo pipefail

NS_FILTER=""          # empty = all namespaces
JSON=false
HTML_OUT=""           # empty = no HTML report
PASS=0; WARN=0; FAIL=0
declare -a FINDINGS    # "SEVERITY|DOMAIN|CHECK|DETAIL"
K8S_CLI="${K8S_CLI:-}"
KCTL_BIN=""
IS_OPENSHIFT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NS_FILTER="$2"; shift 2 ;;
    --json) JSON=true; shift ;;
    --html)
      if [[ $# -gt 1 && "$2" != -* ]]; then HTML_OUT="$2"; shift 2
      else HTML_OUT="k8s-audit-report.html"; shift; fi ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v jq >/dev/null || { echo "jq not found (brew install jq)" >&2; exit 1; }

if [[ -n "$K8S_CLI" ]]; then
  command -v "$K8S_CLI" >/dev/null || { echo "$K8S_CLI not found" >&2; exit 1; }
  KCTL_BIN="$K8S_CLI"
elif command -v oc >/dev/null 2>&1 && oc whoami >/dev/null 2>&1; then
  KCTL_BIN="oc"
elif command -v kubectl >/dev/null 2>&1; then
  KCTL_BIN="kubectl"
elif command -v oc >/dev/null 2>&1; then
  KCTL_BIN="oc"
else
  echo "kubectl or oc not found" >&2
  exit 1
fi

kctl() { "$KCTL_BIN" "$@"; }
fail_access() {
  echo "cluster access check failed: $1" >&2
  exit 2
}

if [[ "$KCTL_BIN" == "oc" ]]; then
  if kctl whoami >/dev/null 2>&1; then
    IS_OPENSHIFT=true
  elif command -v kubectl >/dev/null 2>&1; then
    KCTL_BIN="kubectl"
  fi
fi

if [[ -n "$NS_FILTER" ]]; then NS_ARGS=(-n "$NS_FILTER"); else NS_ARGS=(--all-namespaces); fi

if [[ -n "$NS_FILTER" ]]; then
  kctl get ns "$NS_FILTER" >/dev/null 2>&1 || fail_access "namespace '$NS_FILTER' not found or not readable"
fi

# pull all pods once (hard-fail if cluster is unreachable or unauthorized)
if PODS_JSON="$(kctl get pods "${NS_ARGS[@]}" -o json 2>/dev/null)"; then
  :
else
  fail_access "cannot list pods for scope (${NS_ARGS[*]}) via $KCTL_BIN"
fi

# note: `((X++))` returns exit 1 when X is 0, which aborts under `set -e`; use assignment form
record() { FINDINGS+=("$1|$2|$3|$4"); case "$1" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac; }

# helper: count pods matching a jq filter over .items[]
count_pods() { echo "$PODS_JSON" | jq "[.items[] | select($1)] | length"; }
list_pods()  { echo "$PODS_JSON" | jq -r "[.items[] | select($1) | .metadata.namespace + \"/\" + .metadata.name] | .[0:8] | .[]"; }
normalize_count() {
  local raw="$1"
  raw="${raw//$'\r'/}"
  raw="${raw%%$'\n'*}"
  [[ "$raw" =~ ^[0-9]+$ ]] || raw=0
  printf '%s' "$raw"
}

check_pods() { # severity domain "#N check" jq_filter
  local sev="$1" dom="$2" name="$3" filt="$4"
  local c; c="$(count_pods "$filt")"
  c="$(normalize_count "$c")"
  if [[ "$c" == "0" ]]; then record PASS "$dom" "$name" "no matching workloads"
  else
    local more=""; [[ "$c" -gt 8 ]] && more=", +$((c-8)) more"
    record "$sev" "$dom" "$name" "$c workload(s): $(list_pods "$filt" | paste -sd, -)$more"
  fi
}

# ── Pod Security (checklist domain I) ─────────────────────────────────────────
check_pods FAIL "Pod Security" "#2 Privileged containers" \
  'any(.spec.containers[]?; (.securityContext.privileged // false) == true)'
check_pods FAIL "Pod Security" "#3 allowPrivilegeEscalation not disabled" \
  'any(.spec.containers[]?; (.securityContext.allowPrivilegeEscalation // true) == true)'
check_pods WARN "Pod Security" "#4 Running as root (runAsNonRoot unset)" \
  '((.spec.securityContext.runAsNonRoot // false) == false) and (all(.spec.containers[]?; (.securityContext.runAsNonRoot // false) == false))'
check_pods FAIL "Pod Security" "#5 hostNetwork / hostPID / hostIPC" \
  '(.spec.hostNetwork == true) or (.spec.hostPID == true) or (.spec.hostIPC == true)'
check_pods WARN "Pod Security" "#6 SA token auto-mounted" \
  '(.spec.automountServiceAccountToken // true) == true'
check_pods WARN "Pod Security" "#7 Capabilities not dropped (ALL)" \
  'any(.spec.containers[]?; ((.securityContext.capabilities.drop // []) | index("ALL")) == null)'
check_pods FAIL "Pod Security" "#7b Dangerous capabilities added" \
  'any(.spec.containers[]?; (.securityContext.capabilities.add // []) | any(. == "SYS_ADMIN" or . == "NET_ADMIN" or . == "NET_RAW" or . == "SYS_PTRACE" or . == "SYS_MODULE" or . == "ALL"))'
check_pods WARN "Pod Security" "#4b readOnlyRootFilesystem not set" \
  'any(.spec.containers[]?; (.securityContext.readOnlyRootFilesystem // false) != true)'
check_pods WARN "Pod Security" "#9 hostPath volumes mounted" \
  'any(.spec.volumes[]?; .hostPath != null)'
# ── Supply Chain (domain V) ───────────────────────────────────────────────────
check_pods WARN "Supply Chain" "#28 Images using :latest or untagged" \
  'any(.spec.containers[]?; (.image // "") | (test(":latest$")) or (test(":") | not))'

# ── Resource Management (domain IV) ──────────────────────────────────────────
check_pods WARN "Cluster Hardening" "#22 Containers without resource limits" \
  'any(.spec.containers[]?; (.resources.limits == null))'

# ── Cluster hygiene ──────────────────────────────────────────────────────────
if DEFAULT_PODS_RAW="$(kctl get pods -n default --no-headers 2>/dev/null)"; then
  DEFAULT_WORKLOADS="$(printf '%s' "$DEFAULT_PODS_RAW" | wc -l | tr -d ' ')"
  DEFAULT_WORKLOADS="$(normalize_count "$DEFAULT_WORKLOADS")"
  if [[ "$DEFAULT_WORKLOADS" == "0" ]]; then record PASS "Cluster Hardening" "#20 Workloads in default namespace" "default namespace is empty"
  else record WARN "Cluster Hardening" "#20 Workloads in default namespace" "$DEFAULT_WORKLOADS pod(s) in 'default'"; fi
else
  record WARN "Cluster Hardening" "#20 Workloads in default namespace" "unable to assess: cannot list pods in 'default'"
fi

# ── Network (domain II): namespaces with no NetworkPolicy ────────────────────
if [[ -n "$NS_FILTER" ]]; then
  local_np="$(kctl get netpol -n "$NS_FILTER" --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)"
  local_np="$(normalize_count "$local_np")"
  if [[ "$local_np" == "0" ]]; then
    record FAIL "Network" "#8 Namespaces without a NetworkPolicy" "no NetworkPolicy in: $NS_FILTER"
  else
    record PASS "Network" "#8 Namespaces without a NetworkPolicy" "$NS_FILTER has at least one"
  fi
else
  if NS_LIST_JSON="$(kctl get ns -o json 2>/dev/null)"; then
    NP_MISSING=""
    while read -r ns; do
      [[ -z "$ns" || "$ns" =~ ^(kube-system|kube-public|kube-node-lease|openshift|openshift-.*)$ ]] && continue
      local_np="$(kctl get netpol -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)"
      local_np="$(normalize_count "$local_np")"
      [[ "$local_np" == "0" ]] && NP_MISSING+="$ns "
    done < <(printf '%s' "$NS_LIST_JSON" | jq -r '.items[]?.metadata.name')
    if [[ -z "$NP_MISSING" ]]; then record PASS "Network" "#8 Namespaces without a NetworkPolicy" "all namespaces have at least one"
    else record FAIL "Network" "#8 Namespaces without a NetworkPolicy" "no NetworkPolicy in: ${NP_MISSING% }"; fi
  else
    record WARN "Network" "#8 Namespaces without a NetworkPolicy" "unable to assess: cannot list namespaces"
  fi
fi

# ── RBAC (domain III): cluster-admin bindings ────────────────────────────────
if CRB_JSON="$(kctl get clusterrolebindings -o json 2>/dev/null)"; then
  ADMIN_BINDINGS="$(printf '%s' "$CRB_JSON" | jq -r '[.items[]? | select(.roleRef.name=="cluster-admin") | .metadata.name] | length')"
  ADMIN_BINDINGS="$(normalize_count "$ADMIN_BINDINGS")"
  if [[ "$ADMIN_BINDINGS" -le 1 ]]; then record PASS "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS binding(s)"
  else record WARN "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS bindings grant cluster-admin — review each"; fi
else
  record WARN "RBAC" "#14 cluster-admin bindings" "unable to assess: cannot list clusterrolebindings"
fi

# ── RBAC (domain III): roles granting verbs=* on resources=* ─────────────────
if ROLES_JSON="$(kctl get clusterroles,roles --all-namespaces -o json 2>/dev/null)"; then
  WILDCARD_COUNT="$(printf '%s' "$ROLES_JSON" | jq -r '[.items[]? | select((.metadata.name // "" | startswith("system:")) | not) | select(any(.rules[]?; ((.verbs // []) | index("*")) and ((.resources // []) | index("*"))))] | length')"
  WILDCARD_COUNT="$(normalize_count "$WILDCARD_COUNT")"
  if [[ "$WILDCARD_COUNT" -eq 0 ]]; then record PASS "RBAC" "#16 Roles granting * verbs on * resources" "none (excluding built-in system: roles)"
  else
    WNAMES="$(printf '%s' "$ROLES_JSON" | jq -r '[.items[]? | select((.metadata.name // "" | startswith("system:")) | not) | select(any(.rules[]?; ((.verbs // []) | index("*")) and ((.resources // []) | index("*")))) | .metadata.name] | .[0:8] | join(", ")')"
    record WARN "RBAC" "#16 Roles granting * verbs on * resources" "$WILDCARD_COUNT role(s): $WNAMES"
  fi
else
  record WARN "RBAC" "#16 Roles granting * verbs on * resources" "unable to assess: cannot list roles/clusterroles"
fi
check_pods WARN "RBAC" "#15 Workloads using the default ServiceAccount" \
  '((.spec.serviceAccountName // "default") == "default") and ((.metadata.namespace // "") | startswith("kube-") | not)'

# ── HTML report (optional, single self-contained file) ───────────────────────
html_esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

write_html() {
  local out="$1"
  local ctx; ctx="$(kctl config current-context 2>/dev/null || echo cluster)"
  local when; when="$(date -u +'%Y-%m-%d %H:%M UTC')"
  local total=$((PASS + WARN + FAIL))
  local scope="all namespaces"; [[ -n "$NS_FILTER" ]] && scope="namespace $NS_FILTER"
  {
    cat <<EOF
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>k8s-audit report · $(printf '%s' "$ctx" | html_esc)</title>
<style>
:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,"Segoe UI",Inter,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:40px 24px}h1{font-size:26px;margin:0 0 4px}.meta{color:#8b949e;font-size:14px;margin-bottom:24px}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:28px}.tile{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px}
.tile b{display:block;font-size:30px;line-height:1}.tile span{color:#8b949e;font-size:13px;text-transform:uppercase;letter-spacing:.06em}
.pass b{color:#3fb950}.warn b{color:#d29922}.fail b{color:#f85149}
h2{font-size:15px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin:26px 0 8px}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}
td{padding:10px 14px;border-top:1px solid #21262d;vertical-align:top}tr:first-child td{border-top:0}
.sev{display:inline-block;min-width:44px;text-align:center;font-size:12px;font-weight:700;border-radius:6px;padding:2px 6px}
.sev.PASS{background:#23863620;color:#3fb950}.sev.WARN{background:#9e6a0320;color:#d29922}.sev.FAIL{background:#da363320;color:#f85149}
.chk{font-weight:600;white-space:nowrap}.det{color:#8b949e;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;word-break:break-word}
.foot{margin-top:32px;color:#8b949e;font-size:13px;border-top:1px solid #30363d;padding-top:16px}.foot a{color:#58a6ff;text-decoration:none}
@media print{body{background:#fff;color:#111}.tile,table{background:#fff;border-color:#ccc}.det,.meta,.foot,h2{color:#555}}
</style></head><body><div class="wrap">
<h1>k8s-audit report</h1>
<div class="meta">Context <b>$(printf '%s' "$ctx" | html_esc)</b> · $(printf '%s' "$scope" | html_esc) · $when · $total checks (read-only)</div>
<div class="tiles"><div class="tile pass"><b>$PASS</b><span>pass</span></div><div class="tile warn"><b>$WARN</b><span>warn</span></div><div class="tile fail"><b>$FAIL</b><span>fail</span></div></div>
EOF
    local last_dom="" f sev dom name detail
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r sev dom name detail <<<"$f"
      if [[ "$dom" != "$last_dom" ]]; then
        [[ -n "$last_dom" ]] && echo "</table>"
        echo "<h2>$(printf '%s' "$dom" | html_esc)</h2><table>"
        last_dom="$dom"
      fi
      printf '<tr><td><span class="sev %s">%s</span></td><td class="chk">%s</td><td class="det">%s</td></tr>\n' \
        "$sev" "$sev" "$(printf '%s' "$name" | html_esc)" "$(printf '%s' "$detail" | html_esc)"
    done
    [[ -n "$last_dom" ]] && echo "</table>"
    cat <<'EOF'
<div class="foot">Generated by <a href="https://github.com/k8s-security-pro/k8s-audit">k8s-audit</a>, an open-source read-only first pass. Check numbers map to the <a href="https://k8s-security.pro">k8s-security.pro 50-point checklist</a>. For full CIS coverage run kube-bench or Kubescape.</div>
</div></body></html>
EOF
  } > "$out"
}

if [[ -n "$HTML_OUT" ]]; then
  write_html "$HTML_OUT"
  $JSON || echo "  HTML report written to $HTML_OUT" >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────
if $JSON; then
  printf '{'
  printf '"pass":%d,"warn":%d,"fail":%d,"findings":[' "$PASS" "$WARN" "$FAIL"
  for i in "${!FINDINGS[@]}"; do
    IFS='|' read -r sev dom name detail <<<"${FINDINGS[$i]}"
    [[ $i -gt 0 ]] && printf ','
    printf '{"severity":"%s","domain":"%s","check":"%s","detail":%s}' \
      "$sev" "$dom" "$name" "$(jq -Rn --arg d "$detail" '$d')"
  done
  printf ']}\n'
  exit 0
fi

c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
echo
echo "  k8s-audit · $(kctl config current-context 2>/dev/null || echo cluster)"
echo "  ${c_dim}high-signal checks mapped to the k8s-security.pro 50-point checklist${c_rst}"
if $IS_OPENSHIFT; then
  echo "  ${c_dim}OpenShift mode detected (using oc; skipping openshift-* namespaces in #8)${c_rst}"
fi
echo
last_dom=""
for f in "${FINDINGS[@]}"; do
  IFS='|' read -r sev dom name detail <<<"$f"
  [[ "$dom" != "$last_dom" ]] && { echo "  ── $dom"; last_dom="$dom"; }
  case "$sev" in
    PASS) icon="${c_grn}✓${c_rst}";;
    WARN) icon="${c_yel}![${c_rst}";;
    FAIL) icon="${c_red}✗${c_rst}";;
  esac
  printf "     %s %-42s %s%s%s\n" "$icon" "$name" "$c_dim" "$detail" "$c_rst"
done
echo
echo "  ${c_grn}${PASS} pass${c_rst}   ${c_yel}${WARN} warn${c_rst}   ${c_red}${FAIL} fail${c_rst}"
echo
echo "  ${c_dim}This covers ~16 of 50 checks. For the full 50-point audit, remediation${c_rst}"
echo "  ${c_dim}YAML, Helm charts, Kustomize overlays and CIS/SOC2 mappings:${c_rst}"
echo "  → https://k8s-security.pro"
echo
if command -v kubescape >/dev/null 2>&1 || command -v trivy >/dev/null 2>&1 || command -v kube-bench >/dev/null 2>&1; then
  echo "  ${c_dim}Deeper CIS/NSA scans (detected on PATH):${c_rst}"
  command -v kubescape >/dev/null 2>&1 && echo "     kubescape scan framework nsa"
  command -v trivy     >/dev/null 2>&1 && echo "     trivy k8s --report summary cluster"
  command -v kube-bench>/dev/null 2>&1 && echo "     kube-bench run --targets master,node"
  echo
fi
[[ "$FAIL" -gt 0 ]] && exit 1 || exit 0
