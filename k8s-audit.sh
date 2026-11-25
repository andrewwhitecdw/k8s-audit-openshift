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
INCLUDE_NS_RE=""
EXCLUDE_NS_RE=""
JSON=false
HTML_OUT=""           # empty = no HTML report
CSV_OUT=""
SARIF_OUT=""
BASELINE_IN=""
BASELINE_OUT=""
DRIFT_ONLY=false
FAIL_ON="AUTO"
PROFILE="balanced"
CHECK_PACKS="core,openshift"
GITHUB_ANNOTATIONS=false
EVIDENCE_DIR=""
SHOW_PREFLIGHT=true
PASS=0; WARN=0; FAIL=0
declare -a FINDINGS    # "SEVERITY|DOMAIN|CHECK|DETAIL|ID|FINGERPRINT"
K8S_CLI="${K8S_CLI:-}"
KCTL_BIN=""
IS_OPENSHIFT=false
WHOAMI=""
PROJECT=""
SERVER_URL=""
CAN_LIST_SCOPE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NS_FILTER="$2"; shift 2 ;;
    --include-ns) INCLUDE_NS_RE="$2"; shift 2 ;;
    --exclude-ns) EXCLUDE_NS_RE="$2"; shift 2 ;;
    --json) JSON=true; shift ;;
    --html)
      if [[ $# -gt 1 && "$2" != -* ]]; then HTML_OUT="$2"; shift 2
      else HTML_OUT="k8s-audit-report.html"; shift; fi ;;
    --csv)
      if [[ $# -gt 1 && "$2" != -* ]]; then CSV_OUT="$2"; shift 2
      else CSV_OUT="k8s-audit-report.csv"; shift; fi ;;
    --sarif)
      if [[ $# -gt 1 && "$2" != -* ]]; then SARIF_OUT="$2"; shift 2
      else SARIF_OUT="k8s-audit-report.sarif"; shift; fi ;;
    --baseline-in) BASELINE_IN="$2"; shift 2 ;;
    --baseline-out) BASELINE_OUT="$2"; shift 2 ;;
    --drift-only) DRIFT_ONLY=true; shift ;;
    --fail-on) FAIL_ON="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --check-pack) CHECK_PACKS="$2"; shift 2 ;;
    --github-annotations) GITHUB_ANNOTATIONS=true; shift ;;
    --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
    --no-preflight) SHOW_PREFLIGHT=false; shift ;;
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

scope_ns_match() {
  local ns="$1"
  [[ -n "$INCLUDE_NS_RE" && ! "$ns" =~ $INCLUDE_NS_RE ]] && return 1
  [[ -n "$EXCLUDE_NS_RE" && "$ns" =~ $EXCLUDE_NS_RE ]] && return 1
  return 0
}

pack_enabled() {
  local p="$1"
  [[ ",$CHECK_PACKS," == *",$p,"* ]]
}

emit_evidence() {
  local name="$1" body="$2"
  [[ -z "$EVIDENCE_DIR" ]] && return 0
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\n' "$body" > "$EVIDENCE_DIR/$name"
}

hash_text() {
  local t="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$t" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$t" | cksum | awk '{print $1}'
  fi
}

normalize_count() {
  local raw="$1"
  raw="${raw//$'\r'/}"
  raw="${raw%%$'\n'*}"
  [[ "$raw" =~ ^[0-9]+$ ]] || raw=0
  printf '%s' "$raw"
}

remediation_for() {
  case "$1" in
    2) echo "Set securityContext.privileged=false and drop unnecessary host-level access." ;;
    3) echo "Set allowPrivilegeEscalation=false on every container." ;;
    5) echo "Disable hostNetwork/hostPID/hostIPC unless strictly required." ;;
    7|7b) echo "Drop ALL capabilities; only add explicitly required capabilities." ;;
    8) echo "Apply namespace default-deny NetworkPolicy and allow-list traffic." ;;
    14|16) echo "Reduce wildcard RBAC and cluster-admin bindings; scope roles minimally." ;;
    20) echo "Move workloads out of default namespace into app namespaces." ;;
    22) echo "Set CPU/memory requests+limits for every container." ;;
    28) echo "Pin immutable image tags/digests; avoid latest/untagged." ;;
    OS_SCC_PRIV) echo "Use restricted-v2 SCC where possible; avoid privileged SCC." ;;
    OS_ROUTE_TLS) echo "Configure TLS routes with secure termination and no insecure policy." ;;
    OS_NETPOL_QUALITY) echo "Add namespace-wide default-deny style policies with broad podSelector coverage." ;;
    OS_SA_TOKEN_LEGACY) echo "Use projected SA tokens; remove legacy secret token mounts." ;;
    OS_ESC_CHAIN) echo "Break privilege-escalation chain: privileged/hostPath/default SA combinations." ;;
    *) echo "Review finding and apply least-privilege hardening." ;;
  esac
}

effort_for() {
  case "$1" in
    2|3|5|7|7b|8|20|22|28|OS_ROUTE_TLS|OS_SA_TOKEN_LEGACY) echo "quick" ;;
    14|16|OS_NETPOL_QUALITY|OS_ESC_CHAIN|OS_SCC_PRIV) echo "medium" ;;
    *) echo "medium" ;;
  esac
}

# pull all pods once (hard-fail if cluster is unreachable or unauthorized)
if PODS_JSON="$(kctl get pods "${NS_ARGS[@]}" -o json 2>/dev/null)"; then
  :
else
  fail_access "cannot list pods for scope (${NS_ARGS[*]}) via $KCTL_BIN"
fi
emit_evidence "pods.json" "$PODS_JSON"

# namespace include/exclude filtering for pod-scoped checks
PODS_JSON="$(printf '%s' "$PODS_JSON" | jq --arg nsf "$NS_FILTER" --arg inc "${INCLUDE_NS_RE:-.*}" --arg exc "${EXCLUDE_NS_RE:-$^}" '
  .items |= [ .[]
    | select((($nsf != "" and .metadata.namespace == $nsf)
              or ($nsf == "" and ((.metadata.namespace | test($inc)) and ((.metadata.namespace | test($exc)) | not)))) )
  ]
')"

# Preflight context block
WHOAMI="$(kctl whoami 2>/dev/null || echo unknown)"
PROJECT="$(kctl project -q 2>/dev/null || echo n/a)"
SERVER_URL="$(kctl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo unknown)"
CAN_LIST_SCOPE="$(kctl auth can-i list pods "${NS_ARGS[@]}" 2>/dev/null || echo unknown)"
if $SHOW_PREFLIGHT && ! $JSON; then
  echo "  preflight: client=$KCTL_BIN whoami=$WHOAMI project=$PROJECT can-i-list-pods=$CAN_LIST_SCOPE"
  echo "  preflight: server=$SERVER_URL"
fi

record() {
  local sev="$1" dom="$2" name="$3" detail="$4" id="$5"
  local fp; fp="$(hash_text "$id|$sev|$dom|$detail")"
  FINDINGS+=("$sev|$dom|$name|$detail|$id|$fp")
  case "$sev" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac
}

# helper: count pods matching a jq filter over .items[]
count_pods() { echo "$PODS_JSON" | jq "[.items[] | select($1)] | length"; }
list_pods()  { echo "$PODS_JSON" | jq -r "[.items[] | select($1) | .metadata.namespace + \"/\" + .metadata.name] | .[0:8] | .[]"; }

check_pods() { # severity domain "#N check" jq_filter check_id
  local sev="$1" dom="$2" name="$3" filt="$4" id="$5"
  local c; c="$(count_pods "$filt")"
  c="$(normalize_count "$c")"
  if [[ "$c" == "0" ]]; then record PASS "$dom" "$name" "no matching workloads" "$id"
  else
    local more=""; [[ "$c" -gt 8 ]] && more=", +$((c-8)) more"
    record "$sev" "$dom" "$name" "$c workload(s): $(list_pods "$filt" | paste -sd, -)$more" "$id"
  fi
}

# ── Pod Security (checklist domain I) ─────────────────────────────────────────
check_pods FAIL "Pod Security" "#2 Privileged containers" \
  'any(.spec.containers[]?; (.securityContext.privileged // false) == true)' "2"
check_pods FAIL "Pod Security" "#3 allowPrivilegeEscalation not disabled" \
  'any(.spec.containers[]?; (.securityContext.allowPrivilegeEscalation // true) == true)' "3"
check_pods WARN "Pod Security" "#4 Running as root (runAsNonRoot unset)" \
  '((.spec.securityContext.runAsNonRoot // false) == false) and (all(.spec.containers[]?; (.securityContext.runAsNonRoot // false) == false))' "4"
check_pods FAIL "Pod Security" "#5 hostNetwork / hostPID / hostIPC" \
  '(.spec.hostNetwork == true) or (.spec.hostPID == true) or (.spec.hostIPC == true)' "5"
check_pods WARN "Pod Security" "#6 SA token auto-mounted" \
  '(.spec.automountServiceAccountToken // true) == true' "6"
check_pods WARN "Pod Security" "#7 Capabilities not dropped (ALL)" \
  'any(.spec.containers[]?; ((.securityContext.capabilities.drop // []) | index("ALL")) == null)' "7"
check_pods FAIL "Pod Security" "#7b Dangerous capabilities added" \
  'any(.spec.containers[]?; (.securityContext.capabilities.add // []) | any(. == "SYS_ADMIN" or . == "NET_ADMIN" or . == "NET_RAW" or . == "SYS_PTRACE" or . == "SYS_MODULE" or . == "ALL"))' "7b"
check_pods WARN "Pod Security" "#4b readOnlyRootFilesystem not set" \
  'any(.spec.containers[]?; (.securityContext.readOnlyRootFilesystem // false) != true)' "4b"
check_pods WARN "Pod Security" "#9 hostPath volumes mounted" \
  'any(.spec.volumes[]?; .hostPath != null)' "9"
# ── Supply Chain (domain V) ───────────────────────────────────────────────────
check_pods WARN "Supply Chain" "#28 Images using :latest or untagged" \
  'any(.spec.containers[]?; (.image // "") | (test(":latest$")) or (test(":") | not))' "28"

# ── Resource Management (domain IV) ──────────────────────────────────────────
check_pods WARN "Cluster Hardening" "#22 Containers without resource limits" \
  'any(.spec.containers[]?; (.resources.limits == null))' "22"

# Optional OpenShift check pack
if pack_enabled openshift && $IS_OPENSHIFT; then
  if SCC_JSON="$(kctl get podsecurityadmissionlabels,namespace -A -o json 2>/dev/null || true)"; then
    :
  fi
  if SCC_BINDINGS="$(kctl get rolebindings,clusterrolebindings --all-namespaces -o json 2>/dev/null || true)"; then
    SCC_PRIV_COUNT="$(printf '%s' "$SCC_BINDINGS" | jq -r '[.items[]? | select((.roleRef.name // "") | test("privileged|anyuid"; "i"))] | length')"
    SCC_PRIV_COUNT="$(normalize_count "$SCC_PRIV_COUNT")"
    if [[ "$SCC_PRIV_COUNT" -gt 0 ]]; then
      record WARN "OpenShift Security" "#OS-SCC Privileged grants" "$SCC_PRIV_COUNT privileged/anyuid grants detected" "OS_SCC_PRIV"
    else
      record PASS "OpenShift Security" "#OS-SCC Privileged grants" "no privileged/anyuid SCC grant pattern detected" "OS_SCC_PRIV"
    fi
  else
    record WARN "OpenShift Security" "#OS-SCC Privileged grants" "unable to assess SCC grant bindings" "OS_SCC_PRIV"
  fi

  if ROUTES_JSON="$(kctl get routes --all-namespaces -o json 2>/dev/null || true)"; then
    ROUTE_TLS_BAD="$(printf '%s' "$ROUTES_JSON" | jq -r '[.items[]? | select((.spec.tls // null) == null or ((.spec.tls.insecureEdgeTerminationPolicy // "") == "Allow"))] | length')"
    ROUTE_TLS_BAD="$(normalize_count "$ROUTE_TLS_BAD")"
    if [[ "$ROUTE_TLS_BAD" -gt 0 ]]; then
      record WARN "OpenShift Security" "#OS-Route TLS posture" "$ROUTE_TLS_BAD route(s) missing/weak TLS policy" "OS_ROUTE_TLS"
    else
      record PASS "OpenShift Security" "#OS-Route TLS posture" "routes have TLS config without insecure Allow policy" "OS_ROUTE_TLS"
    fi
  else
    record WARN "OpenShift Security" "#OS-Route TLS posture" "unable to assess routes" "OS_ROUTE_TLS"
  fi

  if NS_LIST_JSON="$(kctl get ns -o json 2>/dev/null || true)"; then
    NP_WEAK=""
    while read -r ns; do
      [[ -z "$ns" || "$ns" =~ ^(kube-system|kube-public|kube-node-lease|openshift|openshift-.*)$ ]] && continue
      scope_ns_match "$ns" || continue
      np_json="$(kctl get netpol -n "$ns" -o json 2>/dev/null || true)"
      default_deny_count="$(printf '%s' "$np_json" | jq -r '[.items[]? | select((.spec.podSelector.matchLabels // {} | length) == 0 and ((.spec.policyTypes // []) | index("Ingress"))) ] | length')"
      default_deny_count="$(normalize_count "$default_deny_count")"
      [[ "$default_deny_count" == "0" ]] && NP_WEAK+="$ns "
    done < <(printf '%s' "$NS_LIST_JSON" | jq -r '.items[]?.metadata.name')
    if [[ -n "$NP_WEAK" ]]; then
      record WARN "OpenShift Security" "#OS-NetworkPolicy quality" "no default-deny pattern in: ${NP_WEAK% }" "OS_NETPOL_QUALITY"
    else
      record PASS "OpenShift Security" "#OS-NetworkPolicy quality" "default-deny style policy detected in scoped namespaces" "OS_NETPOL_QUALITY"
    fi
  fi

  LEGACY_SA="$(echo "$PODS_JSON" | jq -r '[.items[] | select(any(.spec.volumes[]?; .secret.secretName // "" | test("token"; "i")))] | length')"
  LEGACY_SA="$(normalize_count "$LEGACY_SA")"
  if [[ "$LEGACY_SA" -gt 0 ]]; then
    record WARN "OpenShift Security" "#OS-Legacy SA token usage" "$LEGACY_SA workload(s) mount token-like secrets" "OS_SA_TOKEN_LEGACY"
  else
    record PASS "OpenShift Security" "#OS-Legacy SA token usage" "no token-like secret mount pattern detected" "OS_SA_TOKEN_LEGACY"
  fi

  ESC_CHAIN="$(echo "$PODS_JSON" | jq -r '[.items[] | select(any(.spec.containers[]?; (.securityContext.privileged // false)==true) and any(.spec.volumes[]?; .hostPath != null) and ((.spec.serviceAccountName // "default") == "default"))] | length')"
  ESC_CHAIN="$(normalize_count "$ESC_CHAIN")"
  if [[ "$ESC_CHAIN" -gt 0 ]]; then
    record FAIL "OpenShift Security" "#OS-Privilege escalation chain" "$ESC_CHAIN workload(s) combine privileged+hostPath+default SA" "OS_ESC_CHAIN"
  else
    record PASS "OpenShift Security" "#OS-Privilege escalation chain" "no privileged+hostPath+default-SA chain detected" "OS_ESC_CHAIN"
  fi
fi

# ── Cluster hygiene ──────────────────────────────────────────────────────────
if DEFAULT_PODS_RAW="$(kctl get pods -n default --no-headers 2>/dev/null)"; then
  DEFAULT_WORKLOADS="$(printf '%s' "$DEFAULT_PODS_RAW" | wc -l | tr -d ' ')"
  DEFAULT_WORKLOADS="$(normalize_count "$DEFAULT_WORKLOADS")"
  if [[ "$DEFAULT_WORKLOADS" == "0" ]]; then record PASS "Cluster Hardening" "#20 Workloads in default namespace" "default namespace is empty" "20"
  else record WARN "Cluster Hardening" "#20 Workloads in default namespace" "$DEFAULT_WORKLOADS pod(s) in 'default'" "20"; fi
else
  record WARN "Cluster Hardening" "#20 Workloads in default namespace" "unable to assess: cannot list pods in 'default'" "20"
fi

# ── Network (domain II): namespaces with no NetworkPolicy ────────────────────
if [[ -n "$NS_FILTER" ]]; then
  local_np="$(kctl get netpol -n "$NS_FILTER" --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)"
  local_np="$(normalize_count "$local_np")"
  if [[ "$local_np" == "0" ]]; then
    record FAIL "Network" "#8 Namespaces without a NetworkPolicy" "no NetworkPolicy in: $NS_FILTER" "8"
  else
    record PASS "Network" "#8 Namespaces without a NetworkPolicy" "$NS_FILTER has at least one" "8"
  fi
else
  if NS_LIST_JSON="$(kctl get ns -o json 2>/dev/null)"; then
    NP_MISSING=""
    while read -r ns; do
      [[ -z "$ns" || "$ns" =~ ^(kube-system|kube-public|kube-node-lease|openshift|openshift-.*)$ ]] && continue
      scope_ns_match "$ns" || continue
      local_np="$(kctl get netpol -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)"
      local_np="$(normalize_count "$local_np")"
      [[ "$local_np" == "0" ]] && NP_MISSING+="$ns "
    done < <(printf '%s' "$NS_LIST_JSON" | jq -r '.items[]?.metadata.name')
    if [[ -z "$NP_MISSING" ]]; then record PASS "Network" "#8 Namespaces without a NetworkPolicy" "all namespaces have at least one" "8"
    else record FAIL "Network" "#8 Namespaces without a NetworkPolicy" "no NetworkPolicy in: ${NP_MISSING% }" "8"; fi
  else
    record WARN "Network" "#8 Namespaces without a NetworkPolicy" "unable to assess: cannot list namespaces" "8"
  fi
fi

# ── RBAC (domain III): cluster-admin bindings ────────────────────────────────
if CRB_JSON="$(kctl get clusterrolebindings -o json 2>/dev/null)"; then
  ADMIN_BINDINGS="$(printf '%s' "$CRB_JSON" | jq -r '[.items[]? | select(.roleRef.name=="cluster-admin") | .metadata.name] | length')"
  ADMIN_BINDINGS="$(normalize_count "$ADMIN_BINDINGS")"
  if [[ "$ADMIN_BINDINGS" -le 1 ]]; then record PASS "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS binding(s)" "14"
  else record WARN "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS bindings grant cluster-admin — review each" "14"; fi
else
  record WARN "RBAC" "#14 cluster-admin bindings" "unable to assess: cannot list clusterrolebindings" "14"
fi

# ── RBAC (domain III): roles granting verbs=* on resources=* ─────────────────
if ROLES_JSON="$(kctl get clusterroles,roles --all-namespaces -o json 2>/dev/null)"; then
  WILDCARD_COUNT="$(printf '%s' "$ROLES_JSON" | jq -r '[.items[]? | select((.metadata.name // "" | startswith("system:")) | not) | select(any(.rules[]?; ((.verbs // []) | index("*")) and ((.resources // []) | index("*"))))] | length')"
  WILDCARD_COUNT="$(normalize_count "$WILDCARD_COUNT")"
  if [[ "$WILDCARD_COUNT" -eq 0 ]]; then record PASS "RBAC" "#16 Roles granting * verbs on * resources" "none (excluding built-in system: roles)" "16"
  else
    WNAMES="$(printf '%s' "$ROLES_JSON" | jq -r '[.items[]? | select((.metadata.name // "" | startswith("system:")) | not) | select(any(.rules[]?; ((.verbs // []) | index("*")) and ((.resources // []) | index("*")))) | .metadata.name] | .[0:8] | join(", ")')"
    record WARN "RBAC" "#16 Roles granting * verbs on * resources" "$WILDCARD_COUNT role(s): $WNAMES" "16"
  fi
else
  record WARN "RBAC" "#16 Roles granting * verbs on * resources" "unable to assess: cannot list roles/clusterroles" "16"
fi
check_pods WARN "RBAC" "#15 Workloads using the default ServiceAccount" \
  '((.spec.serviceAccountName // "default") == "default") and ((.metadata.namespace // "") | startswith("kube-") | not)' "15"

write_csv() {
  local out="$1"
  {
    echo 'severity,domain,check,id,fingerprint,effort,detail,remediation'
    local f sev dom name detail id fp rem effort
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r sev dom name detail id fp <<<"$f"
      rem="$(remediation_for "$id")"
      effort="$(effort_for "$id")"
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(printf '%s' "$sev" | sed 's/,/;/g')" \
        "$(printf '%s' "$dom" | sed 's/,/;/g')" \
        "$(printf '%s' "$name" | sed 's/,/;/g')" \
        "$id" "$fp" "$effort" \
        "$(printf '%s' "$detail" | sed 's/,/;/g')" \
        "$(printf '%s' "$rem" | sed 's/,/;/g')"
    done
  } > "$out"
}

write_sarif() {
  local out="$1"
  local tmp
  tmp="$(mktemp)"
  local f
  for f in "${FINDINGS[@]}"; do
    printf '%s\n' "$f" >> "$tmp"
  done
  python3 - "$out" "$tmp" <<'PY'
import json,sys
out=sys.argv[1]
inp=sys.argv[2]
rows=[]
with open(inp, encoding='utf-8') as h:
    for line in h:
        line=line.rstrip('\n')
        if not line:
            continue
        sev,dom,name,detail,idv,fp=line.split('|',5)
        rows.append((sev,dom,name,detail,idv,fp))

rules=[]
seen=set()
for sev,dom,name,detail,idv,fp in rows:
    if idv in seen:
        continue
    seen.add(idv)
    rules.append({
        "id": idv,
        "name": name,
        "shortDescription": {"text": name},
        "help": {"text": "See remediation in JSON/CSV output."},
        "properties": {"domain": dom}
    })

def level(sev):
    return {"FAIL":"error","WARN":"warning"}.get(sev,"note")

results=[]
for sev,dom,name,detail,idv,fp in rows:
    results.append({
        "ruleId": idv,
        "level": level(sev),
        "message": {"text": detail},
        "properties": {"domain": dom, "fingerprint": fp}
    })

sarif={
    "version":"2.1.0",
    "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
    "runs":[{"tool":{"driver":{"name":"k8s-audit","rules":rules}},"results":results}]
}
with open(out,'w',encoding='utf-8') as f:
    json.dump(sarif,f,separators=(',',':'))
    f.write('\n')
PY
  rm -f "$tmp"
}

apply_baseline_filter() {
  [[ "$DRIFT_ONLY" != true ]] && return 0
  [[ -z "$BASELINE_IN" || ! -f "$BASELINE_IN" ]] && return 0
  local baseline_ids
  baseline_ids="$(jq -r '.findings[]? | ((.id // .check) + "|" + (.detail // ""))' "$BASELINE_IN" 2>/dev/null || true)"
  local filtered=() f sev dom name detail id fp key exists
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev dom name detail id fp <<<"$f"
    key="$id|$detail"
    exists=false
    if grep -Fxq "$key" <<<"$baseline_ids"; then exists=true; fi
    $exists || filtered+=("$f")
  done
  FINDINGS=("${filtered[@]}")
  PASS=0; WARN=0; FAIL=0
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev _ <<<"$f"
    case "$sev" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac
  done
}

emit_annotations() {
  $GITHUB_ANNOTATIONS || return 0
  local f sev _ name detail id _ level
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev _ name detail id _ <<<"$f"
    case "$sev" in FAIL) level="error";; WARN) level="warning";; *) level="notice";; esac
    echo "::${level} title=${id} ${name}::${detail}"
  done
}

severity_rank() {
  case "$1" in FAIL) echo 3;; WARN) echo 2;; PASS) echo 1;; *) echo 0;; esac
}

is_fail_trigger() {
  local f sev _ _ _ id _
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev _ _ _ id _ <<<"$f"
    [[ "$sev" == "FAIL" ]] || continue
    [[ "$FAIL_ON" == "ALL" ]] && return 0
    if [[ "$FAIL_ON" == "AUTO" ]]; then
      [[ "$id" =~ ^(2|3|5|7b|8|OS_ESC_CHAIN)$ ]] && return 0
      continue
    fi
    [[ ",$FAIL_ON," == *",$id,"* ]] && return 0
  done
  return 1
}

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
    local last_dom="" f sev dom name detail id fp
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r sev dom name detail id fp <<<"$f"
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
if [[ -n "$CSV_OUT" ]]; then
  write_csv "$CSV_OUT"
  $JSON || echo "  CSV report written to $CSV_OUT" >&2
fi
if [[ -n "$SARIF_OUT" ]]; then
  write_sarif "$SARIF_OUT"
  $JSON || echo "  SARIF report written to $SARIF_OUT" >&2
fi

apply_baseline_filter
emit_annotations

if [[ -n "$BASELINE_OUT" ]]; then
  # write post-run baseline snapshot as JSON
  {
    printf '{"pass":%d,"warn":%d,"fail":%d,"findings":[' "$PASS" "$WARN" "$FAIL"
    for i in "${!FINDINGS[@]}"; do
      IFS='|' read -r sev dom name detail id fp <<<"${FINDINGS[$i]}"
      [[ $i -gt 0 ]] && printf ','
      printf '{"severity":"%s","domain":"%s","check":"%s","detail":%s,"id":"%s","fingerprint":"%s"}' \
        "$sev" "$dom" "$name" "$(jq -Rn --arg d "$detail" '$d')" "$id" "$fp"
    done
    printf ']}\n'
  } > "$BASELINE_OUT"
fi

# ── Output ───────────────────────────────────────────────────────────────────
if $JSON; then
  printf '{'
  printf '"pass":%d,"warn":%d,"fail":%d,"profile":"%s","check_pack":"%s","preflight":{"client":"%s","whoami":%s,"project":%s,"server":%s,"can_list_scope":%s},"findings":[' \
    "$PASS" "$WARN" "$FAIL" "$PROFILE" "$CHECK_PACKS" "$KCTL_BIN" \
    "$(jq -Rn --arg v "$WHOAMI" '$v')" "$(jq -Rn --arg v "$PROJECT" '$v')" "$(jq -Rn --arg v "$SERVER_URL" '$v')" "$(jq -Rn --arg v "$CAN_LIST_SCOPE" '$v')"
  for i in "${!FINDINGS[@]}"; do
    IFS='|' read -r sev dom name detail id fp <<<"${FINDINGS[$i]}"
    [[ $i -gt 0 ]] && printf ','
    printf '{"severity":"%s","domain":"%s","check":"%s","detail":%s,"id":"%s","fingerprint":"%s","effort":"%s","remediation":%s}' \
      "$sev" "$dom" "$name" "$(jq -Rn --arg d "$detail" '$d')" "$id" "$fp" "$(effort_for "$id")" "$(jq -Rn --arg d "$(remediation_for "$id")" '$d')"
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
  IFS='|' read -r sev dom name detail id fp <<<"$f"
  [[ "$dom" != "$last_dom" ]] && { echo "  ── $dom"; last_dom="$dom"; }
  case "$sev" in
    PASS) icon="${c_grn}✓${c_rst}";;
    WARN) icon="${c_yel}![${c_rst}";;
    FAIL) icon="${c_red}✗${c_rst}";;
  esac
  printf "     %s %-42s %s[%s] %s%s%s\n" "$icon" "$name" "$c_dim" "$id" "$detail" "$c_rst" ""
done
echo
echo "  ${c_grn}${PASS} pass${c_rst}   ${c_yel}${WARN} warn${c_rst}   ${c_red}${FAIL} fail${c_rst}"
echo "  ${c_dim}profile=${PROFILE}  check_pack=${CHECK_PACKS}  fail_on=${FAIL_ON}${c_rst}"
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
if is_fail_trigger; then exit 1; else exit 0; fi
