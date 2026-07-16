#!/usr/bin/env bash
# Create (or re-use) the kind cluster the testenv builds deploy into, and configure its API
# server to authenticate builds by their build token via native OIDC — the same mechanism a
# kubeadm cluster or EKS would use.
#
# Called by up.sh, but safe to run on its own once the compose stack (in particular the
# environ and pagekite services) is up. Re-running is a no-op if the cluster exists.
set -euo pipefail

cd "$(dirname "$0")"
TESTENV_DIR="$PWD"

# Pin kind and the Kubernetes node image. The host's kind may be older than we need
# (v1beta4 kubeadm config + structured auth); rather than touch the system binary we drop a
# pinned kind into .bin and use that.
KIND_VERSION="v0.32.0"
NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
CLUSTER_NAME="drone-environ"
DEMO_REPO="drone-environ-demo"

# The service label half of the pagekite kite that fronts the extension issuer. The kite is
# ${CONTEXT}-${suffix}; suffix comes from .env.pagekite.
CONTEXT="${PAGEKITE_CONTEXT:-environ}"

KUBECONFIG_FILE="$TESTENV_DIR/.kube/config"
export KUBECONFIG="$KUBECONFIG_FILE"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# --- config -------------------------------------------------------------------
[[ -f .env ]] || die "e2e_test/.env not found — run up.sh, which generates it."
set -a; . ./.env; set +a

[[ -f .env.pagekite ]] || die \
    "e2e_test/.env.pagekite not found. The cluster's API server fetches the issuer's keys
    over a pagekite tunnel, so it needs your kite. Copy .env.pagekite.example to
    .env.pagekite and fill in suffix and kitesecret."
set -a; . ./.env.pagekite; set +a
: "${suffix:?set 'suffix' in e2e_test/.env.pagekite}"
: "${kitesecret:?set 'kitesecret' in e2e_test/.env.pagekite}"
KITE="${CONTEXT}-${suffix}"
ISSUER="https://${KITE}"
SLUG="${GITEA_ADMIN_USER}/${DEMO_REPO}"

# --- pinned kind --------------------------------------------------------------
ensure_kind() {
    local installed=""
    command -v kind >/dev/null && installed="$(kind version 2>/dev/null | awk '{print $2}')"
    if [[ "$installed" == "$KIND_VERSION" ]]; then KIND="kind"; return; fi
    if [[ -x .bin/kind ]] && [[ "$(.bin/kind version 2>/dev/null | awk '{print $2}')" == "$KIND_VERSION" ]]; then
        KIND="$TESTENV_DIR/.bin/kind"; return
    fi
    local arch; arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "unsupported architecture for kind: $arch" ;;
    esac
    say "Fetching pinned kind ${KIND_VERSION} into e2e_test/.bin (host kind is ${installed:-absent})"
    mkdir -p .bin
    curl -fsSLo .bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${arch}"
    chmod +x .bin/kind
    KIND="$TESTENV_DIR/.bin/kind"
}
ensure_kind

# --- render the API server's OIDC config and the RBAC -------------------------
say "Rendering the API server OIDC config (issuer ${ISSUER}) and RBAC (repo ${SLUG})"
mkdir -p k8s/apiserver
sed -e "s|__ISSUER__|${ISSUER}|g" k8s/auth-config.yaml.tmpl > k8s/apiserver/auth-config.yaml
# The group names contain the repo slug; render them in. '|' delimiters because the slug
# contains a '/'.
sed -e "s|__SLUG__|${SLUG}|g" k8s/rbac.yaml.tmpl > k8s/rbac.yaml

# --- the cluster --------------------------------------------------------------
if "$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    say "kind cluster '${CLUSTER_NAME}' already exists — keeping it"
else
    say "Rendering kind-config.yaml and creating cluster '${CLUSTER_NAME}' (${NODE_IMAGE%%@*})"
    sed -e "s|__HOST_ADDR__|${HOST_ADDR}|g" \
        -e "s|__TESTENV_DIR__|${TESTENV_DIR}|g" \
        kind-config.yaml.tmpl > kind-config.yaml
    mkdir -p .kube
    "$KIND" create cluster \
        --name "$CLUSTER_NAME" \
        --config kind-config.yaml \
        --image "$NODE_IMAGE" \
        --kubeconfig "$KUBECONFIG_FILE" \
        --wait 90s
fi

# --- RBAC + the CA the build will trust ---------------------------------------
say "Applying RBAC (namespaces, roles, the seed production Deployment)"
kubectl apply -f k8s/rbac.yaml

say "Exporting the cluster CA for the build to trust (demo/cluster-ca.pem)"
kubectl config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
    | base64 -d > demo/cluster-ca.pem

# --- best-effort: confirm the issuer is reachable through pagekite ------------
say "Checking the issuer is reachable through pagekite (${ISSUER})"
if curl -fsS --max-time 10 "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "    ok — the issuer's discovery document answers over the kite"
else
    echo "    WARNING: could not reach ${ISSUER}/.well-known/openid-configuration yet."
    echo "    The pagekite tunnel may still be connecting, or .env.pagekite may be wrong."
    echo "    Token auth to the cluster will fail until the API server can fetch the keys."
fi

cat <<EOF

$(printf '\033[1;32m')Cluster up.$(printf '\033[0m')  Context kind-${CLUSTER_NAME}, API at https://${HOST_ADDR}:6443

  Inspect it:   KUBECONFIG=${KUBECONFIG_FILE} kubectl get ns
  Issuer kite:  ${ISSUER}/.well-known/openid-configuration
EOF
