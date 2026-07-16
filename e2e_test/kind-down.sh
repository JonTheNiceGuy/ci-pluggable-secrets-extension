#!/usr/bin/env bash
# Delete the testenv's kind cluster. Called by down.sh; safe to run on its own.
# Pass --wipe to also remove the generated cluster artifacts (kubeconfig, rendered
# config, exported CA, the pinned kind binary). Never touches .env.pagekite.
set -euo pipefail

cd "$(dirname "$0")"
TESTENV_DIR="$PWD"
CLUSTER_NAME="drone-environ"

# Prefer the pinned kind if present, so we delete with the same version we created with.
if [[ -x .bin/kind ]]; then KIND="$TESTENV_DIR/.bin/kind"; else KIND="kind"; fi

if command -v "$KIND" >/dev/null 2>&1 && "$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "Deleting kind cluster '${CLUSTER_NAME}'"
    "$KIND" delete cluster --name "$CLUSTER_NAME"
else
    echo "No kind cluster '${CLUSTER_NAME}' to delete."
fi

if [[ "${1:-}" == "--wipe" ]]; then
    rm -rf .bin .kube k8s/apiserver
    rm -f kind-config.yaml demo/cluster-ca.pem k8s/rbac.yaml
    echo "Wiped: pinned kind, cluster kubeconfig, rendered config + RBAC, exported CA."
fi
