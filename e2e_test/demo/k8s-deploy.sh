#!/usr/bin/env bash
# The build authenticating to Kubernetes with nothing but its build token.
#
# This runs inside the pipeline. It presents $DRONE_BUILD_TOKEN — the JWT the extension
# issued for this exact build — as a Kubernetes bearer token. The API server validates it
# via native OIDC against the extension's issuer and maps its claims to a username +
# groups; RBAC then decides what this build may do. What we prove here is that the *same
# code* gets different powers purely because of what the build is:
#
#   push to a branch   -> may only list pods in `demo`
#   push to main       -> may create a namespace and apply a Deployment
#   promote to prod     -> may redeploy the existing prod Deployment, but not create one
#
# For each context we do the thing that should work, and check that the next tier up is
# refused — so the run fails loudly if a boundary has been widened by accident.
set -u

KUBE_API="${KUBE_API:-https://172.17.0.1:6443}"
CA="${CLUSTER_CA:-cluster-ca.pem}"
TOKEN="${DRONE_BUILD_TOKEN:-}"

EVENT="${DRONE_BUILD_EVENT:-}"
BRANCH="${DRONE_COMMIT_BRANCH:-}"
DEPLOY_TO="${DRONE_DEPLOY_TO:-}"

# Woodpecker calls a promotion a "deployment"; the token already normalises it to Drone's
# "promote" (that is the event_name the authenticator keys on), so normalise here too.
[ "$EVENT" = "deployment" ] && EVENT=promote

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }

[ -n "$TOKEN" ] || { red "FAIL: no DRONE_BUILD_TOKEN — the extension issued no token"; exit 1; }
[ -f "$CA" ]    || { red "FAIL: $CA not found — up.sh should have exported the cluster CA into the repo"; exit 1; }

kc() { kubectl --server="$KUBE_API" --certificate-authority="$CA" --token="$TOKEN" "$@"; }

fails=0
# Do an action that must succeed.
allow() {
    desc="$1"; shift
    if out="$("$@" 2>&1)"; then
        green "  OK (allowed): $desc"
    else
        red "  FAIL (expected allowed, denied): $desc"
        printf '    %s\n' "$out"
        fails=$((fails + 1))
    fi
}
# Check that an action is refused, without performing it (SelfSubjectAccessReview).
deny() {
    desc="$1"; shift
    if kc auth can-i "$@" >/dev/null 2>&1; then
        red "  FAIL (expected denied, allowed): $desc"
        fails=$((fails + 1))
    else
        green "  OK (denied): $desc"
    fi
}

echo "Authenticating to $KUBE_API as this build (event=$EVENT branch=${BRANCH:-none} deploy_to=${DEPLOY_TO:-none})"
echo "Identity the cluster sees:"
kc auth whoami 2>&1 | sed 's/^/    /' || echo "    (auth whoami unavailable; continuing)"
echo

if [ "$EVENT" = "promote" ] && [ "$DEPLOY_TO" = "production" ]; then
    echo "Context: a promotion to production -> redeploy the existing prod Deployment"
    allow "rollout restart deployment/demo-app in production" \
        kc rollout restart deployment/demo-app -n production
    # It may redeploy, but not create or delete — that is the whole point of the tier.
    deny  "creating a new deployment in production" create deployments -n production
    deny  "deleting the prod deployment"            delete deployments -n production

elif [ "$EVENT" = "push" ] && [ "$BRANCH" = "main" ]; then
    echo "Context: a push to main -> apply Deployments + create namespaces"
    allow "apply the manifest (creates namespace 'app' + Deployment 'web')" \
        kc apply -f deployment.yaml
    deny  "reading secrets in production" get secrets -n production
    deny  "deleting namespaces" delete namespaces

elif [ "$EVENT" = "pull_request" ]; then
    echo "Context: a pull request -> read-only preview, no changes"
    allow "read deployments (preview current state)" kc get deployments -n production
    deny  "applying a Deployment into 'app'" create deployments -n app
    deny  "creating a namespace"              create namespaces

elif [ "$EVENT" = "push" ]; then
    echo "Context: a push to branch '$BRANCH' -> read-only baseline (repo group)"
    allow "list pods in demo" kc get pods -n demo
    deny  "creating a namespace"                     create namespaces
    deny  "applying a Deployment into 'app'"          create deployments -n app

else
    echo "Context: '$EVENT' to '${DEPLOY_TO:-none}' -> only the repo read-only baseline"
    allow "list pods in demo" kc get pods -n demo
    deny  "creating a namespace"                  create namespaces
    deny  "applying a Deployment into 'app'"       create deployments -n app
fi

echo
if [ "$fails" -eq 0 ]; then
    green "OK: every authorization matched what this build's identity should get."
else
    red "FAIL: $fails authorization check(s) did not match the expected policy."
    exit 1
fi
