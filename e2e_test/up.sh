#!/usr/bin/env bash
# Bring up a local Gitea + Drone + the environment extension, from nothing.
#
# Safe to re-run: it skips any step whose result already exists.
set -euo pipefail

cd "$(dirname "$0")"

# The docker0 gateway: the one address that means "the host" to your browser, to
# the Gitea container, and to the Drone container alike.
HOST_ADDR="${HOST_ADDR:-172.17.0.1}"

GITEA_URL="http://${HOST_ADDR}:3000"
DRONE_URL="http://${HOST_ADDR}:8080"
WOODPECKER_URL="http://${HOST_ADDR}:8000"
DEMO_REPO="drone-environ-demo"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

wait_for() {
    local name=$1 url=$2
    printf '    waiting for %s' "$name"
    for _ in $(seq 60); do
        if curl -sfo /dev/null "$url"; then printf ' ok\n'; return 0; fi
        printf '.'; sleep 1
    done
    printf '\n'
    echo "    $name never came up at $url" >&2
    return 1
}

# --- secrets ------------------------------------------------------------------
# Additive, so an environment created by an older version of this script picks up
# any secret added since without being torn down.
touch .env
ensure_env() {
    if ! grep -q "^$1=" .env; then
        echo "$1=$2" >> .env
        say "Generated $1 into e2e_test/.env"
    fi
}
ensure_env HOST_ADDR "${HOST_ADDR}"
ensure_env GITEA_ADMIN_USER droneadmin
ensure_env GITEA_ADMIN_PASSWORD "$(openssl rand -hex 16)"
ensure_env DRONE_RPC_SECRET "$(openssl rand -hex 16)"
ensure_env DRONE_ENV_PLUGIN_SECRET "$(openssl rand -hex 16)"
ensure_env PROD_DEPLOY_TOKEN "prod-token-$(openssl rand -hex 8)"
ensure_env STAGING_DEPLOY_TOKEN "staging-token-$(openssl rand -hex 8)"
ensure_env DRONE_GITEA_CLIENT_ID ""
ensure_env DRONE_GITEA_CLIENT_SECRET ""
ensure_env WOODPECKER_AGENT_SECRET "$(openssl rand -hex 16)"
ensure_env WOODPECKER_GITEA_CLIENT_ID ""
ensure_env WOODPECKER_GITEA_CLIENT_SECRET ""

set -a; . ./.env; set +a

# The build authenticates to a kind cluster with its build token via native OIDC, and the
# cluster fetches the issuer's keys over a pagekite tunnel — so the extension's issuer is
# the kite URL, built from these. Sourced here, before the extension container starts, so
# it sees PAGEKITE_ISSUER. Required, since the cluster is always part of up.sh.
if [[ ! -f .env.pagekite ]]; then
    echo "e2e_test/.env.pagekite not found. The cluster's API server fetches the issuer's" >&2
    echo "keys over pagekite; copy .env.pagekite.example to .env.pagekite, fill it in, and" >&2
    echo "re-run." >&2
    exit 1
fi
set -a; . ./.env.pagekite; set +a

# The key the buildtoken plugin signs with. It lives on disk rather than in the image
# so that tokens issued before a rebuild still verify after it.
mkdir -p keys
if ! compgen -G 'keys/*.pem' > /dev/null; then
    key="keys/$(date +%Y-%m-%d).pem"
    say "Generating the first build-token signing key ($key)"
    openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key"
    chmod 644 "$key"  # readable by the extension's user inside its container
fi

# --- gitea --------------------------------------------------------------------
say "Starting Gitea"
docker compose up -d gitea
wait_for Gitea "${GITEA_URL}/api/healthz"

say "Creating the Gitea admin user (${GITEA_ADMIN_USER})"
docker compose exec -u git gitea gitea admin user create \
    --username "${GITEA_ADMIN_USER}" \
    --password "${GITEA_ADMIN_PASSWORD}" \
    --email "${GITEA_ADMIN_USER}@example.com" \
    --admin --must-change-password=false 2>&1 | sed 's/^/    /' \
    || echo "    (user already exists, keeping it)"

# --- oauth app ----------------------------------------------------------------
# Drone authenticates users by OAuth against Gitea. The article registers this app
# by hand in the SCM's UI; Gitea has an API for it, so we don't have to.
register_oauth_app() {   # register_oauth_app <name> <redirect-uri> <env-var-prefix>
    local name=$1 redirect=$2 prefix=$3
    if [[ -n "$(grep "^${prefix}_GITEA_CLIENT_ID=" .env | cut -d= -f2)" ]]; then
        return
    fi
    say "Registering ${name} as an OAuth application in Gitea"
    local oauth
    oauth=$(curl -sf -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"${name}\",\"redirect_uris\":[\"${redirect}\"],\"confidential_client\":true}" \
        "${GITEA_URL}/api/v1/user/applications/oauth2")

    local client_id client_secret
    client_id=$(echo "$oauth" | python3 -c 'import sys,json; print(json.load(sys.stdin)["client_id"])')
    client_secret=$(echo "$oauth" | python3 -c 'import sys,json; print(json.load(sys.stdin)["client_secret"])')

    sed -i "s|^${prefix}_GITEA_CLIENT_ID=.*|${prefix}_GITEA_CLIENT_ID=${client_id}|" .env
    sed -i "s|^${prefix}_GITEA_CLIENT_SECRET=.*|${prefix}_GITEA_CLIENT_SECRET=${client_secret}|" .env
    set -a; . ./.env; set +a
    echo "    client_id ${client_id}"
}

register_oauth_app drone "${DRONE_URL}/login" DRONE
register_oauth_app woodpecker "${WOODPECKER_URL}/authorize" WOODPECKER

# --- woodpecker ---------------------------------------------------------------
# Started before the extension, because the extension fetches Woodpecker's ed25519
# public key from it at startup (config: woodpecker.public_key_url) to verify the
# requests it will send. Fetching it live means a fresh `up` picks up Woodpecker's new
# signing key on its own, rather than failing against a stale key file.
say "Starting Woodpecker"
docker compose up -d woodpecker-server woodpecker-agent
wait_for Woodpecker "${WOODPECKER_URL}/api/signature/public-key"

# --- drone, the runner, and the extension -------------------------------------
say "Building the extension image and starting Drone + the runner"
docker compose up -d --build drone runner environ
wait_for Drone "${DRONE_URL}/healthz"
wait_for "the extension" "http://${HOST_ADDR}:3001/healthz"

# --- kubernetes ---------------------------------------------------------------
# The build deploys into a kind cluster, authenticating with its build token via native
# OIDC. .env.pagekite was sourced above (before the extension started), so the extension
# already serves its issuer on the kite; start the tunnel and create the cluster.
# The kite is a new sub-kite pagekite would only register interactively; do it up front
# through the API so the non-interactive tunnel is not rejected with a 401.
# shellcheck disable=SC2154  # suffix comes from .env.pagekite, sourced above
say "Registering the pagekite kite ${PAGEKITE_CONTEXT:-environ}-${suffix} (idempotent)"
KITE="${PAGEKITE_CONTEXT:-environ}-${suffix}" python3 register-kite.py

say "Starting the pagekite tunnel that fronts the extension issuer"
docker compose up -d pagekite

say "Creating the kind cluster and applying its RBAC"
# kind-up.sh exports the cluster CA into demo/cluster-ca.pem, which the repo push below
# then ships to the build — so it must run first.
./kind-up.sh

# --- demo repo ----------------------------------------------------------------
if ! curl -sfo /dev/null -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        "${GITEA_URL}/api/v1/repos/${GITEA_ADMIN_USER}/${DEMO_REPO}"; then
    say "Creating the demo repo"
    curl -sfo /dev/null -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"${DEMO_REPO}\",\"auto_init\":false,\"private\":false}" \
        "${GITEA_URL}/api/v1/user/repos"
fi

# (Re)push the pipeline on every run — force — so edits to demo/ (a new step, an updated
# cluster CA after a fresh cluster) propagate without a wipe. The repo is a throwaway, so
# overwriting its single main branch is fine.
say "Pushing the pipeline to ${GITEA_ADMIN_USER}/${DEMO_REPO}"
work=$(mktemp -d)
cp demo/.drone.yml demo/.woodpecker.yaml demo/verify_token.py demo/README.md \
   demo/k8s-deploy.sh demo/deployment.yaml demo/cluster-ca.pem "$work/"
# The pipelines pin the issuer to verify tokens against; it is the pagekite kite,
# which depends on your suffix, so fill it in at push time.
# shellcheck disable=SC2154  # suffix comes from .env.pagekite, sourced above
PAGEKITE_ISSUER="https://${PAGEKITE_CONTEXT:-environ}-${suffix}"
sed -i "s|__PAGEKITE_ISSUER__|${PAGEKITE_ISSUER}|g" "$work/.drone.yml" "$work/.woodpecker.yaml"
git -C "$work" init -q -b main
git -C "$work" add -A
git -C "$work" -c user.email="${GITEA_ADMIN_USER}@example.com" \
    -c user.name="${GITEA_ADMIN_USER}" commit -qm "Sync the pipeline"
git -C "$work" push -q --force \
    "http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@${HOST_ADDR}:3000/${GITEA_ADMIN_USER}/${DEMO_REPO}.git" main
rm -rf "$work"

cat <<EOF

$(printf '\033[1;32m')Up.$(printf '\033[0m') Log in to Drone with the Gitea account below — Drone will ask Gitea
to authorise it, which is the one step that needs a browser.

  Drone       ${DRONE_URL}
  Woodpecker  ${WOODPECKER_URL}
  Gitea       ${GITEA_URL}
  Extension   http://${HOST_ADDR}:3001/healthz
  Cluster     https://${HOST_ADDR}:6443  (kind context kind-drone-environ)

  username   ${GITEA_ADMIN_USER}
  password   ${GITEA_ADMIN_PASSWORD}

Then, in Drone: SYNC, activate ${GITEA_ADMIN_USER}/${DEMO_REPO}, and hit NEW BUILD.
The pipeline prints the injected variables, verifies its build token, and then uses that
token to deploy into the cluster — with powers that depend on whether it is a branch
push, a push to main, or a promotion to production.

Watch the extension see the build:   docker compose -f e2e_test/docker-compose.yml logs -f environ
Watch the pagekite issuer tunnel:     docker compose -f e2e_test/docker-compose.yml logs -f pagekite
Inspect the cluster:                  KUBECONFIG=e2e_test/.kube/config kubectl get ns
EOF
