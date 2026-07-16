#!/usr/bin/env bash
# Tear the test environment down. Pass --wipe to also delete the Gitea and Drone
# volumes and the generated secrets, so the next up.sh starts from nothing.
set -euo pipefail

cd "$(dirname "$0")"
[[ -f .env ]] && { set -a; . ./.env; set +a; }
[[ -f .env.pagekite ]] && { set -a; . ./.env.pagekite; set +a; }

if [[ "${1:-}" == "--wipe" ]]; then
    docker compose down --volumes --remove-orphans
    # The kind cluster lives outside compose; only a wipe deletes it, so a plain
    # down/up keeps the cluster (and its CA) consistent with the kept demo repo.
    ./kind-down.sh --wipe
    # woodpecker-pubkey.pem is a leftover from the old file-based key config; the
    # extension now fetches the key live, so remove any stale copy.
    rm -f .env woodpecker-pubkey.pem
    echo "Wiped: volumes, the kind cluster, and e2e_test/.env are gone (.env.pagekite kept)."
else
    docker compose down --remove-orphans
    echo "Stopped. Data and the kind cluster kept — run up.sh to bring it back, or down.sh --wipe to reset."
fi
