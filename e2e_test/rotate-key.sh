#!/usr/bin/env bash
# Roll the build-token signing key.
#
# Rotation is three phases, because tokens already in flight must keep verifying:
#
#   1. publish   a new key appears in the JWKS, but the old key keeps signing. Every
#                verifier's cached key set has time to pick the new key up.
#   2. promote   the new key starts signing. Tokens signed by the old key are still
#                live, and still verify, because the old key is still published.
#   3. retire    once every token the old key signed has expired (ttl), delete it.
#                Its tokens stop verifying, which is the point of retiring it.
#
# Skipping phase 1 usually works — a sane verifier re-fetches the JWKS when it meets
# an unknown kid — but "usually" is doing a lot of work in that sentence, and the
# failure lands on a deploy.
set -euo pipefail

cd "$(dirname "$0")"

usage() {
    cat <<'EOF'
usage: rotate-key.sh <publish|promote|retire|status>

  publish   generate a new key and serve it, without signing with it yet
  promote   start signing with the newest key
  retire    delete every key except the one that is signing
  status    show which keys are published and which one signs
EOF
    exit 1
}

restart() {
    # `up -d` is a no-op here: the keys and the config are bind-mounted, so nothing
    # compose compares has changed, and the extension only reads its keys at startup.
    docker compose restart environ > /dev/null 2>&1
    for _ in $(seq 30); do
        curl -sfo /dev/null "http://${HOST_ADDR:-172.17.0.1}:3001/healthz" && return 0
        sleep 1
    done
    echo "the extension did not come back up" >&2
    return 1
}

# The kid of the key the *running* extension is signing with — read from the JWKS it
# is actually serving, not from the config or the logs, so this cannot go stale.
signing_kid() {
    curl -sf "http://${HOST_ADDR:-172.17.0.1}:3001/.well-known/jwks" \
        | python3 -c 'import sys, json; print(json.load(sys.stdin)["keys"][0]["kid"])'
}

status() {
    echo "keys on disk:"
    ls -1 keys/*.pem | sed 's/^/    /'
    echo
    echo "published for verification (kid, newest signs):"
    curl -s "http://${HOST_ADDR:-172.17.0.1}:3001/.well-known/jwks" \
        | python3 -c 'import sys, json; [print("   ", k["kid"], k["alg"]) for k in json.load(sys.stdin)["keys"]]'
    echo
    echo "currently signing with kid: $(signing_kid)"
}

[[ -f .env ]] && { set -a; . ./.env; set +a; }
[[ $# -eq 1 ]] || usage

case "$1" in
    publish)
        new="keys/$(date +%Y-%m-%d-%H%M%S).pem"
        openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$new"
        chmod 644 "$new"
        current=$(ls -1 keys/*.pem | grep -v "$(basename "$new")" | tail -1)

        # Pin signing to the *old* key, so the new one is only published for now.
        python3 - "$current" <<'PY'
import re, sys
from pathlib import Path
current = "/etc/drone-environ/keys/" + Path(sys.argv[1]).name
config = Path("environ-config.yaml")
text = config.read_text()
if "signing_key:" in text:
    text = re.sub(r"( *)signing_key: .*", rf"\1signing_key: {current}", text)
else:
    text = text.replace(
        "    key_dir: /etc/drone-environ/keys",
        f"    key_dir: /etc/drone-environ/keys\n    signing_key: {current}",
    )
config.write_text(text)
PY
        restart
        echo "Published $new. The old key is still signing — give verifiers time to"
        echo "refresh their cached key sets, then: ./rotate-key.sh promote"
        echo
        status
        ;;

    promote)
        # Drop the pin: the plugin then signs with the newest key by filename.
        python3 - <<'PY'
import re
from pathlib import Path
config = Path("environ-config.yaml")
config.write_text(re.sub(r" *signing_key: .*\n", "", config.read_text()))
PY
        restart
        echo "Now signing with the newest key. Tokens from the old key still verify,"
        echo "because it is still published. After the token ttl: ./rotate-key.sh retire"
        echo
        status
        ;;

    retire)
        kid=$(signing_kid)
        # Deleting keys on the strength of a value we failed to read would retire the
        # key that is signing right now, and every live token with it.
        if [[ -z "$kid" ]]; then
            echo "cannot tell which key is signing — is the extension up? Refusing to" >&2
            echo "delete anything." >&2
            exit 1
        fi
        for key in keys/*.pem; do
            # Match each key on disk against the kid the extension says it signs with:
            # the kid is the first 16 hex of the SHA-256 of the DER public key.
            this=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null \
                   | openssl dgst -sha256 -hex | awk '{print substr($NF, 1, 16)}')
            if [[ "$this" != "$kid" ]]; then
                echo "retiring $key (kid $this) — its tokens will stop verifying"
                rm -f "$key"
            fi
        done
        restart
        echo
        status
        ;;

    status) status ;;
    *) usage ;;
esac
