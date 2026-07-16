"""Stand in for the service a build authenticates to.

This runs inside the build, but it does exactly what a *receiving* service would do
with the token a build presents: discover the issuer's keys, verify the signature,
check the audience and expiry, and only then believe the claims.

Nothing here shares a secret with the extension. The only inputs are the token itself
and public keys anyone may fetch. The claims and the endpoints are GitHub Actions'
OIDC shape, so this is close to what you would already run against a GitHub token.
"""

import json
import os
import sys
import urllib.request

import jwt
from jwt import PyJWKClient

# A real verifier pins the issuers it trusts rather than believing the token's own
# `iss` claim — an attacker with any signing key could otherwise point you at a JWKS
# endpoint they control and have you verify their forgery successfully. The pipeline
# passes it in (the extension's public HTTPS kite); a Kubernetes API server pins the same
# value as its oidc issuer URL.
TRUSTED_ISSUER = os.environ["TRUSTED_ISSUER"]

# The extension is configured with a fixed audience for cluster consumers (the `clientId`
# a cluster is set up with); a real verifier hardcodes the audience it expects.
EXPECTED_AUDIENCE = os.environ.get("EXPECTED_AUDIENCE", "kubernetes")

token = os.environ.get("DRONE_BUILD_TOKEN")
if not token:
    sys.exit("FAIL: the build was given no DRONE_BUILD_TOKEN")

# Find the keys the way a cloud provider does: through the OIDC discovery document,
# not a hardcoded key URL. The issuer can then move its keys without every verifier
# being reconfigured.
with urllib.request.urlopen(f"{TRUSTED_ISSUER}/.well-known/openid-configuration") as response:
    discovery = json.load(response)

print(f"discovered issuer {discovery['issuer']}")
print(f"  keys at        {discovery['jwks_uri']}")
print(f"  algorithms     {discovery['id_token_signing_alg_values_supported']}\n")

# PyJWKClient fetches that key set and picks the key matching the token's `kid`. That
# indirection is what makes rotation invisible here: the extension can start signing
# with a new key and this code needs no change, as long as both keys are published.
signing_key = PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)

claims = jwt.decode(
    token,
    signing_key.key,
    algorithms=discovery["id_token_signing_alg_values_supported"],
    audience=EXPECTED_AUDIENCE,
    issuer=TRUSTED_ISSUER,
)

print(f"token verified (kid {jwt.get_unverified_header(token)['kid']}). It claims:\n")
for name in sorted(claims):
    print(f"    {name:<22} {claims[name]}")

# The claims must describe *this* build. If they didn't, someone replayed a token
# issued for a different one.
for name, actual in {
    "repository": os.environ["DRONE_REPO"],
    "event_name": os.environ["DRONE_BUILD_EVENT"],
    "sha": os.environ["DRONE_COMMIT_SHA"],
    "run_number": os.environ["DRONE_BUILD_NUMBER"],
}.items():
    if claims.get(name) != actual:
        sys.exit(f"\nFAIL: {name} claims {claims.get(name)!r}, but this build is {actual!r}")

print("\nOK: the token describes this build, and only a holder of the extension's "
      "private key could have signed it.")

# The decision a receiving service actually makes. A cloud provider would express this
# as a trust policy on `sub` — the same policy it would write for a GitHub token.
expected_subject = f"repo:{os.environ['DRONE_REPO']}:environment:production"
if claims["sub"] == expected_subject:
    print(f"A production deploy would be authorised: sub matches {expected_subject!r}\n"
          f"({claims['actor']} promoted {claims['repository']} at {claims['sha'][:8]})")
else:
    print(f"A production deploy would be refused: sub is {claims['sub']!r}, "
          f"not {expected_subject!r}")
