"""Prove the cluster authenticates a build token via OIDC, and that the tiers hold.

Mints a build token for each of the three contexts — signed with the *real* key the
extension uses (e2e_test/keys), so it verifies against the JWKS the API server fetched —
and presents it to the live cluster as a bearer token. For each we print the identity the
API server extracted from the JWT (username + groups) and a representative allowed/denied
action, so the whole OIDC path is shown working, with nothing but the token.

Run from the repo root:  uv run --project app python e2e_test/prove_k8s.py
"""

import json
import subprocess
import sys
from pathlib import Path

from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken
from ci_pluggable_secrets_extension.server import normalise

TESTENV = Path(__file__).resolve().parent


def load_env(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip().strip('"').strip("'")
    return out


env = {**load_env(TESTENV / ".env"), **load_env(TESTENV / ".env.pagekite")}
host = env.get("HOST_ADDR", "172.17.0.1")
admin = env.get("GITEA_ADMIN_USER", "droneadmin")
context = env.get("PAGEKITE_CONTEXT", "environ")
suffix = env.get("suffix")
if not suffix:
    sys.exit("prove_k8s: no 'suffix' in e2e_test/.env.pagekite")

ISSUER = f"https://{context}-{suffix}"
SLUG = f"{admin}/drone-environ-demo"
API = f"https://{host}:6443"
CA = str(TESTENV / "demo" / "cluster-ca.pem")

# Sign with the same on-disk key the extension uses, so tokens verify against the JWKS
# the API server already fetched from the issuer.
bt = BuildToken()
bt.configure({
    "issuer": ISSUER,
    "audience": "kubernetes",
    "include_claim_keys": ["repo", "context"],
    "emit_groups": True,
    "key_dir": str(TESTENV / "keys"),
})


def mint(event, ref="", deploy_to=""):
    req = EnvironRequest(
        repo=Repo(slug=SLUG, namespace=admin, default_branch="main"),
        build=Build(event=event, ref=ref, deploy_to=deploy_to, after="deadbeef", number=1),
    )
    result = bt.hook_environment(req)
    return {v.name: v for v in normalise("bt", result)}["DRONE_BUILD_TOKEN"].data


def kubectl(token, *args):
    return subprocess.run(
        ["kubectl", "--kubeconfig=/dev/null", f"--server={API}",
         f"--certificate-authority={CA}", f"--token={token}",
         "--request-timeout=15s", *args],
        capture_output=True, text=True,
    )


def can_i(token, *args):
    return kubectl(token, "auth", "can-i", *args).stdout.strip() or "error"


scenarios = [
    ("a pull request", dict(event="pull_request", ref="refs/heads/feature-x"),
     [("allowed", "get", "deployments", "-n", "production"),
      ("denied",  "create", "deployments", "-n", "app"),
      ("denied",  "create", "namespaces")]),
    ("a push to a feature branch", dict(event="push", ref="refs/heads/feature-x"),
     [("allowed", "get", "pods", "-n", "demo"),
      ("denied",  "get", "deployments", "-n", "production"),
      ("denied",  "create", "namespaces")]),
    ("a push to main", dict(event="push", ref="refs/heads/main"),
     [("allowed", "create", "deployments", "-n", "app"),
      ("denied",  "get", "secrets", "-n", "production")]),
    ("a promotion to production", dict(event="promote", deploy_to="production"),
     [("allowed", "patch", "deployments", "-n", "production"),
      ("denied",  "create", "deployments", "-n", "production")]),
]

print(f"Cluster {API} trusts issuer {ISSUER}\n")
failures = 0
for label, build, checks in scenarios:
    token = mint(**build)
    who = kubectl(token, "auth", "whoami", "-o", "json")
    print(f"== {label} ==")
    if who.returncode != 0:
        print("  FAILED to authenticate:", who.stderr.strip())
        failures += 1
        print()
        continue
    info = json.loads(who.stdout)["status"]["userInfo"]
    print("  username:", info["username"])
    print("  groups:  ", [g for g in info.get("groups", []) if g.startswith("oidc:")])
    for expected, *args in checks:
        answer = can_i(token, *args)
        got = "allowed" if answer == "yes" else "denied" if answer == "no" else answer
        mark = "OK" if got == expected else "MISMATCH"
        if got != expected:
            failures += 1
        print(f"  [{mark}] can-i {' '.join(args)}: {answer} (want {expected})")
    print()

if failures:
    sys.exit(f"prove_k8s: {failures} check(s) did not match — see above.")
print("OK: the cluster authenticated every token via OIDC and the tiers held.")
