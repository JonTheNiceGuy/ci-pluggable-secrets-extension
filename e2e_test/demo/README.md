# drone-environ-demo

A throwaway repo, pushed into the local Gitea by `e2e_test/up.sh`. Its pipeline exercises
the environment extension end to end:

- **`show-injected-*`** — asserts the `stdout_plugin` variable the extension injected
  actually arrives in the build (and that deploy credentials only reach a promotion).
- **`verify-build-token`** — validates the build token the way a receiving service would,
  using only the extension's public keys (see `verify_token.py`).
- **`k8s-can-i`** — points kubectl at the cluster, authenticates as this build with only
  its token, and prints `kubectl auth can-i` for a fixed action list — the API server's own
  yes/no, which differs by trigger because the token's groups do.
- **`k8s-deploy`** — authenticates with that same token and performs the action its identity
  is allowed (`k8s-deploy.sh`), then checks the next tier up is refused. A pull request may
  only read (preview); a branch push may only list pods; a push to `main` may apply
  `deployment.yaml`; a promotion to `production` may redeploy. `cluster-ca.pem` (the
  cluster's CA, exported into this repo by `up.sh`) is what the build trusts the API server
  by — it is not a credential.

`.drone.yml` and `.woodpecker.yaml` are the same pipeline for the two CI systems.
