# Deploying ci-pluggable-secrets-extension

This deploys the extension to Kubernetes with the chart in [`../helm_chart/`](../helm_chart/).
For a throwaway local walkthrough of the whole story (Drone/Woodpecker + a kind cluster that
authenticates builds by their token), see [`../e2e_test/`](../e2e_test/) instead.

## 1. Build and push the image

The build context is [`../app/`](../app/):

```sh
docker build -t registry.example.com/ci-pluggable-secrets-extension:0.1.0 app/
docker push registry.example.com/ci-pluggable-secrets-extension:0.1.0
```

## 2. What the extension needs at runtime

| Input | How the chart supplies it | Notes |
| --- | --- | --- |
| shared secret | `pluginSecret` → a Secret, injected as `DRONE_ENV_PLUGIN_SECRET` | must equal the runner's `DRONE_ENV_PLUGIN_TOKEN`. Or point `existingSecret` at your own. |
| config | `config:` → a ConfigMap mounted at `/etc/drone-environ/config.yaml` | `${VAR}` is expanded from the environment at startup |
| buildtoken signing key(s) | `signingKeys:` → a Secret mounted at `key_dir` | keep these **out of committed values** — pass with `--set-file` |

## 3. The issuer must be a reachable HTTPS URL

buildtoken is an OIDC issuer. Whoever consumes its tokens — a Kubernetes API server's OIDC
authenticator, or AWS IAM — fetches the discovery document and JWKS over **HTTPS**, and
checks the token's `iss` against the URL they were configured with. So:

- `config.plugins.buildtoken.issuer` **must equal** the external URL clients reach the
  extension on, and that URL must serve valid TLS. Self-signed is rejected by EKS.
- Enable the chart's Ingress (`ingress.enabled=true`, `ingress.host=...`, `ingress.tls=...`)
  so `https://<host>/.well-known/openid-configuration` resolves, or front the Service with
  your own TLS and set `issuer` to that URL.

(This is the same requirement the e2e environment meets locally with a pagekite tunnel; in a
real cluster it's an Ingress + cert.)

## 4. Install

Put non-secret values in a file and pass secrets on the command line:

```sh
# values.prod.yaml
image:
  repository: registry.example.com/ci-pluggable-secrets-extension
  tag: "0.1.0"
ingress:
  enabled: true
  className: nginx
  host: ci-secrets.example.com
  tls:
    - secretName: ci-secrets-tls
      hosts: [ci-secrets.example.com]
config:
  server: {host: 0.0.0.0, port: 3000, secret: ${DRONE_ENV_PLUGIN_SECRET}}
  plugins:
    buildtoken:
      issuer: https://ci-secrets.example.com
      audience: kubernetes
      ttl: 300
      key_dir: /etc/drone-environ/keys
      include_claim_keys: [repo, context]
      emit_groups: true
```

```sh
helm upgrade --install ci-secrets helm_chart \
  -f values.prod.yaml \
  --set pluginSecret="$(openssl rand -hex 32)" \
  --set-file 'signingKeys.2026-01-01\.pem=./signing-key.pem'
```

Generate a signing key with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
-out signing-key.pem` (or ES256 with `ec`); rotate by adding a newer-dated key and keeping
the old one published — see the rotation notes in the [project README](../README.md).

## 5. Point CI at it

Configure the Drone runner (and/or Woodpecker) to call the Service:

```sh
DRONE_ENV_PLUGIN_ENDPOINT=http://ci-secrets-ci-pluggable-secrets-extension.<namespace>.svc
DRONE_ENV_PLUGIN_TOKEN=<the pluginSecret>
```

## 6. Configure the consuming cluster

To have a cluster authorize builds by their token, wire its OIDC to this issuer — the
cross-cluster table (kubeadm / EKS direct OIDC / EKS IAM federation) and RBAC pattern are in
the [project README](../README.md#the-same-token-on-any-cluster).
