# ci-pluggable-secrets-extension

A [Drone CI environment extension](https://docs.drone.io/extensions/environment/) with
a plugin system: it receives the detail of a build, asks every enabled plugin what
environment variables that build should get, and combines the answers into one response.

It also serves [Woodpecker](https://woodpecker-ci.org/docs/usage/extensions) from the
same plugins — see [Woodpecker](#woodpecker) below.

The repository is laid out as: [`app/`](app/) — the deployable Python package and its
Dockerfile; [`e2e_test/`](e2e_test/) — a throwaway Gitea + Drone + Woodpecker + kind
end-to-end environment; [`docs/`](docs/) — the [deployment guide](docs/deploying.md) and the
[sample plugins](docs/sample_plugins/); and [`helm_chart/`](helm_chart/) — the Kubernetes
chart. Commands below are run from `app/` unless noted.

## Why

Drone lets a runner call out to a single HTTP service to ask "what environment
variables does this build need?". One service, one answer — so the moment you want
variables from two sources (say, a secret store *and* a naming convention derived from
the repo), you are editing one monolithic service and redeploying it.

This extension is that service, but the answer is assembled from plugins. A plugin is a
small Python package dropped onto a plugin path and named in the config file. It sees
the whole build request and returns the variables it wants to contribute; the extension
merges them and replies to Drone.

## How it works

Drone POSTs `{"repo": {...}, "build": {...}}`, signed with a shared secret. The
extension verifies the signature, runs the `environment` hook on every enabled plugin,
merges the results, and returns the array Drone expects:

```json
[{"name": "stdout_plugin", "data": "enabled", "mask": false}]
```

## Running it

```sh
cd app
uv sync                                          # or: pip install -e .
cp config.example.yaml config.yaml
export DRONE_ENV_PLUGIN_SECRET=$(openssl rand -hex 32)

./ci-pluggable-secrets-extension plugins         # show what would load, and with what settings
./ci-pluggable-secrets-extension serve           # listen on :3000
```

Then point the runner at it — the token must equal the extension's secret:

```sh
DRONE_ENV_PLUGIN_ENDPOINT=http://ci-pluggable-secrets-extension:3000
DRONE_ENV_PLUGIN_TOKEN=<the same secret>
```

To deploy it to Kubernetes, see [docs/deploying.md](docs/deploying.md) and [helm_chart/](helm_chart/).

Note that the signature covers the request path, so if a reverse proxy in front of the
extension rewrites the path, verification will fail.

## Configuration

See `config.example.yaml`. The parts that matter:

| Key | Meaning |
| --- | --- |
| `server.secret` | Shared secret; must match `DRONE_ENV_PLUGIN_TOKEN`. Falls back to `$DRONE_ENV_PLUGIN_SECRET`. |
| `server.on_plugin_error` | `fail` (500, and the build fails) or `skip` (drop that plugin's variables, carry on). |
| `server.max_clock_skew` | Reject signed requests whose `Date` is further adrift than this, in seconds. |
| `plugin_paths` | Directories to search for drop-in plugins, alongside the built-in ones. This is how you install a plugin you wrote, or the examples under `docs/sample_plugins/`. |
| `plugins` | The plugins to enable, and their settings. **Order matters** — later plugins override variables set by earlier ones. |

Any `${VAR}` or `${VAR:-default}` in the config is expanded from the environment, so
secrets need not be written to the file.

## Writing a plugin

Create `<plugin_path>/<name>/__init__.py` with one `BaseEnvironPlugin` subclass. Any
method named `hook_<something>` is registered against that hook automatically. There
are two hooks:

| Hook | Called | For |
| --- | --- | --- |
| `hook_environment(request)` | Once per build | Contribute variables to the response |
| `hook_routes(app)` | Once at startup | Add HTTP endpoints of your own. These are **unauthenticated**, so expose only public material — `buildtoken` uses it to publish its JWKS. |

```python
from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class Greeter(BaseEnvironPlugin):
    friendly_name = "greeter"
    version = "0.1.0"
    options = [
        {"name": "greeting", "default": "hello", "help": "What to say"},
        {"name": "token", "required": True, "type": str, "help": "API token"},
    ]

    def hook_environment(self, request):
        # request.repo and request.build are the full Drone payload
        return {"GREETING": f"{self.settings['greeting']} {request.build.author_login}"}
```

Then enable it in `config.yaml`:

```yaml
plugins:
  greeter:
    greeting: g'day
    token: ${GREETER_TOKEN}
```

`options` declares what the plugin accepts from its config section — `name`, `default`,
`required`, `choices`, `type`, `help` — and is validated at startup, so a typo in the
config is a startup error rather than a mystery at build time. The resolved values are
in `self.settings`.

A hook may return any of these; they all mean the same thing to Drone:

```python
return {"KEY": "value"}                          # the simple case
return {"KEY": {"data": "value", "mask": True}}  # mask the value in build logs
return [{"name": "KEY", "data": "value"}]        # the raw Drone form
return None                                      # contribute nothing
```

### Bundled vs example plugins

**`buildtoken`** and **`logreceive`** are shipped, built-in plugins: they are part of the
installed package and load without a `plugin_paths` entry (they still only run when named
under `plugins:`). `stdout` and `deploytarget` are **examples** under `docs/sample_plugins/`
— they demonstrate the plugin system and give you a template, and are installed the same
way your own plugins are (via `plugin_paths`). See
[`docs/sample_plugins/README.md`](docs/sample_plugins/README.md) for the full authoring guide.

**`logreceive`** (built-in) logs the request the CI passes in and returns nothing — a pure
observer for seeing exactly what Drone/Woodpecker send, without changing the build. Off
unless enabled:

```yaml
plugins:
  logreceive:
    level: INFO     # DEBUG, INFO, or WARNING
```

The request is logged as one compact line (a log record must stay single-line for
aggregators), with any newline inside a value escaped.

**`docs/sample_plugins/stdout`** prints the entire request to stdout and returns
`{"stdout_plugin": "enabled"}`. It is the smallest possible plugin, and useful on its
own for seeing exactly what the CI sends.

**`docs/sample_plugins/deploytarget`** hands out per-environment variables, but only to a
build someone deliberately promoted:

```yaml
plugin_paths:
  - /etc/ci-environ/plugins        # where you dropped the example
plugins:
  deploytarget:
    require_promote: true
    targets:
      production:
        DEPLOY_URL: https://prod.example.com
        DEPLOY_TOKEN:
          data: ${PROD_DEPLOY_TOKEN}
          mask: true
      staging:
        DEPLOY_URL: https://staging.example.com
```

Drone populates `build.deploy_to` only on a promotion or rollback, so keying off it
means production credentials never reach a build triggered by a push, a cron, or a
fork's pull request — even though the extension is called for all of them. A promotion
to a target that isn't configured gets nothing rather than another environment's
values, so the deploy step fails rather than deploying somewhere unintended.

Prefer `deploy_to` and `event` for these decisions over `build.params`, which is
whatever the person triggering the build typed.

**`buildtoken`** (built-in) gives every build a short-lived JWT describing itself, which
the build presents to a service instead of holding a long-lived credential. This is the
OIDC workload-identity pattern — the same idea as the token GitHub Actions hands a job
to authenticate to a cloud provider.

```yaml
plugins:
  buildtoken:
    issuer: https://drone-environ.example.com   # where verifiers discover the keys
    ttl: 300
    key_dir: /etc/drone-environ/keys
    include_claim_keys: [repo, context]         # composes the 'sub'
    claims:                                     # merged over the GitHub defaults
      deployment_reason: build.params.REASON
```

The settings follow [GitHub's OIDC model](https://docs.github.com/en/actions/reference/security/oidc):
the subject is composed from `include_claim_keys`, the audience defaults to the
repository owner, and verifiers find the keys through an OIDC discovery document.

By default the claims **mirror GitHub Actions' OIDC token**, so a service that already
verifies GitHub's tokens needs a new issuer and key rather than a new policy. A
promotion produces:

```json
{
  "sub": "repo:octo-org/octo-repo:environment:prod",
  "environment": "prod",  "repository": "octo-org/octo-repo",
  "repository_owner": "octo-org",  "repository_id": "74",
  "repository_visibility": "private",  "actor": "octocat",
  "event_name": "promote",  "ref": "refs/heads/main",  "ref_type": "branch",
  "sha": "example-sha",  "run_id": "1234",  "run_number": "10",
  "runner_environment": "self-hosted",
  "iss": "...", "aud": "...", "jti": "...", "iat": 0, "nbf": 0, "exp": 0
}
```

| GitHub claim | Drone source | Note |
| --- | --- | --- |
| `repository` | `repo.slug` | |
| `repository_owner` | `repo.namespace` | |
| `repository_id` | `repo.uid` | the SCM's id, as GitHub's is |
| `repository_visibility` | `repo.visibility` | |
| `actor` | `build.sender` | who triggered it, not who authored the commit |
| `event_name` | `build.event` | `push`, `promote`, `pull_request`, `cron`, … |
| `ref`, `sha` | `build.ref`, `build.after` | |
| `ref_type` | derived from `build.ref` | `branch` or `tag` |
| `environment` | `build.deploy_to` | only a promotion has one |
| `head_ref`, `base_ref` | `build.source`, `build.target` | **pull requests only** — Drone fills these on every event, but GitHub's meaning is PR-specific, so asserting them for a push would mislead a policy |
| `run_id`, `run_number` | `build.id`, `build.number` | |
| `runner_environment` | always `self-hosted` | every Drone runner is |
| `actor_id`, `repository_owner_id`, `run_attempt`, `workflow`, `job_workflow_ref` | — | **absent**: Drone does not send an equivalent, and a claim that means almost-the-same-thing is worse than no claim, because a verifier will write policy against it |

Numbers are rendered as strings (`"run_number": "10"`), as GitHub's are; `iat`/`exp`/`nbf`
stay numeric. Set `numbers_as_strings: false` to keep them numeric. Add your own claims
under `claims:` (a **name** mapped to a **dotted path into the request**, so
`build.params.REASON` reaches into the promotion parameters), override a default by
redefining it, drop one by setting it to `null`, or start from scratch with
`default_claims: none`. A path with no value is left out rather than asserted as `""`,
so a verifier can meaningfully test a claim's presence.

#### The subject

`sub` is composed from `include_claim_keys`, exactly as GitHub composes it: each key
contributes `key:value`, joined with colons. `repo` is the repository, and `context`
expands to what the build is *doing*. The default `[repo, context]` reproduces GitHub's
own subjects:

| Build | `sub` |
| --- | --- |
| promotion to `Production` | `repo:octo-org/octo-repo:environment:Production` |
| pull request | `repo:octo-org/octo-repo:pull_request` |
| push to a branch | `repo:octo-org/octo-repo:ref:refs/heads/demo-branch` |
| tag | `repo:octo-org/octo-repo:ref:refs/tags/demo-tag` |

Any claim can compose the subject, including your own — `include_claim_keys: [repo,
environment]` yields `repo:octo-org/octo-repo:environment:production`, which is what
you would hand a cloud provider to scope a role to production deploys of one repo. A
colon inside a value is escaped to `%3A`, since subjects are matched by string
comparison. A key naming a claim you do not emit is a **startup error** rather than a
segment that silently vanishes — the only other symptom would be a verifier's policy
quietly failing to match.

#### Audience

Unset, `aud` defaults to the URL of the repository owner (`https://gitea/octo-org`),
as GitHub's does. Set it to whoever consumes the token — `audience: sts.amazonaws.com`
— or to a list.

#### Issuance gating — who does *not* get a token

A token asserts the repository's identity, so code that is not trusted must not receive
one. By default the plugin **withholds a token from any build whose code came from a
fork** (`deny_forks: true`), detected via `build.source_repo` differing from the repo —
the same stance GitHub takes by withholding OIDC from fork pull requests. This covers a
fork pull request, and a promotion or rollback of fork-authored code (which would
otherwise mint an `environment:production` subject for a fork's commit). Set
`deny_forks: false` only if you understand that consequence.

Narrow issuance further with `require_events` — a list of the only build events that
should get a token, e.g. `require_events: [promote, push]`. Everything else gets none.

The environment-extension contract has no per-secret fork/PR flag (unlike a Drone
*secret* extension's `pull_request`/`pull_request_push`), which is exactly why this
gating lives in the plugin. A verifier should still pin the claims it requires (`actor`,
`event_name`, `repository`) rather than trusting that issuance was gated upstream.

```yaml
plugins:
  buildtoken:
    deny_forks: true              # the default; no token for fork-authored code
    require_events: [promote, push]   # optional: only these events get a token
```

#### Keys must load — no silent fallback

The plugin signs with the keys in `key_dir` / `private_key_file`. If none load — a
failed volume mount, an empty directory — it **fails startup** rather than generating a
throwaway in-memory key that would silently break every verifier's cached JWKS on the
next restart. For local experiments you can opt into that throwaway key with
`allow_ephemeral_key: true`; never in production, and never behind more than one replica
(each would generate a different key).

#### How the receiving party validates it

The plugin signs with a private key and publishes, via the `routes` hook, the two
endpoints GitHub's issuer publishes:

| Endpoint | |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery: the issuer, the algorithms, every claim it may assert, and where the keys are |
| `/.well-known/jwks` | the public keys themselves |

Cloud providers federate against the *discovery document*, not a bare key URL, so the
keys can move without reconfiguring every verifier:

```python
discovery = requests.get(f"{ISSUER}/.well-known/openid-configuration").json()
signing_key = PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
claims = jwt.decode(token, signing_key.key, issuer=ISSUER,
                    algorithms=discovery["id_token_signing_alg_values_supported"],
                    audience="https://gitea.example.com/octo-org")
```

The asymmetry is the point. A symmetric secret (HS256) would have to be shared with
every verifier, and anyone who can *verify* a token could also *mint* one. With RS256,
verifiers hold only a public key. A verifier must pin the issuers it trusts rather than
believing the token's own `iss` claim — otherwise an attacker points it at a JWKS
endpoint they control and their forgery verifies.

`e2e_test/demo/verify_token.py` is a working verifier, and runs as a real step in the
demo pipeline.

#### Key rotation

Every `*.pem` in `key_dir` is published for verification; the last one **by filename**
signs, so date-stamped names roll forward on their own. Publishing more than one key is
what makes rotation safe — a token issued a minute before the switchover is still live,
and the verifier finds its key by `kid`.

```sh
./e2e_test/rotate-key.sh publish   # new key served, old key still signing
./e2e_test/rotate-key.sh promote   # new key signs; old tokens still verify
./e2e_test/rotate-key.sh retire    # after the ttl, delete the old key
```

Phase 1 exists because verifiers cache the key set. Skipping straight to signing with a
new key usually works — a sane verifier re-fetches the JWKS when it meets an unknown
`kid` — but "usually" is doing a lot of work in that sentence, and the failure lands on
a deploy. `signing_key:` pins which key signs, which is what makes phase 1 possible;
remove the pin and the newest key takes over. Between `promote` and `retire`, wait out
the token `ttl`: retiring a key invalidates every unexpired token it signed.

If no key can be loaded — neither `key_dir` nor `private_key_file`, or a `key_dir` that
turned out empty because a volume mount failed — the plugin **fails startup** rather than
quietly signing with a throwaway key whose tokens die on the next restart. For a local
experiment you can opt into that throwaway key with `allow_ephemeral_key: true`; never in
production.

#### A real consumer: authorizing a Kubernetes deploy

`verify_token.py` proves a service *can* validate the token. The testenv goes one step
further and lets a build **act** on it: `e2e_test/up.sh` stands up a
[kind](https://kind.sigs.k8s.io/) cluster whose API server authenticates builds by their
build token, and grants power by what the build *is*:

| Build context | May do in the cluster |
| --- | --- |
| pull request | read-only preview: read deployments/pods, but change nothing |
| push to a non-`main` branch | list pods in the `demo` namespace, nothing else |
| push to `main` | create a namespace and apply a Deployment |
| promote to `production` | redeploy the existing production Deployment (not create one) |

Nothing in the demo repo holds a kubeconfig or a cluster credential. The build presents
only its short-lived token, and the API server validates it **itself** via **native OIDC**
— no webhook, nothing kind-specific. This is the portable pattern, the same one a kubeadm
cluster or EKS uses; the extension is just an OIDC issuer, exactly as GitHub Actions is to
a cloud provider.

**The identity: groups mirror the subject.** With `emit_groups: true`, the buildtoken emits
a `groups` claim that is the subject **and each of its segment-prefixes**:

| Build | `sub` (and the last group) | full `groups` claim |
| --- | --- | --- |
| push to `main` | `repo:OWNER/REPO:ref:refs/heads/main` | `[repo:OWNER/REPO, repo:OWNER/REPO:ref:refs/heads/main]` |
| promote to `production` | `repo:OWNER/REPO:environment:production` | `[repo:OWNER/REPO, repo:OWNER/REPO:environment:production]` |
| any other branch | `repo:OWNER/REPO:ref:refs/heads/<x>` | `[repo:OWNER/REPO, repo:OWNER/REPO:ref:refs/heads/<x>]` |

The cluster prepends `oidc:` (its `groupsPrefix`) and RBAC binds the result: the coarse
`oidc:repo:OWNER/REPO` grants every build the read-pods baseline, while a specific tier
adds power on top. A random branch matches only the baseline. Crucially, these are the
**same strings** an AWS IAM trust policy matches on `sub`, so one token drives both worlds.

The API server fetches the issuer's keys over a [pagekite](https://pagekite.net/) tunnel
(real TLS, and it works across the kind/compose network boundary), so the cluster needs a
kite: copy `e2e_test/.env.pagekite.example` to `e2e_test/.env.pagekite` and fill in your
`suffix` and `kitesecret` before running `up.sh`. The demo's `k8s-deploy` step does the
action its tier allows and asserts the next tier up is refused, so the run fails loudly if
a boundary is ever widened.

> The testenv pins **kind v0.32.0** and **Kubernetes v1.36.1**. If your host `kind` is
> older, `kind-up.sh` fetches the pinned binary into `e2e_test/.bin/` rather than touching
> your system install.

##### The same token, on any cluster

Only the cluster-side wiring differs; the token is identical. The claim names line up
across all three:

| | kind / kubeadm | EKS, direct OIDC | EKS, IAM federation |
| --- | --- | --- | --- |
| how | structured `AuthenticationConfiguration` (`--authentication-config`) | `aws eks associate-identity-provider-config` | issuer as an IAM OIDC provider → `AssumeRoleWithWebIdentity` → access entry |
| issuer | `issuer.url` | `issuerUrl` | the OIDC provider URL |
| audience | `issuer.audiences` | `clientId` | the role trust policy's `:aud` condition |
| username | `claimMappings.username.claim: sub` | `usernameClaim: sub` | (the assumed IAM role) |
| groups | `claimMappings.groups.claim: groups` | `groupsClaim: groups` | from the **access entry**, not the claim |
| tiering | RBAC binds the group | RBAC binds the group | trust policy conditions on `sub`; access entry → RBAC |

**Coexistence with another OIDC provider** (likely on a real cluster): on kubeadm/kind the
`jwt` list holds up to 64 authenticators keyed by unique `issuer.url`, so our issuer sits
alongside an existing one — one reason to use structured auth over the single-issuer
`--oidc-*` flags. EKS *direct* OIDC allows only **one** IdP per cluster; if that slot is
taken, use **IAM federation**, which never touches it and coexists with everything. Because
`aud` can be a **list**, one token can satisfy both a direct-OIDC audience and an AWS one at
once. (The testenv models the kubeadm path, which is the one it can run locally.)

## Woodpecker

The same extension, the same plugins, and the same config serve
[Woodpecker](https://woodpecker-ci.org/docs/usage/extensions) too. Enable it by giving
it Woodpecker's public key:

```yaml
woodpecker:
  path: /secrets
  public_key_file: /etc/drone-environ/woodpecker-pubkey.pem
  # or fetch it from the server: public_key_url: http://woodpecker:8000/api/signature/public-key
```

```sh
WOODPECKER_SECRET_EXTENSION_ENDPOINT=http://ci-pluggable-secrets-extension:3001/secrets
WOODPECKER_EXTENSIONS_ALLOWED_HOSTS=*   # Woodpecker will not call a private address otherwise
```

A plugin needs no changes and never learns which CI system asked: Woodpecker's payload
is normalised into the same request Drone sends. What differs is the transport, and the
differences are sharp:

| | Drone | Woodpecker |
| --- | --- | --- |
| Extension type | environment | **no environment extension exists** — the nearest thing is the *secret* extension, so that is what this serves |
| Signature | draft-cavage, **HMAC** with a secret shared both ways | **RFC 9421**, **ed25519** — the extension holds only Woodpecker's *public* key, so its config leaking does not let anyone forge requests to it |
| Response | `[{name, data, mask}]` | `{"secrets": [{name, value, images, events}]}`, or `204` to add nothing |
| Reaching the build | injected into every step | **the step must ask for it by name** with `from_secret` |

That last row is the one that will surprise you. Woodpecker does not inject extension
values into every step, so a pipeline has to opt in:

```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      DEPLOY_TOKEN:
        from_secret: DEPLOY_TOKEN
```

Everything the extension returns arrives as a *secret*, so Woodpecker masks all of it in
the logs — including values that are not secret at all, like `DEPLOY_URL`. There is no
way to hand Woodpecker an unmasked value through this extension point.

### What had to be translated

* **The event vocabulary.** Woodpecker's `deployment` is Drone's `promote`, and its
  `manual` is Drone's `custom`. Unmapped, a plugin keyed on `event == "promote"` would
  silently never fire on Woodpecker, and a deploy would quietly get no credentials. The
  native name stays available to plugins as `build.event_native`. Every other event
  (`push`, `pull_request`, `tag`, `cron`, `release`, `pull_request_closed`) passes
  through unchanged — so `event`/`event_name` mirrors the CI's **own** vocabulary, not
  GitHub's (`tag`/`cron`/`promote` where GitHub says `push`/`schedule`/`workflow_dispatch`).
  A verifier keying on `event_name` must expect the CI's terms.
* **The ref.** On a push Woodpecker sends `refs/heads/main`, but on anything started
  through the API — every deployment — it sends the bare branch `main`. It is completed
  back into a real ref, so the `buildtoken` claims (`ref`, `ref_type`) mean the same
  thing on both systems and one verifier policy matches both.
* **Empty values.** Woodpecker rejects a secret with an empty value *and the whole
  response with it*, so one plugin returning `""` would cost every other plugin its
  variables. Empty variables are dropped, with a warning.

### Verifying against a real Woodpecker

`testenv` runs Woodpecker 3.16 alongside Drone, against the same Gitea, pointed at the
same extension:

```sh
./e2e_test/up.sh
uv run --project app python e2e_test/verify.py             # Drone: a build, a promotion
uv run --project app python e2e_test/verify_woodpecker.py  # Woodpecker: a pipeline, a deployment
```

The ed25519/RFC 9421 verification is hand-rolled ([rfc9421.py](ci_pluggable_secrets_extension/rfc9421.py)),
because Woodpecker sends **no `keyid`** and Python's `http-message-signatures` requires
one. Hand-rolling a signature verifier is only safe if something keeps it honest, so a
request captured from a live Woodpecker server is kept as a fixture
(`tests/fixtures/woodpecker_request.json`) and must still verify. Note also that
`@request-target` is the path alone (`/secrets`) — determined empirically against a real
signature, because guessing wrong fails closed and silently.

## Drone secret extension (optional)

Alongside the environment extension, the same plugins can serve Drone's **secret**
extension. Where the environment extension injects *every* variable into *every* step,
the secret extension answers a step's `from_secret: NAME` with just that one secret — so a
pipeline is explicit about what it pulls, and each secret carries Drone's per-secret
pull-request gating. Enable it with a distinct path:

```yaml
drone_secret:
  path: /secret            # must differ from woodpecker.path
  # secret: ${DRONE_SECRET_PLUGIN_TOKEN}   # defaults to server.secret
```

```sh
DRONE_SECRET_PLUGIN_ENDPOINT=http://ci-pluggable-secrets-extension:3001/secret
DRONE_SECRET_PLUGIN_TOKEN=<the same shared secret, unless you set drone_secret.secret>
```

```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      DEPLOY_TOKEN:
        from_secret: DEPLOY_TOKEN     # Drone asks the extension for exactly this name
```

Drone signs the request the same way as the environment extension (HMAC draft-cavage) and
sends `{name, path, repo, build}`. The extension runs the same plugins, finds the variable
whose name matches, and returns it as a `drone.Secret` — or a `404` if no plugin produced
it, leaving `from_secret` unresolved. The plugins never learn which endpoint asked.

**Per-secret pull-request gating.** The response carries `pull_request` and
`pull_request_push`, which tell Drone whether the secret may be used on pull-request
builds. Both default to **false** — a secret is withheld from PRs unless a plugin opts in
via the expanded return form:

```python
return {"PR_TOKEN": {"data": token, "mask": True, "pull_request": True}}
```

This is the per-secret fork/PR flag the environment-extension contract lacks — the reason
`buildtoken`/`deploytarget` carry their own event gating. Note it does **not** close the
gap where an operator defines a native Drone secret of the same name; only the plugins'
own gating and your not doing that keep event-gating intact.

## Deploying for real

`e2e_test/` optimises for running on one machine with no public address, which hides a
few things a real deployment must get right.

**The issuer must be a public HTTPS URL, matching `iss` exactly.** A cloud provider that
federates with `buildtoken` fetches the discovery and JWKS documents over the network and
pins the issuer string. `issuer:` must therefore be the externally-reachable **HTTPS** URL
of the extension, character-for-character what the verifier is configured to trust — the
testenv's `http://172.17.0.1:3001` works only because the verifier runs in the same demo.
Terminate TLS in front of the extension and set `issuer:` to that public URL.

**Behind more than one replica, every replica must serve the same keys.** A verifier that
fetched the JWKS from replica A must be able to verify a token signed by replica B, so all
replicas need the **same `key_dir`** (a shared/synced volume, or the same mounted secret).
`allow_ephemeral_key` is unusable here: each replica would generate a different key and
tokens would verify only against whichever replica happened to answer the JWKS fetch.

**Key rotation is a rolling restart that must fully settle.** The keys are read once, at
startup. A `publish` → `promote` → `retire` cycle (above) is three rolling restarts; each
must complete across **all** replicas — so every replica publishes the new key — before
you `promote`, or a token signed by an already-promoted replica will fail against a
not-yet-restarted one. Woodpecker's *public* key, by contrast, is refreshed automatically:
it is fetched at startup (with retry) and re-fetched whenever it is older than
`woodpecker.key_max_age` (default `$WOODPECKER_SECRET_AGE_SECONDS`, then 300s) on an
incoming request, and can be forced with `POST /secrets/refresh-key` — so a Woodpecker key
rotation needs no restart.

**Woodpecker: the extension is not the only gatekeeper.** Woodpecker *merges* the secrets
this extension returns with the secrets configured natively in its own UI (org/repo/global),
and the extension **cannot** exclude a native secret. So a plugin's event-gating — e.g.
`deploytarget` only paying out on a promotion — can be bypassed if an operator defines a
**native** secret whose name collides with an extension-issued one: the native one stays
usable via `from_secret` on any event. Do not configure native secrets whose names collide
with extension-issued ones. (Drone's *environment* extension does not have this problem —
it is the sole injector, with no `from_secret` and no merge. This asymmetry is also why the
per-build fork/PR gating lives inside the plugins: the environment-extension contract has
no per-secret fork/PR flag to carry it.)

## Tests

```sh
cd app && uv run pytest
```

## A local Drone to test against

`e2e_test/` brings up a throwaway Gitea, Drone server, Docker runner, and this
extension, all in containers, with the runner pointed at the extension:

```sh
cp e2e_test/.env.pagekite.example e2e_test/.env.pagekite   # then fill in your kite
./e2e_test/up.sh              # ~2 minutes; prints the URLs and a generated password
uv run --project app python e2e_test/verify.py
./e2e_test/down.sh --wipe     # when you are done
```

`up.sh` now also stands up a kind cluster the demo build deploys into (see *A real
consumer: authorizing a Kubernetes deploy* above). Its API server validates build tokens
via native OIDC, fetching the issuer's keys over a pagekite tunnel, so `up.sh` needs
`e2e_test/.env.pagekite` and will stop with instructions if it is missing. A plain `down.sh`
keeps the cluster; only `down.sh --wipe` deletes it.

`up.sh` is idempotent: it generates the secrets, creates the Gitea admin user,
registers Drone as an OAuth app in Gitea *via Gitea's API* (no clicking), starts
everything, and pushes a demo repo whose pipeline asserts that the `stdout_plugin`
variable arrives in the build. `verify.py` then drives the OAuth login the way a
browser would, activates that repo, triggers a build, and checks the assertion held —
so the whole loop is verifiable without a browser. To drive it by hand instead, log in
to Drone with the credentials `up.sh` printed, activate the repo, and hit NEW BUILD.

Everything addresses the host as `172.17.0.1` (the docker0 gateway) rather than
`localhost`. Drone hands the OAuth and webhook URLs it derives from these settings to
your browser and to the Gitea container, so they have to mean the same thing in all
three places — and `localhost` inside the Gitea container means Gitea. Using the
gateway address is also why no ngrok tunnel is needed: nothing has to be publicly
reachable.

Watch the extension handle a real build:

```sh
docker compose -f e2e_test/docker-compose.yml logs -f environ
```
