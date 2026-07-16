# TODO — review follow-ups and decisions

A handoff document for a fresh session. It captures (1) orientation, (2) three
decisions the maintainer made, and (3) the consolidated findings of three reviews
(security, CI/CD, Python), tiered and deduplicated. Nothing below has been implemented
yet — the code is exactly as the reviews found it.

## Orientation

This is an HTTP service that Drone CI and Woodpecker CI call per build to ask "what
environment variables / secrets should this build get?". It verifies a signed request,
runs a plugin system, and returns the answer. It serves two contracts from one codebase:

- **Drone environment extension** — `POST /`, draft-cavage HMAC signature, returns
  `[{name, data, mask}]`. Injected into every step.
- **Woodpecker secret extension** — `POST /secrets`, RFC 9421 ed25519 signature
  (hand-rolled in `ci_pluggable_secrets_extension/rfc9421.py`), returns `{"secrets": [...]}`.

Plugins never learn which CI asked: `ci_pluggable_secrets_extension/woodpecker.py` normalises
Woodpecker's payload into the same request Drone sends.

- Run tests: `uv run pytest` (142 passing, zero warnings; `filterwarnings=["error"]`).
- Local stack: `./e2e_test/up.sh`, then `uv run --project app python e2e_test/verify.py` (Drone) and
  `uv run --project app python e2e_test/verify_woodpecker.py` (Woodpecker). Stack ports: Drone :8080,
  Woodpecker :8000, Gitea :3000, extension :3001.
- Key files: `ci_pluggable_secrets_extension/{server,signature,rfc9421,config,models,woodpecker}.py`,
  `plugins/{buildtoken,deploytarget,stdout}/__init__.py`, `ci_pluggable_secrets_plugin/__init__.py`,
  `plugins/__init__.py` (discovery/registry).
- All dependencies are already pinned to latest (checked this session). Don't downgrade.

---

## Decisions made this session (do these deliberately)

### D1 — Treat `stdout` and `deploytarget` as examples, not shipped plugins — ✅ DONE

Confirmed with maintainer: buildtoken=shipped (stays `ci_pluggable_secrets_extension/plugins/buildtoken`);
stdout + deploytarget moved to `docs/sample_plugins/` with an authoring README
(`docs/sample_plugins/README.md`). testenv now mounts `docs/sample_plugins` into the container
and points `plugin_paths` at it (a live demo of the drop-in mechanism). Tests load the
examples via `plugin_paths` / a `load_example_plugin` conftest helper. README and
config.example.yaml updated.

Original plan follows for reference:


They were written to demonstrate the plugin system, not as fleshed-out features.
`buildtoken` is the opposite — it is the real, supported flagship (OIDC token issuer)
and STAYS a shipped plugin.

**Recommended end-state (confirm the split before executing):**
- Keep `buildtoken` as a bundled, shipped plugin.
- Move `stdout` and `deploytarget` to `docs/sample_plugins/<name>/` OUTSIDE the importable
  built-in plugin package, with a thorough `docs/sample_plugins/README.md` covering: the
  `BaseEnvironPlugin` contract, the `options` spec, the `hook_environment` /
  `hook_routes` hooks, the return shapes, and how to install one via `plugin_paths`.
- Point `testenv` at `docs/sample_plugins` via `plugin_paths` — this doubles as a live
  demonstration of the drop-in mechanism.
- Update the tests that currently enable `stdout`/`deploytarget` (conftest, test_server,
  test_deploytarget, test_plugins) to load them from the examples path.

Alternative the maintainer floated: keep them in place but rename to
`example-deploytarget` / `example-stdout`. The move-to-`examples/` option is
recommended because it makes "these are not supported" structurally obvious and
exercises `plugin_paths`. **Flag for confirmation:** which plugins are "shipped" vs
"example" is the maintainer's call — the recommendation is buildtoken=shipped,
the other two=examples.

### D2 — Rename the top-level `plugins` package — ✅ DONE

Done as recommended: the package is now `ci_pluggable_secrets_extension.plugins` (registry +
buildtoken live there); `import plugins` gone from cli.py/server.py/tests. The external
drop-in namespace was renamed `drone_environ_plugins` → `ci_environ_plugins` (confirmed
with maintainer). pyproject `packages` drops the standalone `plugins`. Dockerfile no
longer copies `plugins/`.

Original plan follows for reference:


`plugins` is a top-level importable package name in site-packages — a serious collision
risk (`import plugins` in `cli.py:7`, `server.py:8`). Rename it.

**Recommended:** make it a subpackage, `ci_pluggable_secrets_extension/plugins/`, imported as
`ci_pluggable_secrets_extension.plugins`. Touches: the package list in `pyproject.toml`, `BUILTIN_PATH`
and `_import()` in `plugins/__init__.py`, the imports in `cli.py`/`server.py`, and every
`import plugins` / `from plugins ...` in tests. The external drop-in namespace is already
`drone_environ_plugins` (`plugins/__init__.py:23`) — consider renaming that to
`ci_environ_plugins` too, since the project is no longer Drone-only.

### D3 — Same-name secret merge / cross-platform parity (researched this session)

Concern: on Woodpecker, extension secrets are *merged* with natively-configured
(org/repo/global) secrets. A native secret the extension did NOT return is still usable
via `from_secret`, and **the extension cannot prevent it** (confirmed against the
Woodpecker docs: "extension secrets are merged … with extension secrets taking priority
by name"; no exclusion mechanism). So `deploytarget`'s event-gating can be bypassed if an
operator defines a same-named native secret.

Research result — the exposure is a property of the *secret-lookup* model, not of a
platform:

| Model | Merge/bypass? | Built-in PR/fork gating? |
| --- | --- | --- |
| Drone **environment** extension (current) | **No** — sole injector, no `from_secret`, no merge | No (not in the contract) |
| Woodpecker **secret** extension (current) | **Yes**, and unfixable from our side | No |
| Drone **secret** extension (not built) | Yes (per-name lookup, can't exclude native) | **Yes** — response `drone.Secret` has `pull_request` + `pull_request_push` (and deprecated `pull`/`fork`) |

Drone secret extension request is per-name: `{path, name, repo, build}` → response
`{name, data, pull_request, pull_request_push}` (`drone-go/plugin/secret`,
`drone/types.go Secret`).

**Status:** action 1 (docs) and action 3 (asymmetry) done. **Action 2 — a Drone secret
extension endpoint — is now BUILT** (`mount_drone_secret` in server.py): `POST /secret`
(configurable, distinct path from Woodpecker), same HMAC signature, per-name lookup over
the same plugins, returns `drone.Secret {name, data, pull_request, pull_request_push}` or
404. `Variable` gained optional `pull_request`/`pull_request_push` (default False =
withheld from PRs) that a plugin opts into via the expanded return form — the per-secret
gating the environment contract lacks. Wired into testenv. Does NOT close the
native-secret merge gap (nothing can). Tests in `test_drone_secret.py`.

**Actions for parity:**
1. **Document** (README, Woodpecker section) that on Woodpecker the extension is NOT the
   sole gatekeeper: operators must not configure native secrets whose names collide with
   extension-issued ones, or event-gating is bypassed. State plainly that the current
   Drone *environment* extension does not have this issue (sole injector).
2. **Consider implementing a Drone secret extension endpoint** (design decision, not
   urgent) so the plugin system can also serve Drone's `from_secret` model. If done, map
   fork/PR gating onto `pull_request`/`pull_request_push` — this is the right protocol
   tool for the fork-PR concern in T2-A below, and it is the closest thing to true parity
   with Woodpecker's secret extension. Note it does NOT close the native-secret-merge gap
   (no platform's secret model can) — only documentation does.
3. Record the asymmetry: the environment-extension contract has no per-secret PR/fork
   flag, which is precisely why `buildtoken`/`deploytarget` must carry their own
   event-gating (see T2-A).

---

## Findings to action

Severity and provenance noted per item: [SEC]=security review, [CI]=CI/CD review,
[PY]=Python review. "Confirmed" = a reviewer demonstrated it with a PoC.

### Tier 1 — live, confirmed, cheap. Do these first. — ✅ DONE (all five landed with regression tests; suite 148 passing)

- **T1-1 [SEC] Unauthenticated body-size DoS (confirmed).** `server.py:92` and `:151`
  buffer the entire request body into memory before any signature check; no size cap
  anywhere. A 60 MB unsigned POST was accepted then 400'd; scale to OOM. Fix: reject on
  `Content-Length` (→413) before reading, plus a concurrency/connection cap. Real
  payloads are a few KB.

- **T1-2 [PY] Plugins run synchronously on the event loop (confirmed).** `server.py:91`
  and `:150` are `async def` but call the synchronous `plugins.run_hook(...)` directly;
  plugins do RSA signing / blocking I/O. 4 concurrent 0.5s builds took 2.0s, and
  `/healthz` was blocked behind an in-flight build (→ liveness probe restarts a healthy
  pod). Fix: `await anyio.to_thread.run_sync(functools.partial(run_hook, ...))` in both
  endpoints. Keep plugins synchronous (right contract). The `buildtoken` JWKS/discovery
  routes are fine (cheap), but cache `jwks()` in `configure()` — it re-derives per request.

- **T1-3 [PY] `buildtoken._interpolate` infinite-loop DoS (confirmed).**
  `plugins/buildtoken/__init__.py` `_interpolate` loops `while "{" in result` and
  substitutes resolved values back into the scanned string; `deploy_to` is
  attacker-chosen on a promotion, so `deploy_to="{build.deploy_to}"` loops forever, and
  via T1-2 wedges the whole extension. Also raises `ValueError` on an unbalanced brace.
  Only active when a `subject:` template is configured (the default `include_claim_keys`
  path is safe). Fix: single-pass `re.sub(r"\{([^{}]*)\}", ...)`, and apply `_escape` to
  substituted values (see T1-4b).

- **T1-4a [PY] Typo silently unmasks a secret (confirmed).** `ci_pluggable_secrets_extension/models.py`
  `Variable` has no `extra` setting (defaults to `ignore`), so
  `{"data": "s3cret", "masked": True}` (typo for `mask`) yields `mask=False` — the secret
  reaches Drone unmasked and lands in the build log. Fix: `model_config =
  ConfigDict(extra="forbid")` on `Variable`. Highest-consequence silent failure; one line.
- **T1-4b [PY] `Variable.data` coercion inconsistent.** The flat plugin-return form
  coerces non-str via `str(value)` (`server.py:44`) but the expanded form does not (→
  `ValidationError`/500). Add a `field_validator("data", mode="before")` that stringifies,
  so both forms behave alike.

- **T1-5 [CI] `rotate-key.sh` uses the wrong JWKS path (confirmed).** Lines 47 and 56 curl
  `/.well-known/jwks.json`; the extension serves `/.well-known/jwks` (the `.json` path
  404s — verified live). Effect: `signing_kid()` returns empty, so `retire` (by its own
  guard) never deletes anything — **phase 3 of rotation is permanently broken**, old keys
  accumulate forever, a compromised key can't be retired via the documented flow. `status`
  tracebacks on the 404. Fix: change both to `/.well-known/jwks`.

### Tier 2 — real, needs a small design decision — ✅ DONE

- **T2-A** buildtoken now gates issuance: `deny_forks` (default **True**, GitHub-aligned;
  detects fork via `build.source_repo` != `repo.slug`, covers fork PRs *and* promotions
  of fork code) + `require_events` allow-list. **Default behaviour change:** fork-authored
  builds now get no token.
- **T2-B** rfc9421 now type-checks `created` (int) and the signature value (byte
  sequence) → 401 not 500.
- **T2-C** both verifiers now *require* digest coverage (and Date/`created` coverage when
  a skew/age bound applies); `test_default_header_list_is_date` inverted; real
  content-digest-coverage test added for the Woodpecker side.
- **T2-D** per-plugin `fail_closed` (BaseEnvironPlugin attr); buildtoken + the
  deploytarget example set it, so a credential plugin's error fails the build even under
  `on_plugin_error: skip`.
- **T2-E** ephemeral key generation is now opt-in (`allow_ephemeral_key`, default
  **False**); no key loading fails startup. **Default behaviour change:** zero-key config
  no longer boots.

Original notes follow for reference:


- **T2-A [SEC M1 + CI #6] `buildtoken` issues a token to every build, including fork PRs,
  with no gating (confirmed).** Unlike `deploytarget` (`require_promote`, fails shut),
  `buildtoken.hook_environment` runs for any event and never consults `repo.trusted` /
  `repo.protected` (present in `models.py:26-27`) or fork state. A fork PR from `attacker`
  on `victim/prod-repo` got a signed token asserting `repository=victim/prod-repo`. The
  `sub`/`event_name` do carry `pull_request` (a careful verifier is safe), but GitHub
  *withholds* OIDC from fork PRs and this cannot. Also: a trusted user promoting a
  fork-PR build to `production` mints `sub:…:environment:production` for fork-authored
  code — a cloud policy keyed only on `environment` would authorise it. Fix: add an
  issuance gate (e.g. `deny_fork_pull` / `require_events` / consult `repo.trusted`),
  defaulting to no token on fork PRs; consider refusing environment-scoped issuance when
  `repo.trusted` is false or `build.source_repo` indicates a fork. This is the natural
  place the Drone-secret-extension `pull_request`/`pull_request_push` fields (D3) would
  plug in.

- **T2-B [PY] Two unauthenticated 500s in the Woodpecker verifier (confirmed).**
  `rfc9421.py:~117` `int(created)` and `:~165` `bytes(signature.value)` trust the
  attacker-typed structured-field values; a malformed `Signature-Input` returns a
  traceback + 500 where the contract says 401. Fix: type-check `created` is int and the
  signature value is bytes, raising `SignatureError` otherwise.

- **T2-C [PY #3 + SEC M2] Digest/replay coverage gaps, and an untested guard.**
  - The "signature must cover content-digest" guard in `rfc9421.py:~111` can be deleted
    with **zero** test failures — the test that looks like it covers it
    (`test_a_request_with_no_content_digest_is_rejected`) pops the header and trips a
    different check. Add a real test that signs over `@request-target` only and asserts
    rejection (sketch is in the Python review).
  - The Drone verifier `signature.py` has **no** digest-coverage requirement at all — a
    signature whose covered set omits `digest` validates against a different body
    (confirmed). And `test_default_header_list_is_date` (`test_signature.py:52`) actively
    enshrines accepting a digest-less signature. Make both verifiers require digest (and
    Date/created) coverage when a body/age bound applies, and invert that test.
  - [SEC M2] Both verifiers skip the replay-age check when the timestamp is absent
    (`rfc9421` `created`, Drone `Date`). Not exploitable (the timestamp is inside the
    signed params), but fail-open — require it when `max_age` is set.

- **T2-D [CI #2] `on_plugin_error: skip` silently ships a green build with no
  credentials.** A per-plugin exception under `skip` is swallowed and the build succeeds
  without that plugin's variables. `fail` is the (safe) default, but for credential
  plugins `skip` is unsafe. Fix: let a plugin declare itself fail-closed regardless of the
  global setting, or at minimum document loudly that `skip` must not be used with a
  credential plugin.

- **T2-E [SEC L1 + CI #4] Ephemeral-key fallback hides a broken key mount.**
  `buildtoken` (`__init__.py:~244`) silently generates an in-memory key when `key_dir` /
  `private_key_file` yield nothing, then keeps issuing — a failed key-volume mount
  degrades to non-persistent keys instead of failing closed, breaking verifier JWKS
  caches. Fix: make ephemeral generation opt-in; otherwise fail startup when keys were
  configured but none loaded.

### Tier 3 — structural quality (one coherent "registry + base class" pass) [all PY] — ✅ DONE

- **T3-1** `Registry` class now holds `plugins`/`hooks`; `create_app` stores one on
  `app.state.registry` and reads from it, so two apps don't share state. Module-level
  `plugins`/`hooks`/`load_plugins_and_hooks`/`run_hook` remain as aliases to a
  `default_registry`. Test added: two registries don't share state.
- **T3-2** results now keyed by unique `registry_name`, not `friendly_name`. Test added:
  two plugins with the same friendly_name both contribute.
- **T3-3** option defaults `deepcopy`'d in `configure`. Test added.
- **T3-4** `_plugin_class` only considers own-module subclasses and raises on >1. Tests
  added (two-class module errors).
- **T3-5** `BaseEnvironPlugin.__init__` rejects a missing `friendly_name`; hook discovery
  filters on `inspect.isfunction` and excludes `hook_prefix`. Tests added. Also fixed
  `test_buildtoken_rotation.py` to assert the retired kid is absent rather than catching
  `StopIteration`, and added an autouse registry-teardown fixture to `test_plugins.py`.

Original notes follow for reference:


- **T3-1** `plugins.plugins` / `plugins.hooks` are module-level globals mutated at
  config time; building a second app retroactively changes what the first serves, and
  tests need manual teardown. Introduce a `Registry` object hung off `app.state`; keep a
  module-level default as a deprecated alias if convenient.
- **T3-2** `run_hook` keys results by free-text `friendly_name` (`plugins/__init__.py:143`)
  while the registry is keyed by module name; two plugins sharing a `friendly_name`
  silently drop one's variables. Key by the unique registry name.
- **T3-3** Plugin option defaults are shared by reference (`ci_pluggable_secrets_plugin:~49`,
  `value = item["default"]`) — mutable-default bug, latent today. `deepcopy` the default.
- **T3-4** `_plugin_class` picks the alphabetically-first `BaseEnvironPlugin` subclass
  (`plugins/__init__.py:73`), so a plugin that subclasses another loads the wrong class.
  Only consider classes whose `__module__` is the plugin's own module; raise on ambiguity.
- **T3-5** Make `BaseEnvironPlugin` an ABC (or `friendly_name`/`version` abstract) so a
  helper class can't be instantiated as a plugin and `"UNDEFINED"` can't ship. Tighten
  hook discovery: filter on `inspect.isfunction` rather than any callable named `hook_*`,
  and exclude the `hook_prefix` knob itself.

### Tier 4 — packaging & docs — ✅ DONE

- **T4-1** Dockerfile rewritten: non-root `appuser`, reproducible `uv sync --frozen
  --no-dev` from the lockfile, deps-before-source layering, `EXPOSE 3000` (matches the
  config default), runs the venv console script directly. Stale `COPY plugins` removed.
- **T4-2** config.py: validates `log_level` against `logging.getLevelNamesMapping()`,
  rejects a non-mapping `woodpecker:`, and rejects both `public_key_file` +
  `public_key_url`. Tests added.
- **T4-3** Woodpecker key fetch retries with backoff (5 attempts); the key is now held in
  a `WoodpeckerKey` cache that **re-fetches when stale** (older than `key_max_age`, default
  `$WOODPECKER_SECRET_AGE_SECONDS` then 300s) on an incoming `/secrets` request, and can be
  forced via `POST /secrets/refresh-key`. A failed refresh keeps the last good key. No
  restart needed for a Woodpecker key rotation.
- **T4-4** README "Deploying for real": public HTTPS issuer matching `iss`, the HA key
  story (shared `key_dir`, no ephemeral behind replicas, rotation = rolling restart that
  settles before promote), and the D3 Woodpecker native-secret merge caveat.
- **T4-5** `full_ref` handles `release` like a tag; `buildtoken._derive` treats
  `pull_request_closed` as PR-shaped; docstring/README note that `event_name` mirrors the
  CI's vocabulary. Tests added.
- **T4-6** Woodpecker 204 (no-secrets) path now logs at INFO. Plus a new per-request INFO
  line on all three POST endpoints (environment, Woodpecker secrets, Drone secret):
  `<plugins> fired in the context of <slug>/<build#>/<stage>/<step> at <ref> due to
  <action>` (action normalised: pull_request→pr, etc.). Stage/step are logged as "-" —
  Drone's and Woodpecker's extension protocols carry only repo+build, not stage/step.

Original notes follow for reference:


- **T4-1 [PY] Dockerfile.** `EXPOSE 3001` contradicts default port 3000
  (`config.py:38`); runs as root; `pip install .` ignores `uv.lock` (non-reproducible,
  a bad upstream release ships itself). Fix: reconcile the port, add a non-root `USER`,
  install from the frozen lock (`uv sync --frozen --no-dev`), and copy deps before source
  for layer caching.
- **T4-2 [PY] config.py hardening.** Validate `log_level` against
  `logging.getLevelNamesMapping()` in `load()` (currently crashes post-load on a bad
  value); reject non-mapping `woodpecker:`; warn/reject when both `public_key_file` and
  `public_key_url` are set (file silently wins).
- **T4-3 [SEC/CI] Woodpecker public key fetch** (`server.py:~62`) is a single startup
  GET with no retry — a brief Woodpecker outage during rollout crashes boot, and a
  Woodpecker key rotation needs an extension restart with no detection. Consider retry +
  periodic refetch.
- **T4-4 [CI] Docs for real deployment** (not code): cloud OIDC federation needs a
  publicly-reachable **HTTPS** issuer with `iss` matching exactly — testenv's
  `http://172.17.0.1:3001` and `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS=*` hide this. Document
  the HA key story (all replicas need the same `key_dir`; ephemeral keys diverge per
  replica and are unusable behind >1 replica; rotation must be a rolling restart that
  fully settles before `promote`). Document the D3 merge caveat.
- **T4-5 [CI] Event-model completeness.** `woodpecker.py EVENTS` omits `release` and
  `pull_request_closed`; `full_ref()` won't reconstruct a `release` tag ref, and
  `buildtoken._derive` matches `pull_request` exactly so `pull_request_closed` loses its
  head/base refs. Neither is dangerous (`deploytarget` stays shut), but the "mapping is
  complete" framing in the docstring/README is overstated — handle `release` like a tag,
  treat `pull_request_closed` as PR-shaped, or document both as unsupported. Add a
  one-line caveat that `event_name` mirrors the CI's vocabulary, not GitHub's
  (`tag`/`cron`/`custom`/`promote` differ from GitHub's `push`/`schedule`/`workflow_dispatch`).
- **T4-6 [CI] Observability.** `deploytarget` logs decline reasons at DEBUG; at the
  shipped INFO level an operator can't see why a push got no secret, and the Woodpecker
  204 path logs nothing. Consider logging decline reasons + the 204 reason at INFO.

### Tests to add (would have caught the above) [PY #11]

Concurrency (T1-2); infinite-loop `subject:` with hostile `deploy_to` (T1-3); two plugins
with the same `friendly_name` both getting variables (T3-2); a plugin mutating
`self.settings` not leaking to the next instance (T3-3); unknown key in the expanded
`Variable` form rejected (T1-4a); a signature not covering the body rejected on BOTH
verifiers (T2-C). Also: replace the two `Exploding` fakes in `test_server.py` (they append
into registry internals and aren't `BaseEnvironPlugin`s) with a real failing plugin loaded
via config; add an autouse registry-teardown fixture in `test_plugins.py`; fix
`test_buildtoken_rotation.py` asserting on `StopIteration` (assert no JWKS key matches the
kid instead).

---

## Do NOT "fix" these — confirmed correct by review

- `models.py` Pydantic v2 mutable defaults (`params: dict = {}`, `repo: Repo = Repo()`)
  are **safe** — v2 deep-copies per instance. Verified. Do not "fix" with `default_factory`.
- Signature verification runs before any plugin execution on both endpoints; no path
  reaches plugins or a 2xx without full verification. Constant-time comparisons throughout
  (`hmac.compare_digest`). No algorithm confusion/downgrade/`none` (each side allow-lists
  one algorithm). `@request-target` correctly path-only for Woodpecker.
- `deploytarget` is not spoofable by push/PR/fork/cron: it gates on `event ∈
  {promote, rollback}` + a known `deploy_to` and fails shut on an unknown target;
  `deploy_to` is only populated by promote/rollback (Drone) / the deployment API
  (Woodpecker), never attacker-settable on push/PR/custom/manual.
- Secrets are never logged (only names); the `stdout` plugin dumps the request, not the
  response; Woodpecker `netrc` is captured by `extra="allow"` but never forwarded or
  logged.
- JWKS/discovery expose only public material (by design, unauthenticated).
- The `buildtoken` OIDC claim mapping is honest — `actor_id`, `repository_owner_id`,
  `run_attempt`, `workflow`, `job_workflow_ref` are omitted rather than approximated;
  `omit_empty` distinguishes `False` from `""`/`None`; `sub` via `include_claim_keys`
  matches GitHub's default and contextual segments incl. `:`→`%3A` escaping.
- The three-phase key-rotation *design* (publish→promote→retire, multi-key JWKS, kid
  selection) is correct — only the script path bug (T1-5) and HA restart atomicity (T4-4)
  undercut it.
- The golden captured-request fixture (`tests/fixtures/woodpecker_request.json`) is what
  makes the hand-rolled RFC 9421 verifier defensible — keep it alive across Woodpecker
  upgrades.
- The Drone-config-leak-enables-forgery property is inherent to its symmetric HMAC
  protocol, not a bug; Woodpecker correctly holds only a public key.

---

## Suggested order

1. **Tier 1** (all live, all small): T1-1, T1-2, T1-3, T1-4a/b, T1-5. Add the matching
   tests as you go.
2. **D1 + D2** (rename examples, rename the `plugins` package) — structural but
   low-risk, and best done before Tier 3 touches the registry. Confirm the shipped-vs-
   example split (D1) with the maintainer first.
3. **Tier 2** design calls: T2-A (fork-PR gating) is the headline; do it alongside the D3
   decision on whether to add a Drone secret extension.
4. **Tier 3** as one registry+base-class pass.
5. **Tier 4** packaging + docs.

Every finding above was demonstrated with a PoC by its reviewer; treat file:line
references as approximate (the files may shift as Tier 1 lands) and re-locate by symbol.
