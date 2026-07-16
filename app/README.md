# ci-pluggable-secrets-extension

The deployable service: a pluggable CI environment/secret extension for Drone and
Woodpecker. It receives a build's details, asks every enabled plugin what variables (or
secrets) that build should get, and combines the answers into one signed response. A
bundled `buildtoken` plugin can also issue a short-lived OIDC JWT describing the build, so
a build can authenticate to a service (e.g. a Kubernetes cluster) with no long-lived
credential.

This directory is the self-contained, dockerable unit:

- `ci_pluggable_secrets_extension/` — the app (server, config, CLI, models, bundled plugins).
- `ci_pluggable_secrets_plugin/` — the `BaseEnvironPlugin` base class that plugins subclass.
- `tests/` — the test suite.
- `Dockerfile`, `pyproject.toml`, `uv.lock` — the build.

## Run it locally

```sh
uv sync
cp config.example.yaml config.yaml
export DRONE_ENV_PLUGIN_SECRET=$(openssl rand -hex 32)
./ci-pluggable-secrets-extension plugins   # show what would load
./ci-pluggable-secrets-extension serve      # listen on :3000
```

## Test

```sh
uv run pytest
```

See the [project README](../README.md) for the full story and the plugin-authoring guide,
[../docs/deploying.md](../docs/deploying.md) to deploy it, and [../helm_chart/](../helm_chart/)
for the Kubernetes chart.
