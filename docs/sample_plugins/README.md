# Example plugins & how to write your own

The two plugins here — `stdout` and `deploytarget` — are **examples**, not shipped
features. They exist to show what the plugin system can do and to give you a working
template to copy. They are deliberately *not* part of the installed package; they are
loaded the same way your own plugins are: by dropping them onto a directory named in
`plugin_paths`.

The one plugin that *is* shipped and supported is `buildtoken`
(`ci_pluggable_secrets_extension/plugins/buildtoken/`), the OIDC build-token issuer. It loads
automatically — you never put it on a `plugin_paths` directory.

- **`stdout`** — logs the whole request to stdout and returns `{"stdout_plugin": "enabled"}`.
  The smallest possible plugin: one hook, one option, no state.
- **`deploytarget`** — hands out per-environment variables, but only to a build that a
  human promoted (`deploy_to` is set only on promote/rollback). Shows config-driven
  behaviour and fail-shut gating.

(The bundled `buildtoken` and `logreceive` plugins are built in — part of the installed
package — and load without a `plugin_paths` entry; see the top-level README.)

## Installing a plugin

A plugin is a Python package (a directory with an `__init__.py`) whose name is the
plugin's name. Install one in three steps:

1. Put the package on a directory, e.g. `/etc/ci-environ/plugins/myplugin/__init__.py`.
2. Add that directory to `plugin_paths` in the config file.
3. Enable the plugin by name under `plugins:`.

```yaml
plugin_paths:
  - /etc/ci-environ/plugins        # your drop-in directory

plugins:
  myplugin:                        # matches the package directory name
    some_option: a value           # passed to the plugin as settings
```

Drop-in plugins are imported under the `ci_environ_plugins` namespace, so
`myplugin/__init__.py` becomes the module `ci_environ_plugins.myplugin`. The built-in
`buildtoken` searches first, so a drop-in cannot shadow it; among `plugin_paths`
directories the earliest listed wins on a name clash (you get a warning either way).

Check what would load without starting the server:

```
ci-pluggable-secrets-extension --config config.yaml plugins
```

## Writing a plugin

Subclass `BaseEnvironPlugin` and add a `hook_environment` method. That method is called
once per build with the parsed request, and whatever it returns is merged into the
response the CI system receives.

```python
from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class MyPlugin(BaseEnvironPlugin):
    friendly_name = "myplugin"      # shown in logs and /healthz
    version = "1.0.0"

    # Each option is validated against name/default/required/choices/type before your
    # hook ever runs. An option with no default and required=True is a startup error if
    # unset; an unknown key in the config is warned about and ignored.
    options = [
        {"name": "greeting", "type": str, "default": "hello",
         "help": "What to greet the build with"},
    ]

    def hook_environment(self, request):
        # request is an ci_pluggable_secrets_extension.models.EnvironRequest (Drone's shape). The
        # same object is produced for Woodpecker, normalised — a plugin never learns
        # which CI asked. request.repo and request.build carry the build's facts.
        return {"GREETING": self.settings["greeting"]}
```

### The request

`request` is an `EnvironRequest` with two members, `request.repo` and `request.build`,
modelled on Drone's payload (unknown fields are preserved, so a newer server does not
break an older plugin). Useful fields:

- `request.repo.slug`, `.namespace`, `.name`, `.trusted`, `.protected`, `.visibility`
- `request.build.event` (`push`, `pull_request`, `promote`, `rollback`, `cron`, `tag`,
  `custom`), `.deploy_to` (set only on a promotion), `.ref`, `.after`, `.sender`,
  `.params` (a dict of promotion parameters)

A Woodpecker request is translated into this same shape before your hook sees it, so
one plugin serves both CIs. `build.event` mirrors the CI's own vocabulary.

### What a hook may return

Any of these; they are all normalised to the same thing:

| Return | Meaning |
| --- | --- |
| `None` | contribute nothing |
| `{"NAME": "value"}` | a plain variable (unmasked) |
| `{"NAME": {"data": "secret", "mask": True}}` | a masked variable (Drone hides it in logs) |
| `{"NAME": {"data": 1}}` | non-strings are coerced to strings |
| `[{"name": "NAME", "data": "value", "mask": False}]` | the explicit list form |

Mask anything that is a credential. Unknown keys in the expanded form (e.g. a typo
`"masked"`) are **rejected**, not silently accepted — so a masking mistake fails loudly
rather than leaking a secret to the build log.

The expanded form also accepts `pull_request` and `pull_request_push` (both default
`false`). These are used **only** by the optional Drone *secret* endpoint, where they map
to `drone.Secret`'s per-secret gating — `false` withholds the secret from pull-request
builds. They are ignored on the environment and Woodpecker paths.

When two enabled plugins return the same variable name, the one **later** in the
config's `plugins:` order wins (a warning is logged). Config order is hook order.

### Error handling

If your hook raises, the whole request fails by default (`on_plugin_error: fail`), so a
build never runs with a credential silently missing. An operator can set
`on_plugin_error: skip` globally to carry on without a failing plugin's variables.

A plugin that hands out credentials should not be skippable — a green build with a
credential missing is worse than a failed one. Set `fail_closed = True` on the class and
an error from it fails the request even under `skip`. `deploytarget` here and the
built-in `buildtoken` both do this.

```python
class MyPlugin(BaseEnvironPlugin):
    fail_closed = True     # an error here fails the build even under on_plugin_error: skip
```

### Adding routes (advanced)

A plugin can publish HTTP endpoints of its own by defining `hook_routes(self, app)`,
where `app` is the FastAPI application. `buildtoken` uses this to serve its JWKS and
OIDC discovery documents. These endpoints are **unauthenticated**, so only ever expose
public material through them.

```python
    def hook_routes(self, app):
        @app.get("/myplugin/status")
        async def status():
            return {"ok": True}
```

Any method named `hook_<name>` is registered against the `<name>` hook automatically;
`environment` and `routes` are the two the server dispatches.

## Running the examples

The local test environment (`e2e_test/`) mounts this directory into the extension
container and points `plugin_paths` at it — see `e2e_test/environ-config.yaml` and
`e2e_test/docker-compose.yml`. That is the pattern to copy for a real deployment.
