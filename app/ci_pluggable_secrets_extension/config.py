import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SECRET_ENV = "DRONE_ENV_PLUGIN_SECRET"

_EXPAND = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}")


class ConfigError(Exception):
    """Raised when the config file is missing, malformed, or incomplete."""


WOODPECKER_KEY_AGE_ENV = "WOODPECKER_SECRET_AGE_SECONDS"


@dataclass
class Woodpecker:
    """Serve Woodpecker's secret extension alongside Drone's environment extension.

    Woodpecker signs with an ed25519 key pair rather than a shared secret, so what is
    configured here is its *public* key — either a PEM on disk, or the URL of the
    server's /api/signature/public-key endpoint.
    """

    path: str = "/secrets"
    public_key_file: str | None = None
    public_key_url: str | None = None
    token: str | None = None
    # Reject a signature whose `created` is older than this — the replay window.
    max_age: int = 300
    # Re-fetch the public key when it is older than this on an incoming request, so a
    # Woodpecker key rotation is picked up without restarting the extension. Also
    # refreshable on demand via the refresh-key endpoint.
    key_max_age: int = 300


@dataclass
class DroneSecret:
    """Serve Drone's *secret* extension too, so a step can ask for a named secret with
    `from_secret` instead of every plugin variable being injected into every step.

    Drone signs the secret extension the same way as the environment extension (HMAC
    draft-cavage), so the shared secret defaults to the same one; set it here only if
    the runner uses a different DRONE_SECRET_PLUGIN_TOKEN.
    """

    path: str = "/secret"
    secret: str | None = None


@dataclass
class Config:
    secret: str
    host: str = "0.0.0.0"
    port: int = 3000
    log_level: str = "INFO"
    max_clock_skew: int = 300
    # Cap on simultaneous in-flight requests, passed to uvicorn. Anything over this is
    # shed with a 503 rather than piling up unbounded work from an unauthenticated
    # client. Real load is one request per build step.
    limit_concurrency: int = 256
    # A plugin that errors is usually one that failed to fetch a credential the
    # build needs; running the build without it silently is worse than failing.
    on_plugin_error: str = "fail"
    plugin_paths: list[Path] = field(default_factory=list)
    plugins: dict[str, dict] = field(default_factory=dict)
    woodpecker: Woodpecker | None = None
    drone_secret: DroneSecret | None = None


def _expand(value) -> Any:
    """Expand ${VAR} and ${VAR:-default} so secrets stay out of the config file."""
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match):
        name, fallback = match.group(1), match.group(2)
        found = os.environ.get(name)
        if found is None and fallback is None:
            raise ConfigError(f"${{{name}}} is referenced in the config but is not set")
        return found if found is not None else fallback

    return _EXPAND.sub(replace, value)


def load(path) -> Config:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file {path} does not exist")

    raw: Any = _expand(yaml.safe_load(path.read_text()) or {})
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a mapping")

    server = raw.get("server") or {}
    secret = server.get("secret") or os.environ.get(SECRET_ENV)
    if not secret:
        raise ConfigError(
            f"no shared secret: set server.secret in {path} or ${SECRET_ENV}. "
            "It must match DRONE_ENV_PLUGIN_TOKEN on the Drone runner."
        )

    on_plugin_error = server.get("on_plugin_error", "fail")
    if on_plugin_error not in ("fail", "skip"):
        raise ConfigError(
            f"server.on_plugin_error must be 'fail' or 'skip', got {on_plugin_error!r}"
        )

    # Validate the log level here, not deep inside logging.basicConfig, where a typo
    # would surface as an obscure error after the config has otherwise loaded.
    log_level = str(server.get("log_level", "INFO")).upper()
    if log_level not in logging.getLevelNamesMapping():
        raise ConfigError(
            f"server.log_level {log_level!r} is not a known level: one of "
            f"{', '.join(sorted(logging.getLevelNamesMapping()))}"
        )

    plugins = raw.get("plugins") or {}
    if not isinstance(plugins, dict):
        raise ConfigError("plugins must be a mapping of plugin name to its settings")
    # `stdout:` with nothing under it is a natural way to enable a plugin that
    # needs no settings, and YAML parses that as None.
    plugins = {name: (settings or {}) for name, settings in plugins.items()}

    woodpecker = None
    if raw.get("woodpecker"):
        settings = raw["woodpecker"]
        if not isinstance(settings, dict):
            raise ConfigError(
                "woodpecker must be a mapping of settings (path, public_key_file, "
                f"public_key_url, token, max_age), got {type(settings).__name__}"
            )
        if settings.get("public_key_file") and settings.get("public_key_url"):
            raise ConfigError(
                "woodpecker has both public_key_file and public_key_url set; give one. "
                "The file would silently win, so which key verifies requests would not "
                "match what the config appears to say."
            )
        if not (settings.get("public_key_file") or settings.get("public_key_url")):
            raise ConfigError(
                "woodpecker needs public_key_file or public_key_url: the extension "
                "verifies Woodpecker's signature with the server's ed25519 public key, "
                "served at <woodpecker>/api/signature/public-key"
            )
        # The key-refresh interval defaults from the environment, then a literal 300s.
        key_max_age = settings.get("key_max_age")
        if key_max_age is None:
            key_max_age = os.environ.get(WOODPECKER_KEY_AGE_ENV, 300)
        woodpecker = Woodpecker(
            path=settings.get("path", "/secrets"),
            public_key_file=settings.get("public_key_file"),
            public_key_url=settings.get("public_key_url"),
            token=settings.get("token"),
            max_age=int(settings.get("max_age", 300)),
            key_max_age=int(key_max_age),
        )

    drone_secret = None
    if raw.get("drone_secret"):
        ds = raw["drone_secret"]
        if not isinstance(ds, dict):
            raise ConfigError(
                f"drone_secret must be a mapping (path, secret), got {type(ds).__name__}"
            )
        drone_secret = DroneSecret(
            path=ds.get("path", "/secret"),
            secret=ds.get("secret"),
        )
        if woodpecker and woodpecker.path == drone_secret.path:
            raise ConfigError(
                f"woodpecker and drone_secret both use the path {drone_secret.path!r}, "
                "but they speak different protocols; give them distinct paths"
            )

    return Config(
        secret=secret,
        woodpecker=woodpecker,
        drone_secret=drone_secret,
        host=server.get("host", "0.0.0.0"),
        port=int(server.get("port", 3000)),
        log_level=log_level,
        max_clock_skew=int(server.get("max_clock_skew", 300)),
        limit_concurrency=int(server.get("limit_concurrency", 256)),
        on_plugin_error=on_plugin_error,
        plugin_paths=[Path(p).expanduser() for p in (raw.get("plugin_paths") or [])],
        plugins=plugins,
    )
