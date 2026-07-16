import functools
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

import anyio.to_thread
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from ci_pluggable_secrets_extension import plugins, rfc9421, woodpecker
from ci_pluggable_secrets_extension.config import ConfigError
from ci_pluggable_secrets_extension.models import EnvironRequest, SecretRequest, Variable
from ci_pluggable_secrets_extension.signature import SignatureError, verify

ENVIRONMENT_HOOK = "environment"
ROUTES_HOOK = "routes"

# Real requests are a few KB. Anything past this is buffered into memory before a
# signature can be checked, so cap it and reject before reading a byte more.
MAX_BODY_BYTES = 1024 * 1024


class BodyTooLarge(Exception):
    def __init__(self, size):
        self.size = size


async def read_limited_body(request: Request, limit: int = MAX_BODY_BYTES) -> bytes:
    """Buffer the body, refusing to grow past `limit`.

    The body is read before the signature is verified — it has to be, since the
    signature covers it — so an unauthenticated client controls how much memory this
    allocates. A declared Content-Length is rejected up front; a chunked body (no
    length, or a lying one) is caught as it streams.
    """
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge(int(declared))

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge(total)
        chunks.append(chunk)
    return b"".join(chunks)


def normalise(plugin_name, result) -> list[Variable]:
    """Turn whatever a plugin returned into the variables Drone expects.

    Plugins may return the simple `{"name": "value"}` form, the expanded
    `{"name": {"data": ..., "mask": True}}` form for secrets, or a list of
    already-built Variables.
    """
    if result is None:
        return []
    if isinstance(result, Variable):
        return [result]
    if isinstance(result, list):
        return [
            item if isinstance(item, Variable) else Variable(**item)
            for item in result
        ]
    if not isinstance(result, dict):
        raise TypeError(
            f"Plugin {plugin_name} returned {type(result).__name__}, "
            "expected a dict, a list, or None"
        )

    variables = []
    for name, value in result.items():
        if isinstance(value, dict):
            variables.append(Variable(name=name, **value))
        else:
            # Variable.data coerces to str, so the flat and expanded forms agree.
            variables.append(Variable(name=name, data=value))
    return variables


def combine(results) -> list[Variable]:
    """Merge every plugin's contribution into one response, config order winning."""
    merged: dict[str, Variable] = {}
    for plugin_name, result in results.items():
        for variable in normalise(plugin_name, result):
            if variable.name in merged:
                logging.warning(
                    "Plugin %s overrides the variable %s set by an earlier plugin",
                    plugin_name, variable.name,
                )
            merged[variable.name] = variable
    return list(merged.values())


# The action names Drone/Woodpecker use, normalised to the short forms an operator reads
# in a log line. Everything else passes through as-is.
_NORMALISED_ACTION = {
    "pull_request": "pr",
    "pull_request_closed": "pr",
}


def normalised_action(event: str) -> str:
    return _NORMALISED_ACTION.get(event, event or "unknown")


def log_fired(log, results, payload, stage="-", step="-") -> None:
    """One INFO line per handled request: which plugins fired, and in what build context.

    Stage and step are not carried by Drone's or Woodpecker's extension protocols (the
    request is repo+build only), so they are logged as "-" unless a caller has them.
    """
    fired = [name for name, result in results.items() if result]
    build, repo = payload.build, payload.repo
    log.info(
        "%s fired in the context of %s/%s/%s/%s at %s due to %s",
        ", ".join(fired) or "no plugins",
        repo.slug or f"{repo.namespace}/{repo.name}" or "-",
        build.number, stage, step,
        build.ref or build.after or "-",
        normalised_action(build.event),
    )


def load_woodpecker_key(settings, attempts=5, backoff=2.0):
    """Woodpecker's ed25519 public key, from disk or from the server itself.

    Fetching from the server is retried: a brief Woodpecker outage during a rollout
    should not crash-loop the extension's boot. Note the key is read once, at startup —
    if Woodpecker rotates its key the extension must be restarted (see the README).
    """
    if settings.public_key_file:
        return rfc9421.load_public_key(Path(settings.public_key_file).read_bytes())

    request = urllib.request.Request(settings.public_key_url)
    if settings.token:
        request.add_header("Authorization", f"Bearer {settings.token}")

    log = logging.getLogger("ci_pluggable_secrets_extension")
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return rfc9421.load_public_key(response.read())
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt < attempts:
                wait = backoff * attempt
                log.warning(
                    "Could not fetch Woodpecker's public key from %s (attempt %d/%d): "
                    "%s; retrying in %.0fs",
                    settings.public_key_url, attempt, attempts, exc, wait,
                )
                time.sleep(wait)
    raise ConfigError(
        f"could not fetch Woodpecker's public key from {settings.public_key_url} "
        f"after {attempts} attempts: {last_error}"
    )


class WoodpeckerKey:
    """Woodpecker's public key, cached with its age, and re-fetched when it goes stale.

    Woodpecker's key can rotate. Rather than only reading it at startup, this refreshes
    it lazily: when a `/secrets` request arrives and the cached key is older than
    `key_max_age`, it is re-loaded first. It can also be refreshed on demand through the
    refresh-key endpoint. A refresh that fails keeps the last good key — better stale
    than dead — so a Woodpecker blip does not take the endpoint down.
    """

    def __init__(self, settings):
        self.settings = settings
        self.log = logging.getLogger("ci_pluggable_secrets_extension")
        self.key = load_woodpecker_key(settings)
        self.fetched_at = time.time()

    def refresh(self):
        self.key = load_woodpecker_key(self.settings)
        self.fetched_at = time.time()
        self.log.info("Refreshed Woodpecker's public key")
        return self.key

    @property
    def age(self) -> float:
        return time.time() - self.fetched_at

    def current(self, max_age):
        """The key, refreshed first if it is older than `max_age` (0 disables)."""
        if max_age and self.age > max_age:
            try:
                self.refresh()
            except ConfigError as exc:
                self.log.warning(
                    "Could not refresh Woodpecker's public key (%.0fs old); keeping the "
                    "cached one: %s", self.age, exc,
                )
        return self.key


def create_app(config, registry=None) -> FastAPI:
    app = FastAPI(title="CI environment extension", version="0.1.0")
    log = logging.getLogger("ci_pluggable_secrets_extension")

    # The plugins this app serves. Held on app.state so a second app built in the same
    # process has its own set rather than sharing this one's. Defaults to the process
    # registry, which cli.py loads before calling here.
    registry = registry if registry is not None else plugins.default_registry
    app.state.registry = registry

    # A plugin may need endpoints of its own — a plugin issuing signed tokens has to
    # publish the key that verifies them somewhere. These are unauthenticated, so a
    # plugin must only expose public material here.
    registry.run_hook(ROUTES_HOOK, app, on_error="fail")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "plugins": [p.describe() for p in registry.plugins.values()]}

    if config.woodpecker:
        mount_woodpecker(app, config, log, registry)

    if config.drone_secret:
        mount_drone_secret(app, config, log, registry)

    @app.post("/")
    async def environment(request: Request) -> Response:
        try:
            body = await read_limited_body(request)
        except BodyTooLarge as exc:
            log.warning("Rejected oversized request from %s: %d bytes", request.client, exc.size)
            return JSONResponse({"message": "request body too large"}, status_code=413)

        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"

        try:
            verify(
                config.secret,
                request.method,
                target,
                dict(request.headers),
                body,
                config.max_clock_skew,
            )
        except SignatureError as exc:
            log.warning("Rejected request from %s: %s", request.client, exc)
            # Drone treats any non-200 as an extension failure; 400 matches what
            # drone-go's own handler returns for a bad signature.
            return JSONResponse({"message": str(exc)}, status_code=400)

        payload = EnvironRequest.model_validate_json(body)

        try:
            # Plugins are synchronous and may block (RSA signing, network I/O); run
            # them in a worker thread so one build cannot stall the event loop and the
            # /healthz liveness probe behind it.
            results = await anyio.to_thread.run_sync(
                functools.partial(
                    registry.run_hook,
                    ENVIRONMENT_HOOK, payload, on_error=config.on_plugin_error,
                )
            )
        except Exception as exc:
            log.error("Failing the request because a plugin errored: %s", exc)
            return JSONResponse({"message": "plugin error"}, status_code=500)

        variables = combine(results)
        log_fired(log, results, payload)
        log.info(
            "Returning %d variable(s): %s",
            len(variables), ", ".join(v.name for v in variables) or "none",
        )
        return JSONResponse([v.to_environment() for v in variables])

    return app


def mount_woodpecker(app, config, log, registry):
    """Serve Woodpecker's secret extension from the same plugins.

    Woodpecker asks a different question in a different dialect, but the answer comes
    from the same place: the plugins' `environment` hook, which never learns which CI
    system asked.
    """
    settings = config.woodpecker
    key = WoodpeckerKey(settings)

    @app.post(settings.path)
    async def secrets(request: Request) -> Response:
        try:
            body = await read_limited_body(request)
        except BodyTooLarge as exc:
            log.warning("Rejected oversized Woodpecker request from %s: %d bytes",
                        request.client, exc.size)
            return JSONResponse({"message": "request body too large"}, status_code=413)

        # The path, not the full URL: Woodpecker signs @request-target, which RFC 9421
        # defines as the request target alone.
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"

        # Re-fetch the key if it has gone stale, so a Woodpecker key rotation is picked
        # up without a restart. Off the event loop, since a refresh may do network I/O.
        public_key = await anyio.to_thread.run_sync(key.current, settings.key_max_age)

        try:
            rfc9421.verify(
                public_key,
                request.method,
                target,
                dict(request.headers),
                body,
                settings.max_age,
            )
        except SignatureError as exc:
            log.warning("Rejected Woodpecker request from %s: %s", request.client, exc)
            return JSONResponse({"message": str(exc)}, status_code=401)

        incoming = woodpecker.WoodpeckerRequest.model_validate_json(body)
        payload = woodpecker.to_request(incoming)

        try:
            results = await anyio.to_thread.run_sync(
                functools.partial(
                    registry.run_hook,
                    ENVIRONMENT_HOOK, payload, on_error=config.on_plugin_error,
                )
            )
        except Exception as exc:
            log.error("Failing the request because a plugin errored: %s", exc)
            return JSONResponse({"message": "plugin error"}, status_code=500)

        variables = combine(results)
        log_fired(log, results, payload)
        if not variables:
            # Woodpecker's way of saying "add nothing", leaving its own secrets alone.
            # Logged so an operator can tell "no plugin contributed" apart from a request
            # that never arrived.
            log.info(
                "No variables for Woodpecker pipeline %s (%s event); returning 204",
                incoming.pipeline.number, incoming.pipeline.event,
            )
            return Response(status_code=204)

        # Scoped to this pipeline's *native* event: the mapped name means nothing to
        # Woodpecker, and it rejects a secret that names no event at all.
        secrets = woodpecker.to_secrets(variables, incoming.pipeline.event)
        log.info(
            "Returning %d secret(s) for the %s event: %s",
            len(secrets), incoming.pipeline.event,
            ", ".join(secret.name for secret in secrets),
        )
        return JSONResponse({"secrets": [secret.model_dump() for secret in secrets]})

    refresh_path = settings.path.rstrip("/") + "/refresh-key"

    @app.post(refresh_path)
    async def refresh_key() -> Response:
        """Force a re-fetch of Woodpecker's public key, e.g. right after it rotates.
        Only ever reloads public material from the configured source."""
        try:
            await anyio.to_thread.run_sync(key.refresh)
        except ConfigError as exc:
            log.warning("On-demand Woodpecker key refresh failed: %s", exc)
            return JSONResponse({"status": "error", "message": str(exc)}, status_code=502)
        return {"status": "ok", "key_age_seconds": round(key.age, 1)}

    log.info(
        "Serving Woodpecker's secret extension at POST %s (key refresh at POST %s)",
        settings.path, refresh_path,
    )


def mount_drone_secret(app, config, log, registry):
    """Serve Drone's *secret* extension from the same plugins.

    Where the environment extension injects every variable into every step, the secret
    extension answers a step's `from_secret: NAME` with just that one secret — so a
    pipeline is explicit about which secrets it pulls, and each carries drone.Secret's
    per-secret pull-request gating. Same plugins, same HMAC signature as the environment
    extension; the plugins never learn which endpoint asked.
    """
    settings = config.drone_secret
    secret = settings.secret or config.secret

    @app.post(settings.path)
    async def drone_secret(request: Request) -> Response:
        try:
            body = await read_limited_body(request)
        except BodyTooLarge as exc:
            log.warning("Rejected oversized secret request from %s: %d bytes",
                        request.client, exc.size)
            return JSONResponse({"message": "request body too large"}, status_code=413)

        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"

        try:
            verify(secret, request.method, target, dict(request.headers),
                   body, config.max_clock_skew)
        except SignatureError as exc:
            log.warning("Rejected secret request from %s: %s", request.client, exc)
            # 400 is what drone-go's own secret handler returns for a bad signature.
            return JSONResponse({"message": str(exc)}, status_code=400)

        incoming = SecretRequest.model_validate_json(body)
        payload = EnvironRequest(repo=incoming.repo, build=incoming.build)

        try:
            results = await anyio.to_thread.run_sync(
                functools.partial(
                    registry.run_hook,
                    ENVIRONMENT_HOOK, payload, on_error=config.on_plugin_error,
                )
            )
        except Exception as exc:
            log.error("Failing the request because a plugin errored: %s", exc)
            return JSONResponse({"message": "plugin error"}, status_code=500)

        variables = combine(results)
        log_fired(log, results, payload)

        match = next((v for v in variables if v.name == incoming.name), None)
        if match is None:
            # 404 is how Drone's secret handler signals "no such secret", leaving the
            # build's `from_secret` unresolved.
            log.info(
                "No secret named %r for %s #%s; returning 404",
                incoming.name, payload.repo.slug, payload.build.number,
            )
            return JSONResponse(
                {"message": f"no secret named {incoming.name!r}"}, status_code=404
            )

        log.info(
            "Serving secret %r to %s #%s (pull_request=%s)",
            match.name, payload.repo.slug, payload.build.number, match.pull_request,
        )
        return JSONResponse(match.to_drone_secret())

    log.info("Serving Drone's secret extension at POST %s", settings.path)
