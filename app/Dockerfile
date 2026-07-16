# Reproducible build from the frozen uv.lock, so a bad upstream release cannot ship
# itself into this image. uv comes from its own published image rather than being
# pip-installed, and dependencies are installed before the source so the (large, slow,
# rarely-changing) dependency layer is cached across source edits.
FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy mode (not hardlink) because the cache and the venv are on different layers, and
# bytecode-compile on install so first-request latency is not paid at runtime.
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

WORKDIR /app

# Dependencies only, from the lockfile — cached until pyproject.toml or uv.lock changes.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Then the source and the project itself.
COPY ci_pluggable_secrets_extension ./ci_pluggable_secrets_extension
COPY ci_pluggable_secrets_plugin ./ci_pluggable_secrets_plugin
RUN uv sync --frozen --no-dev

# Run as an unprivileged user, not root.
RUN useradd --system --uid 10001 appuser
USER appuser

# Drop-in plugins and the config live here; mount over them to add your own.
VOLUME /etc/drone-environ

# The default port from ci_pluggable_secrets_extension/config.py. A deployment that sets server.port
# to something else should publish that port instead — EXPOSE is documentation only.
EXPOSE 3000

# The console script from the venv directly — no uv, no writes, at runtime.
ENTRYPOINT ["/app/.venv/bin/ci-pluggable-secrets-extension", \
            "--config", "/etc/drone-environ/config.yaml"]
CMD ["serve"]
