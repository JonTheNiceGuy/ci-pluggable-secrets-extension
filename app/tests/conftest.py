import json
from pathlib import Path

import pytest

from ci_pluggable_secrets_extension import config as configuration
from ci_pluggable_secrets_extension import plugins

SECRET = "correct-horse-battery-staple"

# The example plugins (stdout, deploytarget) are not part of the installed package;
# they live here and are loaded via plugin_paths, exactly as an operator would drop in
# their own. Tests that need one point plugin_paths here or load it through the loader.
# app/tests -> app -> repo root; the sample plugins live under docs/ now.
REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PLUGINS = REPO_ROOT / "docs" / "sample_plugins"


def load_example_plugin(name):
    """Load an example plugin's class the way the loader does at runtime, so a test
    exercises the same module (ci_environ_plugins.<name>) production would."""
    module = plugins._import(name, EXAMPLE_PLUGINS)
    return plugins._plugin_class(module)

BUILD_REQUEST = {
    "repo": {
        "id": 1,
        "namespace": "octocat",
        "name": "hello-world",
        "slug": "octocat/hello-world",
        "scm": "git",
        "default_branch": "main",
        "private": True,
        "trusted": True,
    },
    "build": {
        "id": 42,
        "repo_id": 1,
        "number": 7,
        "status": "pending",
        "event": "push",
        "action": "",
        "ref": "refs/heads/main",
        "target": "main",
        "author_login": "octocat",
        "author_email": "octocat@github.com",
        "message": "a commit",
        "params": {"KEY": "value"},
    },
}


@pytest.fixture
def body() -> bytes:
    return json.dumps(BUILD_REQUEST).encode()


@pytest.fixture
def config(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        f"""
server:
  secret: {SECRET}
  log_level: DEBUG
plugin_paths:
  - {EXAMPLE_PLUGINS}
plugins:
  stdout:
    pretty: false
"""
    )
    loaded = configuration.load(path)
    plugins.load_plugins_and_hooks(loaded)
    yield loaded
    plugins.plugins.clear()
    plugins.hooks.clear()
