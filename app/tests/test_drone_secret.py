"""Drone's secret extension: the same plugins, answering one named secret at a time.

Where the environment extension injects every variable into every step, a step asks the
secret extension for a specific `from_secret: NAME` and gets just that one — with
drone.Secret's per-secret pull-request gating.
"""

import json

import pytest
from fastapi.testclient import TestClient

from ci_pluggable_secrets_extension import plugins
from ci_pluggable_secrets_extension.config import Config, DroneSecret
from ci_pluggable_secrets_extension.server import create_app
from ci_pluggable_secrets_extension.signature import sign

from .conftest import BUILD_REQUEST, SECRET

VAULT_PLUGIN = '''
from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class Vault(BaseEnvironPlugin):
    friendly_name = "vault"

    def hook_environment(self, request):
        return {
            "DEPLOY_TOKEN": {"data": "s3cret", "mask": True},
            # Opts this one into pull-request builds; the default withholds them.
            "PR_TOKEN": {"data": "pr-safe", "mask": True, "pull_request": True},
        }
'''


@pytest.fixture
def app(tmp_path):
    ext = tmp_path / "plugins"
    (ext / "vault").mkdir(parents=True)
    (ext / "vault" / "__init__.py").write_text(VAULT_PLUGIN)

    config = Config(
        secret=SECRET,
        drone_secret=DroneSecret(path="/secret"),
        plugin_paths=[ext],
        plugins={"vault": {}},
    )
    plugins.load_plugins_and_hooks(config)
    yield create_app(config)
    plugins.plugins.clear()
    plugins.hooks.clear()


def ask_for(client, name, secret=SECRET):
    body = json.dumps({"name": name, "path": "", **BUILD_REQUEST}).encode()
    headers = sign(secret, "POST", "/secret", {"Content-Type": "application/json"}, body)
    return client.post("/secret", content=body, headers=headers)


def test_a_named_secret_is_returned_in_the_drone_shape(app):
    response = ask_for(TestClient(app), "DEPLOY_TOKEN")
    assert response.status_code == 200
    assert response.json() == {
        "name": "DEPLOY_TOKEN", "data": "s3cret",
        "pull_request": False, "pull_request_push": False,
    }


def test_a_pull_request_allowed_secret_carries_the_flag(app):
    assert ask_for(TestClient(app), "PR_TOKEN").json()["pull_request"] is True


def test_an_unknown_secret_name_is_a_404(app):
    assert ask_for(TestClient(app), "NO_SUCH_SECRET").status_code == 404


def test_a_badly_signed_secret_request_is_rejected(app):
    assert ask_for(TestClient(app), "DEPLOY_TOKEN", secret="wrong").status_code == 400


def test_an_unsigned_secret_request_is_rejected(app):
    body = json.dumps({"name": "DEPLOY_TOKEN", **BUILD_REQUEST}).encode()
    assert TestClient(app).post("/secret", content=body).status_code == 400
