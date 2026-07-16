import pytest

from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo, Variable
from ci_pluggable_secrets_extension.server import combine, normalise

from .conftest import load_example_plugin

# deploytarget is an example plugin (docs/sample_plugins/), not part of the package;
# load it the way an operator's drop-in plugin would be loaded.
DeployTarget = load_example_plugin("deploytarget")

TARGETS = {
    "production": {
        "DEPLOY_URL": "https://prod.example.com",
        "DEPLOY_TOKEN": {"data": "prod-token", "mask": True},
    },
    "staging": {"DEPLOY_URL": "https://staging.example.com"},
}


def plugin(**settings):
    configured = DeployTarget()
    configured.configure({"targets": TARGETS, **settings})
    return configured


def request(**build):
    return EnvironRequest(repo=Repo(slug="octocat/hello-world"), build=Build(**build))


def test_a_push_gets_no_deploy_variables():
    assert plugin().hook_environment(request(event="push", number=1)) is None


def test_a_promotion_gets_its_target_variables():
    result = plugin().hook_environment(
        request(event="promote", deploy_to="production", number=2, sender="jon")
    )
    assert result == {
        "DEPLOY_URL": "https://prod.example.com",
        "DEPLOY_TOKEN": {"data": "prod-token", "mask": True},
        "DEPLOY_TARGET": "production",
    }


def test_the_secret_is_masked_but_the_url_is_not():
    result = plugin().hook_environment(request(event="promote", deploy_to="production"))
    variables = {v.name: v for v in normalise("deploytarget", result)}

    assert variables["DEPLOY_TOKEN"].mask is True
    assert variables["DEPLOY_TOKEN"].data == "prod-token"
    assert variables["DEPLOY_URL"].mask is False


def test_targets_do_not_leak_into_each_other():
    result = plugin().hook_environment(request(event="promote", deploy_to="staging"))
    assert result["DEPLOY_URL"] == "https://staging.example.com"
    assert "DEPLOY_TOKEN" not in result


def test_an_unknown_target_gets_nothing(caplog):
    result = plugin().hook_environment(request(event="promote", deploy_to="mars", number=3))
    assert result is None
    assert "unknown target 'mars'" in caplog.text


def test_a_rollback_counts_as_a_promotion():
    result = plugin().hook_environment(request(event="rollback", deploy_to="production"))
    assert result["DEPLOY_TARGET"] == "production"


def test_require_promote_off_still_needs_a_deploy_target():
    configured = plugin(require_promote=False)
    assert configured.hook_environment(request(event="push")) is None
    assert configured.hook_environment(
        request(event="custom", deploy_to="staging")
    )["DEPLOY_TARGET"] == "staging"


def test_both_plugins_merge_into_one_response():
    """What Drone actually receives when stdout and deploytarget are both enabled."""
    merged = combine({
        "stdout": {"stdout_plugin": "enabled"},
        "deploytarget": plugin().hook_environment(
            request(event="promote", deploy_to="production")
        ),
    })
    assert merged == [
        Variable(name="stdout_plugin", data="enabled"),
        Variable(name="DEPLOY_URL", data="https://prod.example.com"),
        Variable(name="DEPLOY_TOKEN", data="prod-token", mask=True),
        Variable(name="DEPLOY_TARGET", data="production"),
    ]


@pytest.mark.parametrize("event", ["push", "pull_request", "cron", "tag"])
def test_no_event_other_than_a_promotion_sees_production(event):
    """The whole point: the extension runs on every build, but only a promotion pays out."""
    assert plugin().hook_environment(request(event=event, deploy_to="production")) is None
