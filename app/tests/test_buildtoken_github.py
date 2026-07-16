"""The default claims mirror GitHub Actions' OIDC token, so that a service which
already verifies GitHub's tokens needs a new issuer and key — not a new policy."""

import jwt
import pytest

from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.server import normalise
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken

ISSUER = "https://drone-environ.example.com"
AUDIENCE = "https://drone.example.com/droneadmin"

REPO = Repo(
    id=1,
    uid="74",
    user_id=1,
    namespace="octo-org",
    name="octo-repo",
    slug="octo-org/octo-repo",
    visibility="private",
    private=True,
)


def plugin(**settings):
    configured = BuildToken()
    configured.configure({
        "issuer": ISSUER, "audience": AUDIENCE, "allow_ephemeral_key": True, **settings,
    })
    return configured


def claims(configured, **build):
    result = configured.hook_environment(EnvironRequest(repo=REPO, build=Build(**build)))
    token = normalise("buildtoken", result)[0].data
    return jwt.decode(
        token, configured.signing["public"], algorithms=["RS256", "ES256"],
        audience=AUDIENCE, issuer=ISSUER,
    )


def test_a_promotion_looks_like_a_github_deployment_token():
    token = claims(
        plugin(),
        id=1234, number=10, event="promote", deploy_to="prod",
        ref="refs/heads/main", after="example-sha", sender="octocat",
    )

    assert token["sub"] == "repo:octo-org/octo-repo:environment:prod"
    assert token["environment"] == "prod"
    assert token["repository"] == "octo-org/octo-repo"
    assert token["repository_owner"] == "octo-org"
    assert token["repository_id"] == "74"
    assert token["repository_visibility"] == "private"
    assert token["actor"] == "octocat"
    assert token["event_name"] == "promote"
    assert token["ref"] == "refs/heads/main"
    assert token["ref_type"] == "branch"
    assert token["sha"] == "example-sha"
    assert token["run_id"] == "1234"
    assert token["run_number"] == "10"
    assert token["runner_environment"] == "self-hosted"
    assert token["aud"] == AUDIENCE
    assert token["iss"] == ISSUER
    assert {"jti", "iat", "nbf", "exp"} <= set(token)


def test_numbers_are_strings_as_they_are_in_githubs_token():
    token = claims(plugin(), id=1234, number=10, event="push", ref="refs/heads/main")
    assert token["run_id"] == "1234"
    assert token["run_number"] == "10"

    # ...but the time claims must stay numeric, or no verifier will accept them.
    assert isinstance(token["iat"], int)
    assert isinstance(token["exp"], int)


def test_numbers_can_be_left_numeric():
    token = claims(
        plugin(numbers_as_strings=False),
        id=1234, number=10, event="push", ref="refs/heads/main",
    )
    assert token["run_id"] == 1234


def test_a_tag_build_says_so():
    token = claims(plugin(), event="tag", ref="refs/tags/v1.2.3")
    assert token["ref_type"] == "tag"
    assert token["sub"] == "repo:octo-org/octo-repo:ref:refs/tags/v1.2.3"


def test_a_pull_request_carries_head_and_base_like_github():
    token = claims(
        plugin(),
        event="pull_request", ref="refs/pull/42/head",
        source="feature-branch", target="main",
    )
    assert token["sub"] == "repo:octo-org/octo-repo:pull_request"
    assert token["head_ref"] == "feature-branch"
    assert token["base_ref"] == "main"


def test_a_push_has_no_head_or_base_ref():
    """Drone fills source/target on every event; GitHub only has them on a pull
    request. Asserting a head_ref for a push would mislead a policy written against
    GitHub's meaning of the claim."""
    token = claims(plugin(), event="push", ref="refs/heads/main",
                   source="main", target="main")

    assert "head_ref" not in token
    assert "base_ref" not in token
    assert token["sub"] == "repo:octo-org/octo-repo:ref:refs/heads/main"


def test_a_push_has_no_environment():
    token = claims(plugin(), event="push", ref="refs/heads/main")
    assert "environment" not in token


def test_claims_with_no_drone_equivalent_are_absent_rather_than_guessed():
    """A claim that means almost-the-same-thing is worse than no claim: a verifier
    will write policy against it."""
    token = claims(plugin(), event="push", ref="refs/heads/main")
    for absent in ("actor_id", "repository_owner_id", "run_attempt", "workflow",
                   "job_workflow_ref"):
        assert absent not in token


def test_extra_claims_merge_over_the_github_defaults():
    token = claims(
        plugin(claims={"deployment_reason": "build.params.REASON",
                       "actor": "build.author_login"}),
        event="promote", deploy_to="prod", sender="the-bot",
        author_login="octocat", params={"REASON": "hotfix"},
    )
    assert token["deployment_reason"] == "hotfix"
    assert token["actor"] == "octocat"          # the override won
    assert token["repository"] == "octo-org/octo-repo"   # the defaults survived


def test_a_default_claim_can_be_dropped():
    token = claims(plugin(claims={"runner_environment": None}),
                   event="push", ref="refs/heads/main")
    assert "runner_environment" not in token
    assert "repository" in token


def test_the_github_defaults_can_be_turned_off_entirely():
    token = claims(
        plugin(default_claims="none", claims={"repo.slug": "repo.slug"}),
        event="push", ref="refs/heads/main",
    )
    assert token["repo.slug"] == "octo-org/octo-repo"
    assert "repository" not in token
    assert "runner_environment" not in token


def test_the_subject_can_still_be_overridden():
    token = claims(
        plugin(subject="drone:{repo.slug}:{build.event}"),
        event="promote", deploy_to="prod",
    )
    assert token["sub"] == "drone:octo-org/octo-repo:promote"


@pytest.mark.parametrize("event,expected", [
    ("push", "repo:octo-org/octo-repo:ref:refs/heads/main"),
    ("cron", "repo:octo-org/octo-repo:ref:refs/heads/main"),
])
def test_the_subject_falls_back_to_the_ref(event, expected):
    assert claims(plugin(), event=event, ref="refs/heads/main")["sub"] == expected
