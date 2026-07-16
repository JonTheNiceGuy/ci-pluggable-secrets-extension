"""The settings follow GitHub's OIDC model: the subject is composed from
include_claim_keys, the audience defaults to the repository owner, and verifiers find
the keys through an OIDC discovery document.

https://docs.github.com/en/actions/reference/security/oidc
"""

import jwt
import pytest

from ci_pluggable_secrets_plugin import PluginConfigError
from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.server import normalise
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken

ISSUER = "https://drone-environ.example.com"

REPO = Repo(
    uid="74",
    namespace="octo-org",
    name="octo-repo",
    slug="octo-org/octo-repo",
    link="https://github.example.com/octo-org/octo-repo",
    visibility="private",
)


def plugin(**settings):
    configured = BuildToken()
    configured.configure({"issuer": ISSUER, "allow_ephemeral_key": True, **settings})
    return configured


def claims(configured, **build):
    result = configured.hook_environment(EnvironRequest(repo=REPO, build=Build(**build)))
    token = normalise("buildtoken", result)[0].data
    return jwt.decode(
        token, configured.public_key, algorithms=["RS256", "ES256"],
        options={"verify_aud": False}, issuer=ISSUER,
    )


# --- the subject, composed from include_claim_keys ----------------------------

def test_the_default_subject_is_githubs_for_a_deployment():
    token = claims(plugin(), event="promote", deploy_to="Production")
    assert token["sub"] == "repo:octo-org/octo-repo:environment:Production"


def test_the_default_subject_is_githubs_for_a_pull_request():
    token = claims(plugin(), event="pull_request", ref="refs/pull/1/head")
    assert token["sub"] == "repo:octo-org/octo-repo:pull_request"


def test_the_default_subject_is_githubs_for_a_branch():
    token = claims(plugin(), event="push", ref="refs/heads/demo-branch")
    assert token["sub"] == "repo:octo-org/octo-repo:ref:refs/heads/demo-branch"


def test_the_default_subject_is_githubs_for_a_tag():
    token = claims(plugin(), event="tag", ref="refs/tags/demo-tag")
    assert token["sub"] == "repo:octo-org/octo-repo:ref:refs/tags/demo-tag"


def test_the_subject_can_be_composed_from_any_claims():
    token = claims(
        plugin(include_claim_keys=["repo", "event_name", "actor"]),
        event="promote", deploy_to="prod", sender="octocat",
    )
    assert token["sub"] == "repo:octo-org/octo-repo:event_name:promote:actor:octocat"


def test_a_narrow_subject_can_pin_deployments_to_one_environment():
    """What you would actually hand a cloud provider to scope a role to production."""
    token = claims(
        plugin(include_claim_keys=["repo", "environment"]),
        event="promote", deploy_to="production",
    )
    assert token["sub"] == "repo:octo-org/octo-repo:environment:production"


def test_a_custom_claim_can_compose_the_subject():
    token = claims(
        plugin(claims={"team": "build.params.TEAM"},
               include_claim_keys=["repo", "team"]),
        event="promote", deploy_to="prod", params={"TEAM": "platform"},
    )
    assert token["sub"] == "repo:octo-org/octo-repo:team:platform"


def test_an_empty_claim_does_not_leave_a_dangling_separator():
    token = claims(
        plugin(include_claim_keys=["repo", "environment"]),
        event="push", ref="refs/heads/main",   # a push has no environment
    )
    assert token["sub"] == "repo:octo-org/octo-repo"


def test_a_colon_in_a_value_is_escaped():
    """A subject is matched by string comparison, so a colon inside a value must not
    look like the separator between segments."""
    token = claims(
        plugin(include_claim_keys=["repo", "environment"]),
        event="promote", deploy_to="prod:eu-west-1",
    )
    assert token["sub"] == "repo:octo-org/octo-repo:environment:prod%3Aeu-west-1"


def test_a_subject_key_naming_no_claim_is_a_startup_error():
    """Otherwise it silently drops out of the subject, and the only symptom is a
    verifier's policy quietly failing to match."""
    with pytest.raises(PluginConfigError, match="include_claim_keys names enviroment"):
        plugin(include_claim_keys=["repo", "enviroment"])   # typo


def test_a_dropped_claim_cannot_be_used_in_the_subject():
    with pytest.raises(PluginConfigError, match="which no claim provides"):
        plugin(claims={"environment": None}, include_claim_keys=["repo", "environment"])


def test_a_subject_template_still_overrides_everything():
    token = claims(
        plugin(subject="drone:{repo.slug}:{build.event}"),
        event="promote", deploy_to="prod",
    )
    assert token["sub"] == "drone:octo-org/octo-repo:promote"


def test_a_hostile_deploy_to_cannot_loop_the_subject_template():
    """deploy_to is attacker-chosen on a promotion. A resolved value that is itself a
    placeholder must be substituted once and never rescanned, or _interpolate spins
    forever — and, running on the event loop, wedges the whole extension."""
    token = claims(
        plugin(subject="env:{build.deploy_to}"),
        event="promote", deploy_to="{build.deploy_to}",
    )
    assert token["sub"] == "env:{build.deploy_to}"


def test_a_subject_template_escapes_substituted_values():
    """Like the include_claim_keys path, a colon in a substituted value must not read
    as a segment separator."""
    token = claims(
        plugin(subject="env:{build.deploy_to}"),
        event="promote", deploy_to="prod:eu-west-1",
    )
    assert token["sub"] == "env:prod%3Aeu-west-1"


# --- the audience -------------------------------------------------------------

def test_the_audience_defaults_to_the_repository_owner_like_github():
    token = claims(plugin(), event="push", ref="refs/heads/main")
    assert token["aud"] == "https://github.example.com/octo-org"


def test_the_audience_can_be_set():
    token = claims(plugin(audience="sts.amazonaws.com"), event="push")
    assert token["aud"] == "sts.amazonaws.com"


def test_the_audience_can_be_a_list():
    token = claims(plugin(audience=["a", "b"]), event="push")
    assert token["aud"] == ["a", "b"]


# --- discovery ----------------------------------------------------------------

def test_the_discovery_document_points_at_the_keys():
    document = plugin().discovery()

    assert document["issuer"] == ISSUER
    assert document["jwks_uri"] == f"{ISSUER}/.well-known/jwks"
    assert document["response_types_supported"] == ["id_token"]
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]
    assert document["scopes_supported"] == ["openid"]


def test_the_discovery_document_advertises_every_claim_it_may_issue():
    supported = plugin().discovery()["claims_supported"]

    for claim in ("sub", "aud", "iss", "exp", "iat", "nbf", "jti"):
        assert claim in supported
    for claim in ("repository", "repository_owner", "actor", "event_name", "ref",
                  "ref_type", "sha", "environment", "run_id", "run_number"):
        assert claim in supported


def test_a_custom_claim_is_advertised_too():
    supported = plugin(claims={"team": "build.params.TEAM"}).discovery()["claims_supported"]
    assert "team" in supported


def test_the_discovery_document_follows_a_moved_jwks_path():
    document = plugin(jwks_path="/keys").discovery()
    assert document["jwks_uri"] == f"{ISSUER}/keys"


def test_the_advertised_algorithms_cover_every_published_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    for name, key in (
        ("a-rsa.pem", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("b-ec.pem", ec.generate_private_key(ec.SECP256R1())),
    ):
        (tmp_path / name).write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    document = plugin(key_dir=str(tmp_path)).discovery()
    assert document["id_token_signing_alg_values_supported"] == ["ES256", "RS256"]
