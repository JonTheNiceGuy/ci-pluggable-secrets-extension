import time

import jwt
import pytest

from ci_pluggable_secrets_plugin import PluginConfigError
from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken
from ci_pluggable_secrets_extension.server import normalise

ISSUER = "https://drone-environ.example.com"
AUDIENCE = "https://deploy.example.com"

CLAIMS = {
    "repo.slug": "repo.slug",
    "build.event": "build.event",
    "build.target": "build.deploy_to",
    "actor": "build.sender",
}


def plugin(**settings):
    configured = BuildToken()
    configured.configure({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "claims": CLAIMS,
        "allow_ephemeral_key": True,
        **settings,
    })
    return configured


def request(**build):
    return EnvironRequest(
        repo=Repo(slug="droneadmin/drone-environ-demo", namespace="droneadmin"),
        build=Build(**build),
    )


def issued(configured, **build):
    """The token the build would actually receive, as a string."""
    result = configured.hook_environment(request(**build))
    variables = normalise("buildtoken", result)
    return {v.name: v for v in variables}


def verify(token, configured, **kwargs):
    """Verify the way a receiving party would: with the public key, and nothing else."""
    return jwt.decode(
        token,
        configured.public_key,
        algorithms=[configured.settings["algorithm"]],
        audience=AUDIENCE,
        issuer=ISSUER,
        **kwargs,
    )


def test_the_receiving_party_can_verify_the_token_with_the_public_key():
    configured = plugin()
    token = issued(configured, event="promote", deploy_to="production", sender="jon")

    claims = verify(token["DRONE_BUILD_TOKEN"].data, configured)

    assert claims["repo.slug"] == "droneadmin/drone-environ-demo"
    assert claims["build.event"] == "promote"
    assert claims["build.target"] == "production"
    assert claims["actor"] == "jon"


def test_the_token_is_masked_because_it_is_a_credential():
    token = issued(plugin(), event="push")
    assert token["DRONE_BUILD_TOKEN"].mask is True


def test_the_standard_claims_are_set():
    configured = plugin(ttl=600)
    token = issued(configured, event="promote", deploy_to="production")

    claims = verify(token["DRONE_BUILD_TOKEN"].data, configured)

    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    # The default subject takes GitHub's shape for a deployment.
    assert claims["sub"] == "repo:droneadmin/drone-environ-demo:environment:production"
    assert claims["exp"] - claims["iat"] == 600
    assert claims["nbf"] <= int(time.time())
    assert claims["jti"]


def test_each_build_gets_a_different_token():
    configured = plugin()
    first = issued(configured, event="push", number=1)["DRONE_BUILD_TOKEN"].data
    second = issued(configured, event="push", number=2)["DRONE_BUILD_TOKEN"].data
    assert first != second

    claims = [verify(t, configured)["jti"] for t in (first, second)]
    assert claims[0] != claims[1]


def test_the_subject_is_a_template_over_the_request():
    configured = plugin(subject="repo:{repo.slug}:target:{build.deploy_to}")
    token = issued(configured, event="promote", deploy_to="production")
    claims = verify(token["DRONE_BUILD_TOKEN"].data, configured)
    assert claims["sub"] == "repo:droneadmin/drone-environ-demo:target:production"


def test_a_claim_list_names_each_claim_after_its_path():
    configured = plugin(claims=["repo.slug", "build.event"])
    token = issued(configured, event="cron")
    claims = verify(token["DRONE_BUILD_TOKEN"].data, configured)
    assert claims["repo.slug"] == "droneadmin/drone-environ-demo"
    assert claims["build.event"] == "cron"


def test_a_nested_path_reaches_into_build_params():
    configured = plugin(claims={"reason": "build.params.REASON"})
    token = issued(configured, event="promote", params={"REASON": "hotfix"})
    assert verify(token["DRONE_BUILD_TOKEN"].data, configured)["reason"] == "hotfix"


def test_a_claim_with_no_matching_path_is_left_out(caplog):
    configured = plugin(claims={"nope": "build.does_not_exist"})
    token = issued(configured, event="push")
    assert "nope" not in verify(token["DRONE_BUILD_TOKEN"].data, configured)
    assert "leaving it out of the token" in caplog.text


def test_an_expired_token_is_rejected():
    configured = plugin(ttl=-1)  # already expired when issued
    token = issued(configured, event="push")
    with pytest.raises(jwt.ExpiredSignatureError):
        verify(token["DRONE_BUILD_TOKEN"].data, configured)


def test_a_token_for_someone_else_is_rejected():
    configured = plugin()
    token = issued(configured, event="push")
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token["DRONE_BUILD_TOKEN"].data,
            configured.public_key,
            algorithms=["RS256"],
            audience="https://not-for-me.example.com",
        )


def test_a_token_signed_by_a_different_key_is_rejected():
    """The forgery case: another extension's key must not verify against ours."""
    ours, theirs = plugin(), plugin()
    forged = issued(theirs, event="promote", deploy_to="production")
    with pytest.raises(jwt.InvalidSignatureError):
        verify(forged["DRONE_BUILD_TOKEN"].data, ours)


def test_the_token_cannot_be_edited_without_breaking_the_signature():
    configured = plugin()
    token = issued(configured, event="push")["DRONE_BUILD_TOKEN"].data


    # A long key, so PyJWT does not (rightly) warn about a weak HMAC secret — the
    # point of the test is that the wrong key fails, not that a short one does.
    tampered = jwt.encode(
        {**jwt.decode(token, options={"verify_signature": False}), "build.event": "promote"},
        "not-the-key-and-certainly-long-enough-to-be-a-real-one",
        algorithm="HS256",
    )
    with pytest.raises(jwt.exceptions.PyJWTError):
        verify(tampered, configured)


def test_the_jwks_endpoint_publishes_only_the_public_half():
    configured = plugin()
    jwks = configured.jwks()

    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert key["kid"] == configured.key_id
    # A private RSA key would carry d/p/q; a public one must not.
    assert not {"d", "p", "q"} & set(key)


def test_a_verifier_can_use_the_jwks_alone():
    """The whole point: given only the published key set, a stranger can verify.

    This is what the receiving party does — match the token's kid against the key
    set, verify with that public key. No shared secret exists anywhere in this test.
    """
    configured = plugin()
    token = issued(configured, event="promote", deploy_to="production")["DRONE_BUILD_TOKEN"].data

    published = jwt.PyJWKSet.from_dict(configured.jwks())
    kid = jwt.get_unverified_header(token)["kid"]
    signing_key = next(key for key in published.keys if key.key_id == kid)

    claims = jwt.decode(
        token, signing_key.key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER
    )
    assert claims["build.target"] == "production"


def test_the_extension_serves_the_key_set_over_http():
    """The routes hook really does mount the endpoint on the running app."""
    from fastapi.testclient import TestClient

    from ci_pluggable_secrets_extension import plugins
    from ci_pluggable_secrets_extension.config import Config
    from ci_pluggable_secrets_extension.server import create_app

    settings = {
        "issuer": ISSUER, "audience": AUDIENCE, "claims": CLAIMS,
        "allow_ephemeral_key": True,
    }
    try:
        plugins.load_plugins_and_hooks({"buildtoken": settings})
        client = TestClient(create_app(Config(secret="irrelevant-here")))

        # GitHub's own paths, so a verifier configured for GitHub finds these too.
        response = client.get("/.well-known/jwks")
        assert response.status_code == 200

        key = response.json()["keys"][0]
        assert key["kty"] == "RSA"
        assert not {"d", "p", "q"} & set(key)

        discovery = client.get("/.well-known/openid-configuration")
        assert discovery.status_code == 200
        assert discovery.json()["jwks_uri"] == f"{ISSUER}/.well-known/jwks"
    finally:
        plugins.plugins.clear()
        plugins.hooks.clear()


def test_es256_works_too():
    configured = plugin(algorithm="ES256")
    token = issued(configured, event="push")["DRONE_BUILD_TOKEN"].data
    assert verify(token, configured)["build.event"] == "push"
    assert configured.jwks()["keys"][0]["kty"] == "EC"


# --- issuance gating (T2-A) ----------------------------------------------------

def test_a_fork_pull_request_gets_no_token_by_default():
    """A fork PR must not receive a token asserting the upstream repository's identity
    — GitHub withholds OIDC from fork PRs, and so does this."""
    configured = plugin()
    result = configured.hook_environment(
        request(event="pull_request", source_repo="attacker/drone-environ-demo", number=1)
    )
    assert result is None


def test_a_same_repo_build_still_gets_a_token():
    configured = plugin()
    assert configured.hook_environment(request(event="push", number=2)) is not None


def test_deny_forks_can_be_turned_off():
    configured = plugin(deny_forks=False)
    result = configured.hook_environment(
        request(event="pull_request", source_repo="attacker/drone-environ-demo", number=3)
    )
    assert result is not None


def test_a_promotion_of_fork_authored_code_is_also_denied():
    """The subtler case: a promotion whose commit came from a fork must not mint an
    environment-scoped token for fork-authored code."""
    configured = plugin()
    result = configured.hook_environment(
        request(event="promote", deploy_to="production",
                source_repo="attacker/drone-environ-demo", number=4)
    )
    assert result is None


def test_require_events_limits_which_builds_get_a_token():
    configured = plugin(require_events=["promote"])
    assert configured.hook_environment(request(event="push", number=5)) is None
    assert configured.hook_environment(
        request(event="promote", deploy_to="prod", number=6)
    ) is not None


# --- keys fail closed (T2-E) ---------------------------------------------------

def test_no_configured_key_fails_closed_by_default():
    """A failed key mount must fail startup, not silently degrade to a throwaway key."""
    with pytest.raises(PluginConfigError, match="no signing key"):
        BuildToken().configure({"issuer": ISSUER})


def test_an_ephemeral_key_must_be_opted_into():
    configured = BuildToken()
    configured.configure({"issuer": ISSUER, "allow_ephemeral_key": True})
    assert configured.signing["source"] == "ephemeral"


def test_a_key_can_be_loaded_from_disk(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "jwt.pem"
    pem.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    configured = plugin(private_key_file=str(pem))
    token = issued(configured, event="push")["DRONE_BUILD_TOKEN"].data

    # Verifiable against the key on disk, not just the one in memory: tokens survive
    # a restart.
    assert jwt.decode(
        token, key.public_key(), algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER
    )["build.event"] == "push"


def test_an_unset_field_is_not_asserted_as_an_empty_claim():
    """A push has no deploy target. Saying build.target="" is not the same as saying
    nothing, and a verifier should be able to test for the claim's presence."""
    configured = plugin()
    token = issued(configured, event="push")
    claims = verify(token["DRONE_BUILD_TOKEN"].data, configured)

    assert "build.target" not in claims
    assert claims["build.event"] == "push"


def test_false_is_a_real_value_and_survives_omit_empty():
    configured = plugin(claims={"private": "repo.private"})
    request_with_public_repo = EnvironRequest(
        repo=Repo(slug="droneadmin/demo", private=False), build=Build(event="push")
    )
    result = configured.hook_environment(request_with_public_repo)
    token = normalise("buildtoken", result)[0].data

    assert verify(token, configured)["private"] is False


def test_omit_empty_can_be_turned_off():
    configured = plugin(omit_empty=False)
    token = issued(configured, event="push")
    assert verify(token["DRONE_BUILD_TOKEN"].data, configured)["build.target"] == ""
