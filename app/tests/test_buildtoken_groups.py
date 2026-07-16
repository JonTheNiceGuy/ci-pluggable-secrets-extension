"""The optional `groups` claim: the subject and each of its segment-prefixes.

A Kubernetes API server maps this claim to RBAC groups (groupsClaim), and the values are
the same strings an AWS IAM trust policy would match on `sub` — so one token drives both
direct-OIDC RBAC and IAM federation. See the buildtoken plugin's _groups().
"""

import jwt
import pytest

from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken
from ci_pluggable_secrets_extension.server import normalise

ISSUER = "https://drone-environ.example.com"
AUDIENCE = "kubernetes"
SLUG = "droneadmin/drone-environ-demo"


def plugin(**settings):
    configured = BuildToken()
    configured.configure({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allow_ephemeral_key": True,
        **settings,
    })
    return configured


def claims_for(configured, **build):
    result = configured.hook_environment(
        EnvironRequest(repo=Repo(slug=SLUG, namespace="droneadmin"), build=Build(**build))
    )
    token = {v.name: v for v in normalise("buildtoken", result)}["DRONE_BUILD_TOKEN"].data
    return jwt.decode(
        token, configured.public_key,
        algorithms=[configured.settings["algorithm"]],
        audience=AUDIENCE, issuer=ISSUER,
    )


def test_no_groups_claim_unless_enabled():
    claims = claims_for(plugin(), event="push", ref="refs/heads/main")
    assert "groups" not in claims


def test_groups_for_a_push_to_main_are_the_subject_and_its_prefixes():
    claims = claims_for(plugin(emit_groups=True), event="push", ref="refs/heads/main")
    assert claims["sub"] == f"repo:{SLUG}:ref:refs/heads/main"
    assert claims["groups"] == [f"repo:{SLUG}", f"repo:{SLUG}:ref:refs/heads/main"]


def test_groups_for_a_production_promotion():
    claims = claims_for(
        plugin(emit_groups=True), event="promote", deploy_to="production",
        ref="refs/heads/main",
    )
    assert claims["groups"] == [f"repo:{SLUG}", f"repo:{SLUG}:environment:production"]


def test_a_random_branch_only_carries_the_repo_baseline_beyond_its_own_ref():
    # The specific-branch group has no RBAC binding, so only the shared repo:<slug>
    # baseline grants anything — this is how "any branch" gets the read-only tier.
    claims = claims_for(plugin(emit_groups=True), event="push", ref="refs/heads/feature-x")
    assert claims["groups"] == [f"repo:{SLUG}", f"repo:{SLUG}:ref:refs/heads/feature-x"]
    assert f"repo:{SLUG}" in claims["groups"]


def test_the_last_group_is_always_the_full_subject():
    claims = claims_for(plugin(emit_groups=True), event="push", ref="refs/heads/main")
    assert claims["groups"][-1] == claims["sub"]


def test_the_repo_baseline_is_shared_across_events():
    push = claims_for(plugin(emit_groups=True), event="push", ref="refs/heads/main")
    promote = claims_for(
        plugin(emit_groups=True), event="promote", deploy_to="production",
    )
    assert push["groups"][0] == promote["groups"][0] == f"repo:{SLUG}"


def test_the_groups_claim_name_is_configurable():
    claims = claims_for(
        plugin(emit_groups=True, groups_claim="teams"), event="push", ref="refs/heads/main",
    )
    assert "groups" not in claims
    assert claims["teams"][-1] == claims["sub"]


def test_a_subject_template_emits_the_whole_subject_as_one_group():
    configured = plugin(emit_groups=True, subject="repo:{repo.slug}:target:{build.deploy_to}")
    claims = claims_for(configured, event="promote", deploy_to="production")
    assert claims["groups"] == [f"repo:{SLUG}:target:production"]


def test_groups_appears_in_the_discovery_document_when_enabled():
    assert "groups" in plugin(emit_groups=True).discovery()["claims_supported"]
    assert "groups" not in plugin().discovery()["claims_supported"]


@pytest.mark.parametrize("keys,expected_tail", [
    (["repo"], f"repo:{SLUG}"),
    (["repo", "context"], f"repo:{SLUG}:ref:refs/heads/main"),
])
def test_groups_track_include_claim_keys(keys, expected_tail):
    claims = claims_for(
        plugin(emit_groups=True, include_claim_keys=keys),
        event="push", ref="refs/heads/main",
    )
    assert claims["groups"][-1] == expected_tail
