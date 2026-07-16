import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ci_pluggable_secrets_plugin import PluginConfigError
from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo
from ci_pluggable_secrets_extension.server import normalise
from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken

ISSUER = "https://drone-environ.example.com"
AUDIENCE = "https://deploy.example.com"


def write_key(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (directory / name).write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return key


def plugin(key_dir, **settings):
    configured = BuildToken()
    configured.configure({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "key_dir": str(key_dir),
        **settings,
    })
    return configured


def issue(configured, **build):
    result = configured.hook_environment(
        EnvironRequest(repo=Repo(slug="octo/repo"), build=Build(**build))
    )
    return normalise("buildtoken", result)[0].data


def verify_against_jwks(token, jwks):
    """Verify the way a receiver does: pick the key the token names, then check it."""
    keys = jwt.PyJWKSet.from_dict(jwks)
    kid = jwt.get_unverified_header(token)["kid"]
    signing_key = next(key for key in keys.keys if key.key_id == kid)
    return jwt.decode(
        token, signing_key.key, algorithms=["RS256", "ES256"],
        audience=AUDIENCE, issuer=ISSUER,
    )


def test_every_key_in_the_directory_is_published(tmp_path):
    write_key(tmp_path, "2026-01-01.pem")
    write_key(tmp_path, "2026-07-01.pem")

    published = plugin(tmp_path).jwks()["keys"]
    assert len(published) == 2
    assert len({key["kid"] for key in published}) == 2


def test_the_newest_key_by_name_signs(tmp_path):
    write_key(tmp_path, "2026-01-01.pem")
    new = write_key(tmp_path, "2026-07-01.pem")

    configured = plugin(tmp_path)
    token = issue(configured, event="push", ref="refs/heads/main")

    # Verifiable with the new key specifically, so that is what signed it.
    assert jwt.decode(token, new.public_key(), algorithms=["RS256"],
                      audience=AUDIENCE, issuer=ISSUER)["event_name"] == "push"


def test_a_token_signed_by_the_retired_key_still_verifies_during_the_overlap(tmp_path):
    """The reason rotation needs more than one published key.

    A token issued a minute before the switchover is still live. If the old key
    vanished from the JWKS the moment the new one took over, that build's token
    would stop verifying mid-deploy.
    """
    old = write_key(tmp_path, "2026-01-01.pem")

    before = plugin(tmp_path)
    old_token = issue(before, event="promote", deploy_to="production")

    # A new key arrives and takes over the signing.
    write_key(tmp_path, "2026-07-01.pem")
    after = plugin(tmp_path)
    new_token = issue(after, event="promote", deploy_to="production")

    assert after.signing["kid"] != before.signing["kid"]

    # Both tokens verify against the key set the extension now publishes.
    jwks = after.jwks()
    assert verify_against_jwks(old_token, jwks)["environment"] == "production"
    assert verify_against_jwks(new_token, jwks)["environment"] == "production"

    # And the old token really was signed by the old key.
    assert jwt.get_unverified_header(old_token)["kid"] == before.signing["kid"]
    assert jwt.decode(old_token, old.public_key(), algorithms=["RS256"],
                      audience=AUDIENCE, issuer=ISSUER)


def test_a_key_can_be_published_before_it_starts_signing(tmp_path):
    """Phase one of a careful rotation: publish the new key, keep signing with the old,
    and give every verifier's JWKS cache time to catch up before switching."""
    write_key(tmp_path, "2026-01-01.pem")
    write_key(tmp_path, "2026-07-01.pem")

    configured = plugin(tmp_path, signing_key="2026-01-01.pem")

    assert len(configured.jwks()["keys"]) == 2
    assert configured.signing["source"].endswith("2026-01-01.pem")

    token = issue(configured, event="push", ref="refs/heads/main")
    assert verify_against_jwks(token, configured.jwks())["event_name"] == "push"


def test_retiring_a_key_stops_its_tokens_verifying(tmp_path):
    """Phase three: once the old tokens have expired, delete the old key and its
    tokens become unverifiable — which is the point of retiring it."""
    write_key(tmp_path, "2026-01-01.pem")
    before = plugin(tmp_path)
    old_token = issue(before, event="push", ref="refs/heads/main")
    old_kid = jwt.get_unverified_header(old_token)["kid"]

    (tmp_path / "2026-01-01.pem").unlink()
    write_key(tmp_path, "2026-07-01.pem")
    after = plugin(tmp_path)

    # The retired key is gone from the published set, so a receiver can no longer find
    # the key the old token names by its kid — the token is unverifiable.
    published_kids = {key["kid"] for key in after.jwks()["keys"]}
    assert old_kid not in published_kids


def test_the_signing_key_is_published_first(tmp_path):
    write_key(tmp_path, "2026-01-01.pem")
    write_key(tmp_path, "2026-07-01.pem")
    configured = plugin(tmp_path)
    assert configured.jwks()["keys"][0]["kid"] == configured.signing["kid"]


def test_an_unknown_signing_key_is_a_startup_error(tmp_path):
    write_key(tmp_path, "2026-01-01.pem")
    with pytest.raises(PluginConfigError, match="not among the loaded keys"):
        plugin(tmp_path, signing_key="the-one-i-forgot-to-copy.pem")


def test_a_missing_key_dir_is_a_startup_error(tmp_path):
    with pytest.raises(PluginConfigError, match="is not a directory"):
        plugin(tmp_path / "nowhere")


def test_no_private_material_is_ever_published(tmp_path):
    write_key(tmp_path, "2026-01-01.pem")
    write_key(tmp_path, "2026-07-01.pem")
    for key in plugin(tmp_path).jwks()["keys"]:
        assert not {"d", "p", "q", "dp", "dq", "qi"} & set(key)


def test_mixed_key_types_each_keep_their_own_algorithm(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec

    write_key(tmp_path, "2026-01-rsa.pem")
    ec_key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "2026-07-ec.pem").write_bytes(ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    configured = plugin(tmp_path)
    algorithms = {key["kid"]: key["alg"] for key in configured.jwks()["keys"]}

    assert set(algorithms.values()) == {"RS256", "ES256"}
    # The EC key sorts last, so it signs — and the token says ES256, not the RS256
    # the config defaults to.
    assert configured.settings["algorithm"] == "ES256"
    token = issue(configured, event="push", ref="refs/heads/main")
    assert jwt.get_unverified_header(token)["alg"] == "ES256"
    assert verify_against_jwks(token, configured.jwks())["event_name"] == "push"
