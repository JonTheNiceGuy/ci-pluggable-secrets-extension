"""Woodpecker support: same plugins, different transport.

Woodpecker has no environment extension — its nearest equivalent is the secret
extension — and it signs RFC 9421 with an ed25519 key pair rather than Drone's
draft-cavage HMAC. These tests pin the translation in both directions.
"""

import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ci_pluggable_secrets_extension import plugins
from ci_pluggable_secrets_extension import rfc9421
from ci_pluggable_secrets_extension.config import Config, Woodpecker
from ci_pluggable_secrets_extension.models import Variable
from ci_pluggable_secrets_extension.server import create_app
from ci_pluggable_secrets_extension.signature import SignatureError
from ci_pluggable_secrets_extension.woodpecker import (
    WoodpeckerRequest,
    to_request,
    to_secrets,
)

from .conftest import EXAMPLE_PLUGINS

PIPELINE = {
    "repo": {
        "id": 3,
        "forge_remote_id": "74",
        "owner": "octo-org",
        "name": "octo-repo",
        "full_name": "octo-org/octo-repo",
        "forge_url": "https://gitea.example.com/octo-org/octo-repo",
        "clone_url": "https://gitea.example.com/octo-org/octo-repo.git",
        "default_branch": "main",
        "private": True,
        "visibility": "private",
        "active": True,
        "config_file": ".woodpecker.yaml",
    },
    "pipeline": {
        "id": 12,
        "number": 5,
        "event": "deployment",
        "status": "pending",
        "deploy_to": "production",
        "commit": "cafebabe",
        "branch": "main",
        "ref": "refs/heads/main",
        "message": "ship it",
        "author": "octocat",
        "author_email": "octocat@example.com",
        "sender": "octocat",
        "variables": {"REASON": "hotfix"},
    },
}


@pytest.fixture
def signing_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def public_key(signing_key):
    return signing_key.public_key()


def sign(private_key, path, body):
    """Sign as Woodpecker does — see rfc9421.sign, pinned by the golden fixture below."""
    return rfc9421.sign(private_key, path, body)


# --- the payload, normalised ---------------------------------------------------

def test_a_woodpecker_pipeline_becomes_the_request_the_plugins_know():
    request = to_request(WoodpeckerRequest.model_validate(PIPELINE))

    assert request.repo.slug == "octo-org/octo-repo"
    assert request.repo.namespace == "octo-org"
    assert request.repo.uid == "74"
    assert request.repo.visibility == "private"
    assert request.build.number == 5
    assert request.build.after == "cafebabe"
    assert request.build.ref == "refs/heads/main"
    assert request.build.deploy_to == "production"
    assert request.build.sender == "octocat"
    assert request.build.params == {"REASON": "hotfix"}


def test_a_woodpecker_deployment_is_a_promotion():
    """The bug this prevents: a plugin keyed on event == "promote" would silently never
    fire on Woodpecker, and a deploy would quietly get no credentials."""
    request = to_request(WoodpeckerRequest.model_validate(PIPELINE))
    assert request.build.event == "promote"


def test_the_native_event_is_preserved():
    request = to_request(WoodpeckerRequest.model_validate(PIPELINE))
    assert request.build.model_extra["event_native"] == "deployment"
    assert request.build.model_extra["ci"] == "woodpecker"


@pytest.mark.parametrize("native,mapped", [
    ("deployment", "promote"),
    ("manual", "custom"),
    ("push", "push"),
    ("pull_request", "pull_request"),
    ("tag", "tag"),
    ("cron", "cron"),
])
def test_the_event_vocabularies_line_up(native, mapped):
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"]["event"] = native
    assert to_request(WoodpeckerRequest.model_validate(payload)).build.event == mapped


def test_unknown_woodpecker_fields_do_not_break_the_request():
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"]["some_future_field"] = "surprise"
    payload["netrc"] = {"login": "x", "password": "y"}
    assert to_request(WoodpeckerRequest.model_validate(payload)).build.number == 5


# --- the response ---------------------------------------------------------------

def test_variables_become_secrets_scoped_to_this_pipelines_event():
    secrets = to_secrets(
        [Variable(name="DEPLOY_TOKEN", data="s3cret", mask=True)], "deployment"
    )
    assert [s.model_dump() for s in secrets] == [
        {"name": "DEPLOY_TOKEN", "value": "s3cret", "images": [], "events": ["deployment"]}
    ]


def test_a_secret_always_names_an_event():
    """Woodpecker rejects a secret with no events, so this must never be empty."""
    for secret in to_secrets([Variable(name="A", data="1")], "push"):
        assert secret.events


# --- the endpoint ---------------------------------------------------------------

@pytest.fixture
def app(public_key, tmp_path):
    pem = tmp_path / "woodpecker.pub"
    pem.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    config = Config(
        secret="drone-secret",
        woodpecker=Woodpecker(path="/secrets", public_key_file=str(pem)),
        plugin_paths=[EXAMPLE_PLUGINS],
        plugins={"stdout": {}},
    )
    plugins.load_plugins_and_hooks(config)
    yield create_app(config)
    plugins.plugins.clear()
    plugins.hooks.clear()


def test_a_signed_woodpecker_request_gets_the_plugins_secrets(app, signing_key):
    client = TestClient(app)
    body = json.dumps(PIPELINE).encode()

    response = client.post("/secrets", content=body, headers=sign(signing_key, "/secrets", body))

    assert response.status_code == 200
    assert response.json() == {
        "secrets": [
            {"name": "stdout_plugin", "value": "enabled", "images": [],
             "events": ["deployment"]}
        ]
    }


def test_an_unsigned_woodpecker_request_is_rejected(app):
    client = TestClient(app)
    body = json.dumps(PIPELINE).encode()
    assert client.post("/secrets", content=body).status_code == 401


def test_a_request_signed_by_the_wrong_key_is_rejected(app):
    client = TestClient(app)
    body = json.dumps(PIPELINE).encode()
    forged = sign(Ed25519PrivateKey.generate(), "/secrets", body)
    assert client.post("/secrets", content=body, headers=forged).status_code == 401


def test_a_tampered_body_is_rejected(app, signing_key):
    client = TestClient(app)
    body = json.dumps(PIPELINE).encode()
    headers = sign(signing_key, "/secrets", body)

    tampered = json.loads(json.dumps(PIPELINE))
    tampered["pipeline"]["deploy_to"] = "production"
    response = client.post(
        "/secrets", content=json.dumps(tampered).encode() + b" ", headers=headers
    )
    assert response.status_code == 401


def test_a_request_with_no_content_digest_is_rejected(app, signing_key):
    client = TestClient(app)
    body = json.dumps(PIPELINE).encode()
    headers = sign(signing_key, "/secrets", body)
    headers.pop("Content-Digest")
    assert client.post("/secrets", content=body, headers=headers).status_code == 401


def test_the_drone_endpoint_still_works_alongside_it(app, body):
    from ci_pluggable_secrets_extension.signature import sign as drone_sign

    client = TestClient(app)
    headers = drone_sign("drone-secret", "POST", "/", {}, body)
    response = client.post("/", content=body, headers=headers)

    assert response.status_code == 200
    assert response.json() == [
        {"name": "stdout_plugin", "data": "enabled", "mask": False}
    ]


def test_a_non_ed25519_key_is_refused():
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(SignatureError, match="expected an ed25519 public key"):
        rfc9421.load_public_key(rsa_pem)


def test_an_empty_variable_is_left_out_rather_than_poisoning_the_response(caplog):
    """Woodpecker rejects a secret with an empty value — and the whole response with
    it, so one plugin returning "" would cost every other plugin its variables."""
    secrets = to_secrets(
        [Variable(name="EMPTY", data=""), Variable(name="REAL", data="1")], "push"
    )
    assert [s.name for s in secrets] == ["REAL"]
    assert "Woodpecker rejects empty secrets" in caplog.text


# --- interop with the real thing -------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def captured():
    """A request captured from a live Woodpecker 3.16 server, and its public key.

    Hand-rolling a signature verifier is only safe if something keeps it honest. This
    is that something: if a change here stops accepting what Woodpecker actually
    sends, this test fails rather than the deploy.
    """
    request = json.loads((FIXTURES / "woodpecker_request.json").read_text())
    public_key = rfc9421.load_public_key((FIXTURES / "woodpecker_pubkey.pem").read_bytes())
    return request, public_key


def test_a_real_woodpecker_request_verifies():
    request, public_key = captured()

    # created is in the past, so age checking is off for this one.
    rfc9421.verify(
        public_key, request["method"], request["path"], request["headers"],
        request["body"].encode(), max_age=0,
    )


def test_a_real_woodpecker_request_with_a_tampered_body_does_not_verify():
    request, public_key = captured()
    with pytest.raises(SignatureError, match="Content-Digest"):
        rfc9421.verify(
            public_key, request["method"], request["path"], request["headers"],
            request["body"].encode() + b" ", max_age=0,
        )


def test_a_real_woodpecker_request_signed_for_another_path_does_not_verify():
    request, public_key = captured()
    with pytest.raises(SignatureError, match="does not match"):
        rfc9421.verify(
            public_key, request["method"], "/elsewhere", request["headers"],
            request["body"].encode(), max_age=0,
        )


def test_the_real_request_carries_no_keyid():
    """Which is exactly why this scheme is verified by hand: Python's
    http-message-signatures requires a keyid and raises KeyError without one."""
    request, _ = captured()
    signature_input = next(
        v for k, v in request["headers"].items() if k.lower() == "signature-input"
    )
    assert "keyid" not in signature_input
    assert 'alg="ed25519"' in signature_input


def test_a_replayed_signature_is_rejected(signing_key, public_key):
    """An hour-old signature is a replay, not a request."""
    body = b"{}"
    stale = rfc9421.sign(signing_key, "/secrets", body, created=int(time.time()) - 3600)

    with pytest.raises(SignatureError, match="over the 300s limit"):
        rfc9421.verify(public_key, "POST", "/secrets", stale, body, max_age=300)


def test_a_fresh_signature_of_our_own_verifies(signing_key, public_key):
    """Our signer and our verifier agree — and the golden fixture above proves the
    verifier also agrees with the real Woodpecker."""
    body = b'{"pipeline": {"event": "push"}}'
    headers = rfc9421.sign(signing_key, "/secrets", body)
    rfc9421.verify(public_key, "POST", "/secrets", headers, body)


# --- key refresh (T4-3) ----------------------------------------------------------

def _write_pubkey(path, public_key):
    path.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def _pub_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_a_stale_key_is_refetched_before_use(tmp_path, public_key):
    from ci_pluggable_secrets_extension.config import Woodpecker
    from ci_pluggable_secrets_extension.server import WoodpeckerKey

    pem = tmp_path / "wp.pem"
    _write_pubkey(pem, public_key)
    holder = WoodpeckerKey(Woodpecker(public_key_file=str(pem)))

    # Rotate the key on disk. While the cached one is fresh, current() keeps it.
    rotated = Ed25519PrivateKey.generate().public_key()
    _write_pubkey(pem, rotated)
    assert _pub_bytes(holder.current(max_age=3600)) == _pub_bytes(public_key)

    # Once stale, current() re-reads and picks up the rotated key.
    holder.fetched_at = 0
    assert _pub_bytes(holder.current(max_age=1)) == _pub_bytes(rotated)


def test_the_refresh_key_endpoint_reloads_the_key(app):
    response = TestClient(app).post("/secrets/refresh-key")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def _headers_for(signing_key, params, body):
    """Sign `body` under the exact `@signature-params` string given, so a test can craft
    a covered set or parameters that rfc9421.sign would never produce."""
    components = [c.strip('"') for c in params.split(";", 1)[0].strip("()").split()]
    digest_headers = {"Content-Digest": rfc9421.content_digest(body)}
    base = rfc9421.signature_base(components, params, "POST", "/secrets", digest_headers)
    signature = signing_key.sign(base.encode())
    return {
        "Content-Digest": rfc9421.content_digest(body),
        "Signature-Input": f"{rfc9421.LABEL}={params}",
        "Signature": f"{rfc9421.LABEL}=:{base64.b64encode(signature).decode()}:",
    }


def test_a_signature_not_covering_content_digest_is_rejected(signing_key, public_key):
    """The real digest-coverage test (the header-popping test above trips a different
    check): a signature over @request-target alone leaves the body unsigned."""
    body = b'{"pipeline": {"event": "push"}}'
    params = f'("@request-target");created={int(time.time())};alg="ed25519"'
    headers = _headers_for(signing_key, params, body)
    with pytest.raises(SignatureError, match="content-digest"):
        rfc9421.verify(public_key, "POST", "/secrets", headers, body, max_age=0)


def test_a_signature_with_no_created_is_rejected_when_age_is_enforced(signing_key, public_key):
    """A validly-signed request that omits `created` must still be refused when age is
    enforced — the freshness check must not be silently skipped."""
    body = b"{}"
    params = '("@request-target" "content-digest");alg="ed25519"'
    headers = _headers_for(signing_key, params, body)
    with pytest.raises(SignatureError, match="no 'created'"):
        rfc9421.verify(public_key, "POST", "/secrets", headers, body, max_age=300)


def test_a_non_integer_created_is_a_401_not_a_500(public_key):
    """`created` is attacker-typed; a string one must raise SignatureError (→401), not
    trip int() into a traceback (→500)."""
    body = b"{}"
    params = '("@request-target" "content-digest");created="soon";alg="ed25519"'
    headers = {
        "Content-Digest": rfc9421.content_digest(body),
        "Signature-Input": f"{rfc9421.LABEL}={params}",
        # The signature is never reached: the created type-check comes first.
        "Signature": f"{rfc9421.LABEL}=:{base64.b64encode(b'x' * 64).decode()}:",
    }
    with pytest.raises(SignatureError, match="created"):
        rfc9421.verify(public_key, "POST", "/secrets", headers, body, max_age=300)


def test_a_non_bytes_signature_value_is_a_401_not_a_500(public_key):
    """A Signature value that is not a byte sequence must raise SignatureError, not reach
    bytes() and 500 (or coerce an integer into a zero-filled buffer)."""
    body = b"{}"
    params = f'("@request-target" "content-digest");created={int(time.time())};alg="ed25519"'
    headers = {
        "Content-Digest": rfc9421.content_digest(body),
        "Signature-Input": f"{rfc9421.LABEL}={params}",
        "Signature": f"{rfc9421.LABEL}=5",   # an integer, not a byte sequence
    }
    with pytest.raises(SignatureError, match="byte sequence"):
        rfc9421.verify(public_key, "POST", "/secrets", headers, body, max_age=0)


# --- the ref, made whole ---------------------------------------------------------

def test_a_bare_branch_ref_becomes_a_real_git_ref():
    """A Woodpecker deployment carries ref="main", not "refs/heads/main". Left alone,
    the token would claim a different ref on each CI system for the same commit, and
    ref_type would vanish."""
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"]["ref"] = "main"
    payload["pipeline"]["branch"] = "main"

    assert to_request(WoodpeckerRequest.model_validate(payload)).build.ref == "refs/heads/main"


def test_a_real_ref_is_left_alone():
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"]["ref"] = "refs/heads/feature"
    assert to_request(WoodpeckerRequest.model_validate(payload)).build.ref == "refs/heads/feature"


def test_a_bare_tag_ref_becomes_a_tag_ref():
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"].update(event="tag", ref="v1.2.3", branch="")
    assert to_request(WoodpeckerRequest.model_validate(payload)).build.ref == "refs/tags/v1.2.3"


def test_a_release_ref_is_reconstructed_as_a_tag():
    """A release is tag-shaped: its bare ref names a tag, not a branch (T4-5)."""
    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"].update(event="release", ref="v2.0.0", branch="")
    assert to_request(WoodpeckerRequest.model_validate(payload)).build.ref == "refs/tags/v2.0.0"


def test_a_closed_pull_request_keeps_its_head_and_base_refs():
    """buildtoken._derive treats pull_request_closed as PR-shaped, so head/base survive
    rather than vanishing (T4-5)."""
    from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken

    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"].update(event="pull_request_closed", branch="feature", ref="")
    request = to_request(WoodpeckerRequest.model_validate(payload))

    plugin = BuildToken()
    plugin.configure({"issuer": "https://issuer.example.com", "allow_ephemeral_key": True})
    derived = plugin._derive(request.model_dump(mode="json"))
    assert derived["head_ref"] == "feature"


def test_the_token_claims_the_same_ref_type_on_both_ci_systems():
    from ci_pluggable_secrets_extension.plugins.buildtoken import BuildToken

    payload = json.loads(json.dumps(PIPELINE))
    payload["pipeline"]["ref"] = "main"          # as Woodpecker sends it
    request = to_request(WoodpeckerRequest.model_validate(payload))

    plugin = BuildToken()
    plugin.configure({
        "issuer": "https://issuer.example.com", "audience": "aud",
        "allow_ephemeral_key": True,
    })
    derived = plugin._derive(request.model_dump(mode="json"))

    assert derived["ref_type"] == "branch"
