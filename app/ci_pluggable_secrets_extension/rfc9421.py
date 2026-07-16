"""Verify the HTTP Message Signature Woodpecker puts on its requests.

Woodpecker signs with RFC 9421 and an **ed25519 key pair** — the opposite arrangement
to Drone, which signs the draft-cavage scheme with an HMAC secret shared both ways.
Here the extension holds only Woodpecker's *public* key, so a leak of the extension's
config does not let anyone forge a request to it.

A request from Woodpecker 3.16 looks like this (captured from a live server, and kept
as tests/fixtures/woodpecker_request.json so this stays honest):

    Content-Digest: sha-256=:JnsvjEtJL8xnyUORaZ5hlo10w1OeBpJNUdjCxZYV7BI=:
    Signature-Input: woodpecker-ci-extensions=("@request-target" "content-digest");created=1784066615;alg="ed25519"
    Signature: woodpecker-ci-extensions=:AsueyYcPPiqHC7FM...:

Two things about that are worth knowing, because both bite:

* `woodpecker-ci-extensions` is the signature *label*, not a `keyid` parameter — there
  is no keyid at all. Python's http-message-signatures library requires one and raises
  KeyError without it, which is why the scheme is verified here directly.
* `@request-target` is the path alone ("/secrets"), not "post /secrets" — verified
  empirically against a real signature, since guessing wrong fails closed and silently.
"""

import base64
import hashlib
import hmac
import re
import time

import http_sfv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from ci_pluggable_secrets_extension.signature import SignatureError

LABEL = "woodpecker-ci-extensions"
ALGORITHM = "ed25519"
COVERED = ("@request-target", "content-digest")
DEFAULT_MAX_AGE = 300

_DIGEST = re.compile(r"sha-256=:(?P<digest>[^:]+):")


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError(
            f"expected an ed25519 public key, got {type(key).__name__}. Woodpecker's "
            "key comes from its /api/signature/public-key endpoint."
        )
    return key


def content_digest(body: bytes) -> str:
    """The Content-Digest header value, per RFC 9530."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _get(headers, name):
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def signature_base(components, params, method, path, headers) -> str:
    """The exact bytes that were signed, per RFC 9421 section 2.5."""
    lines = []
    for component in components:
        if component == "@request-target":
            value = path
        elif component == "@method":
            value = method.upper()
        elif component == "@authority":
            value = _get(headers, "host")
        elif component.startswith("@"):
            raise SignatureError(f"unsupported signed component {component}")
        else:
            value = _get(headers, component)

        if value is None:
            raise SignatureError(f"signed component {component} is missing")
        lines.append(f'"{component}": {value.strip()}')

    # The trailing line is the signature parameters exactly as they were sent — which
    # is why they cannot be normalised or reordered on the way in.
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def verify(public_key, method, path, headers, body=b"", max_age=DEFAULT_MAX_AGE) -> None:
    """Raise SignatureError unless the request is validly signed by `public_key`."""
    raw_input = _get(headers, "signature-input")
    raw_signature = _get(headers, "signature")
    if not raw_input or not raw_signature:
        raise SignatureError("request carries no HTTP signature")

    label, components, params, serialized = _parse_input(raw_input)
    signature = _parse_signature(raw_signature, label)

    algorithm = params.get("alg", ALGORITHM)
    if algorithm != ALGORITHM:
        raise SignatureError(f"unsupported signature algorithm {algorithm!r}")

    # Without content-digest among the covered components the body is not signed at
    # all, and could be swapped for any other while the signature still checked out.
    if "content-digest" not in components:
        raise SignatureError(
            "the signature does not cover content-digest, so the body is unsigned"
        )
    _verify_content_digest(headers, body)

    # `created` is an attacker-typed structured-field value. int() on a string one is a
    # 500 where the contract is 401, and a missing `created` must not silently skip the
    # freshness check — it is inside the signed params, so requiring it is fail-closed.
    created = params.get("created")
    if max_age:
        if created is None:
            raise SignatureError(
                "signature has no 'created' parameter, so its age cannot be checked"
            )
        if not isinstance(created, int):
            raise SignatureError(f"signature 'created' is not an integer: {created!r}")
        age = abs(time.time() - created)
        if age > max_age:
            raise SignatureError(
                f"signature was created {int(age)}s ago, over the {max_age}s limit"
            )

    base = signature_base(components, serialized, method, path, headers)
    try:
        public_key.verify(signature, base.encode())
    except InvalidSignature as exc:
        raise SignatureError("signature does not match Woodpecker's public key") from exc


def _parse_input(raw):
    dictionary = http_sfv.Dictionary()
    try:
        dictionary.parse(raw.encode())
    except ValueError as exc:
        raise SignatureError(f"Signature-Input is malformed: {exc}") from exc

    if len(dictionary) != 1:
        raise SignatureError(
            f"expected exactly one signature, got {len(dictionary)}"
        )

    label = next(iter(dictionary))
    inner = dictionary[label]
    components = [item.value for item in inner]
    params = dict(inner.params)

    # The signature base must quote the parameters byte for byte as they arrived, so
    # take them from the header rather than re-serialising.
    serialized = raw.strip()[len(label) + 1:]
    return label, components, params, serialized


def _parse_signature(raw, label):
    dictionary = http_sfv.Dictionary()
    try:
        dictionary.parse(raw.encode())
    except ValueError as exc:
        raise SignatureError(f"Signature header is malformed: {exc}") from exc

    if label not in dictionary:
        raise SignatureError(
            f"Signature has no entry for {label!r}, which Signature-Input names"
        )
    # The value must be a byte sequence. A wrongly-typed one (e.g. an integer) would
    # otherwise reach bytes() and either 500 or, worse, coerce to a zero-filled buffer.
    value = dictionary[label].value
    if not isinstance(value, (bytes, bytearray)):
        raise SignatureError("the Signature value is not a byte sequence")
    return bytes(value)


def _verify_content_digest(headers, body) -> None:
    """The signature covers the Content-Digest *header*; only this ties it to the body."""
    provided = _get(headers, "content-digest")
    if provided is None:
        raise SignatureError("request has no Content-Digest header")

    match = _DIGEST.search(provided)
    if not match:
        raise SignatureError(f"Content-Digest is not a sha-256 digest: {provided!r}")

    expected = base64.b64encode(hashlib.sha256(body).digest()).decode()
    if not hmac.compare_digest(expected, match.group("digest")):
        raise SignatureError("body does not match the signed Content-Digest header")


def sign(private_key: Ed25519PrivateKey, path, body=b"", label=LABEL, created=None):
    """Sign exactly as Woodpecker does. For tests, and for anyone porting this."""
    created = int(time.time()) if created is None else created
    digest = content_digest(body)
    params = f'("@request-target" "content-digest");created={created};alg="{ALGORITHM}"'

    base = signature_base(
        list(COVERED), params, "POST", path, {"Content-Digest": digest}
    )
    signature = private_key.sign(base.encode())

    return {
        "Content-Type": "application/json",
        "Content-Digest": digest,
        "Signature-Input": f"{label}={params}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode()}:",
    }
