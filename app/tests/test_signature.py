import time
from email.utils import formatdate

import pytest

from ci_pluggable_secrets_extension.signature import SignatureError, digest, sign, verify

from .conftest import SECRET


def test_round_trip(body):
    headers = sign(SECRET, "POST", "/", {"Content-Type": "application/json"}, body)
    verify(SECRET, "POST", "/", headers, body)


def test_wrong_secret_is_rejected(body):
    headers = sign(SECRET, "POST", "/", {}, body)
    with pytest.raises(SignatureError, match="does not match"):
        verify("not-the-secret", "POST", "/", headers, body)


def test_tampered_body_is_rejected(body):
    headers = sign(SECRET, "POST", "/", {}, body)
    with pytest.raises(SignatureError, match="Digest"):
        verify(SECRET, "POST", "/", headers, body + b" ")


def test_tampered_request_target_is_rejected(body):
    headers = sign(SECRET, "POST", "/", {}, body)
    with pytest.raises(SignatureError, match="does not match"):
        verify(SECRET, "POST", "/elsewhere", headers, body)


def test_unsigned_request_is_rejected(body):
    with pytest.raises(SignatureError, match="no HTTP signature"):
        verify(SECRET, "POST", "/", {"Date": formatdate(usegmt=True)}, body)


def test_stale_date_is_rejected(body):
    stale = formatdate(time.time() - 3600, usegmt=True)
    headers = sign(SECRET, "POST", "/", {"Date": stale}, body)
    with pytest.raises(SignatureError, match="adrift"):
        verify(SECRET, "POST", "/", headers, body)


def test_authorization_header_form_is_accepted(body):
    headers = sign(SECRET, "POST", "/", {}, body)
    headers["Authorization"] = "Signature " + headers.pop("Signature")
    verify(SECRET, "POST", "/", headers, body)


def test_a_signature_not_covering_the_body_is_rejected(body):
    """The body is bound only through Digest. A signature that omits Digest from its
    covered set (here, the draft default of Date only) could be lifted onto a different
    body, so it must be refused rather than accepted for its Date alone."""
    headers = sign(SECRET, "POST", "/", {}, body, header_names=("date",))
    headers["Signature"] = headers["Signature"].replace('headers="date",', "")
    with pytest.raises(SignatureError, match="Digest"):
        verify(SECRET, "POST", "/", headers, body)


def test_a_signature_not_covering_the_date_is_rejected(body):
    """Without Date in the covered set the Date can be rewritten and the signature
    replayed, so a skew-enforcing verify must refuse it."""
    headers = sign(SECRET, "POST", "/", {}, body,
                   header_names=("(request-target)", "digest"))
    with pytest.raises(SignatureError, match="Date"):
        verify(SECRET, "POST", "/", headers, body)


def test_digest_matches_the_drone_format(body):
    assert digest(b"").startswith("SHA-256=")
