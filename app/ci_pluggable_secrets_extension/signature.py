"""Verify the HTTP signature Drone puts on extension requests.

Drone signs with github.com/99designs/httpsignatures-go, an implementation of the
*draft* Cavage HTTP-signatures spec (draft-cavage-http-signatures), not the final
RFC 9421. The two are wire-incompatible, and the Python libraries on PyPI target
RFC 9421 or are unmaintained, so the draft scheme is implemented here directly.
"""

import base64
import hashlib
import hmac
import re
import time
from email.utils import formatdate, parsedate_to_datetime

SUPPORTED_ALGORITHMS = ("hmac-sha256",)
DEFAULT_HEADERS = ("date",)
DEFAULT_MAX_CLOCK_SKEW = 300

_PARAM = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


class SignatureError(Exception):
    """Raised when a request is unsigned, malformed, stale, or forged."""


def _get(headers, name, default=None):
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return default


def _extract_signature_params(headers) -> dict:
    raw = _get(headers, "signature")
    if raw is None:
        authorization = _get(headers, "authorization", "")
        if authorization.lower().startswith("signature "):
            raw = authorization[len("signature "):]
    if not raw:
        raise SignatureError("request carries no HTTP signature")

    params = dict(_PARAM.findall(raw))
    if "signature" not in params:
        raise SignatureError("signature header has no signature parameter")
    return params


def build_signing_string(method, target, headers, header_names) -> str:
    lines = []
    for name in header_names:
        name = name.lower()
        if name == "(request-target)":
            lines.append(f"(request-target): {method.lower()} {target}")
            continue
        value = _get(headers, name)
        if value is None:
            raise SignatureError(f"signed header {name} is missing from the request")
        lines.append(f"{name}: {value.strip()}")
    return "\n".join(lines)


def digest(body: bytes) -> str:
    return "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def sign(secret, method, target, headers, body=b"", key_id="hmac-key",
         header_names=("(request-target)", "date", "digest")):
    """Sign a request the way Drone does. Used by the tests and the dev client."""
    headers = {k: v for k, v in headers.items()}
    headers.setdefault("Date", formatdate(usegmt=True))
    headers.setdefault("Digest", digest(body))

    signing_string = build_signing_string(method, target, headers, header_names)
    mac = hmac.new(secret.encode(), signing_string.encode(), hashlib.sha256).digest()
    headers["Signature"] = (
        f'keyId="{key_id}",algorithm="hmac-sha256",'
        f'headers="{" ".join(header_names)}",'
        f'signature="{base64.b64encode(mac).decode()}"'
    )
    return headers


def verify(secret, method, target, headers, body=b"",
           max_clock_skew=DEFAULT_MAX_CLOCK_SKEW) -> None:
    """Raise SignatureError unless the request is validly signed with `secret`."""
    params = _extract_signature_params(headers)

    algorithm = params.get("algorithm", "hmac-sha256").lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise SignatureError(f"unsupported signature algorithm {algorithm}")

    header_names = params.get("headers", " ".join(DEFAULT_HEADERS)).split()
    signing_string = build_signing_string(method, target, headers, header_names)

    expected = hmac.new(secret.encode(), signing_string.encode(), hashlib.sha256).digest()
    try:
        provided = base64.b64decode(params["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureError("signature is not valid base64") from exc

    if not hmac.compare_digest(expected, provided):
        raise SignatureError("signature does not match the shared secret")

    covered = [name.lower() for name in header_names]

    # A signature that does not cover Date can be replayed forever: an attacker rewrites
    # the Date and the signature still checks out. Require it whenever skew is enforced,
    # rather than skipping the freshness check when Date was conveniently left unsigned.
    if max_clock_skew:
        if "date" not in covered:
            raise SignatureError(
                "signature does not cover the Date header, so its freshness cannot "
                "be checked"
            )
        _verify_date(_get(headers, "date"), max_clock_skew)

    # The body is bound to the signature only through the Digest header. Without Digest
    # in the covered set the signature could be lifted onto any other body, so require
    # it rather than skipping the body check when it is absent.
    if "digest" not in covered:
        raise SignatureError(
            "signature does not cover the Digest header, so the body is unsigned"
        )
    provided_digest = _get(headers, "digest", "")
    if not hmac.compare_digest(digest(body), provided_digest.strip()):
        raise SignatureError("body does not match the signed Digest header")


def _verify_date(value, max_clock_skew) -> None:
    if not value:
        raise SignatureError("signed Date header is missing")
    try:
        sent = parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError) as exc:
        raise SignatureError(f"Date header is unparseable: {value!r}") from exc

    skew = abs(time.time() - sent)
    if skew > max_clock_skew:
        raise SignatureError(
            f"Date header is {int(skew)}s adrift, over the {max_clock_skew}s limit"
        )
