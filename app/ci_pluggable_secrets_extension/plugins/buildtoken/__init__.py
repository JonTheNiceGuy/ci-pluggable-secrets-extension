"""Issue a short-lived, signed JWT describing the build.

The shape is the one OIDC uses for workload identity — the same idea as the token
GitHub Actions hands a job to let it authenticate to a cloud provider without a
long-lived key. The build gets a token asserting facts about itself ("this is a
promotion of droneadmin/drone-environ-demo to production"); the receiving party
verifies the signature against the public key this plugin publishes, and decides
what that build is allowed to do.

The default claims deliberately mirror GitHub Actions' OIDC token, so a service that
already trusts GitHub's tokens needs a new issuer and key, not a new policy language.
See GITHUB_CLAIMS below for the mapping, and the README for what GitHub asserts that
Drone simply does not tell us.

Tokens are signed with a private key and verified with the *public* half, fetched
from the JWKS endpoint. That asymmetry is the point: a symmetric secret would have to
be shared with every verifier, and anyone able to verify a token could also mint one.
"""

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from ci_pluggable_secrets_plugin import BaseEnvironPlugin, PluginConfigError

MISSING = object()

# A {dotted.path} placeholder. The inner class excludes braces, so nothing nested or
# malformed can be captured — the substitution is a single non-recursive pass.
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

# GitHub Actions' OIDC claims, mapped to where Drone keeps the same fact. Claims
# GitHub sends that have no Drone equivalent (actor_id, repository_owner_id,
# run_attempt, workflow, job_workflow_ref) are absent rather than guessed at: a claim
# that means almost-the-same-thing is worse than no claim, because a verifier will
# write policy against it.
GITHUB_CLAIMS = {
    "repository": "repo.slug",
    "repository_owner": "repo.namespace",
    "repository_id": "repo.uid",              # the SCM's id, as GitHub's is
    "repository_visibility": "repo.visibility",
    "actor": "build.sender",
    "event_name": "build.event",
    "ref": "build.ref",
    "ref_type": "derived.ref_type",
    "sha": "build.after",
    "environment": "build.deploy_to",         # only a promotion has one
    "head_ref": "derived.head_ref",            # only a pull request has one
    "base_ref": "derived.base_ref",
    "run_id": "build.id",
    "run_number": "build.number",
    "runner_environment": "derived.runner_environment",
}


class BuildToken(BaseEnvironPlugin):
    friendly_name = "buildtoken"
    version = "0.5.0"
    # The token is a credential; a build that should have one but silently gets none is
    # worse than a failed build, so an error here fails the request even under skip.
    fail_closed = True
    options = [
        {
            "name": "issuer",
            "type": str,
            "required": True,
            "help": "The 'iss' claim: this extension's URL, where verifiers fetch the keys",
        },
        {
            "name": "audience",
            "default": None,
            "help": "The 'aud' claim: who the token is for. A string or a list. Like "
                    "GitHub, this defaults to the URL of the repository owner.",
        },
        {
            "name": "include_claim_keys",
            "type": list,
            "default": ["repo", "context"],
            "help": "Which claims compose the 'sub', GitHub's mechanism. Each key "
                    "contributes 'key:value', joined with colons. 'repo' is the "
                    "repository and 'context' expands to environment:X, pull_request, "
                    "or ref:X — so the default reproduces GitHub's own subjects.",
        },
        {
            "name": "subject",
            "type": str,
            "default": None,
            "help": "Bypass include_claim_keys entirely and build 'sub' from a {path} "
                    "template. GitHub has no equivalent; prefer include_claim_keys.",
        },
        {
            "name": "default_claims",
            "type": str,
            "default": "github",
            "choices": ["github", "none"],
            "help": "Start from GitHub Actions' claim set, or from nothing",
        },
        {
            "name": "claims",
            "default": {},
            "help": "Claim name -> dotted path into the request, merged over the "
                    "defaults. A bare list of paths uses each path as its own claim "
                    "name; a claim set to null is dropped.",
        },
        {
            "name": "ttl",
            "type": int,
            "default": 300,
            "help": "Seconds the token stays valid. Keep it shorter than a build.",
        },
        {
            "name": "deny_forks",
            "type": bool,
            "default": True,
            "help": "Issue no token to a build whose code came from a fork (detected "
                    "via build.source_repo differing from the repo). GitHub withholds "
                    "OIDC from fork PRs; this matches that. A fork PR would otherwise "
                    "get a token asserting the upstream repository's identity.",
        },
        {
            "name": "require_events",
            "type": list,
            "default": None,
            "help": "If set, issue a token only for these build events (e.g. "
                    "[promote, push]); every other event gets none. Unset means all "
                    "events, minus whatever deny_forks excludes.",
        },
        {
            "name": "allow_ephemeral_key",
            "type": bool,
            "default": False,
            "help": "Permit generating an in-memory key when no key_dir or "
                    "private_key_file is configured. Off by default so a failed key "
                    "mount fails startup instead of silently issuing non-persistent "
                    "tokens that stop verifying on restart.",
        },
        {
            "name": "omit_empty",
            "type": bool,
            "default": True,
            "help": "Leave a claim out when the request has no value for it, rather "
                    "than asserting an empty string",
        },
        {
            "name": "numbers_as_strings",
            "type": bool,
            "default": True,
            "help": "Render numeric claims as strings, as GitHub's token does. Does "
                    "not touch iat/exp/nbf, which must stay numeric.",
        },
        {
            "name": "emit_groups",
            "type": bool,
            "default": False,
            "help": "Also emit a 'groups' claim: the subject and each of its "
                    "segment-prefixes (repo:slug, then repo:slug:ref:..., ...). A "
                    "Kubernetes API server maps this via groupsClaim so RBAC can grant "
                    "by build context, and the values are the same strings an IAM trust "
                    "policy would match on `sub`. Off by default, since GitHub's token "
                    "has no groups claim.",
        },
        {
            "name": "groups_claim",
            "type": str,
            "default": "groups",
            "help": "The claim name the group list is emitted under when emit_groups is set.",
        },
        {
            "name": "variable",
            "type": str,
            "default": "DRONE_BUILD_TOKEN",
            "help": "The variable the token is delivered in",
        },
        {
            "name": "key_dir",
            "type": str,
            "default": None,
            "help": "Directory of PEM private keys. Every key here is published for "
                    "verifiers; the newest one signs. This is how rotation works.",
        },
        {
            "name": "signing_key",
            "type": str,
            "default": None,
            "help": "Which key in key_dir signs. Defaults to the last by filename, so "
                    "date-stamped names roll forward on their own. Set it explicitly "
                    "to publish a new key before you start signing with it.",
        },
        {
            "name": "private_key_file",
            "type": str,
            "default": None,
            "help": "A single PEM private key, for when you are not rotating yet. If "
                    "neither this nor key_dir is set, an ephemeral key is generated "
                    "and tokens stop verifying when the extension restarts.",
        },
        {
            "name": "algorithm",
            "type": str,
            "default": "RS256",
            "choices": ["RS256", "ES256"],
            "help": "What to generate when no key is configured. For keys loaded from "
                    "disk the algorithm follows the key's own type.",
        },
        {
            "name": "jwks_path",
            "type": str,
            "default": "/.well-known/jwks",
            "help": "Where the public keys are published, GitHub's path",
        },
        {
            "name": "discovery_path",
            "type": str,
            "default": "/.well-known/openid-configuration",
            "help": "The OIDC discovery document, which points verifiers at jwks_path. "
                    "Cloud providers federate against this rather than a bare key URL.",
        },
    ]

    def configure(self, settings):
        super().configure(settings)

        self.settings["claims"] = self._resolve_claims()
        self._check_subject_keys()
        self.keys = self._load_keys()
        self.signing = self._pick_signing_key()
        # A key on disk dictates its own algorithm; the option only says what to
        # generate when there is no key at all.
        self.settings["algorithm"] = self.signing["alg"]

        # The published key set and discovery document only change when the keys do,
        # which is at configure time. Build them once rather than per JWKS request.
        self._jwks = self._build_jwks()
        self._discovery = self._build_discovery()

        self.log.info(
            "Signing build tokens with kid %s (%s); publishing %d key(s) for "
            "verification: %s",
            self.signing["kid"], self.signing["source"], len(self.keys),
            ", ".join(key["kid"] for key in self.keys),
        )

    # --- claims ---------------------------------------------------------------

    def _resolve_claims(self) -> dict:
        claims = self.settings["claims"]
        if isinstance(claims, list):
            claims = {path: path for path in claims}
        elif not isinstance(claims, dict):
            raise PluginConfigError(
                f"In {self.describe()} claims must be a mapping or a list, "
                f"got {type(claims).__name__}"
            )

        if self.settings["default_claims"] == "github":
            claims = {**GITHUB_CLAIMS, **claims}

        # An explicit null drops a default the deployment does not want to assert.
        return {name: path for name, path in claims.items() if path is not None}

    def _check_subject_keys(self) -> None:
        """A subject key naming a claim we do not emit would silently drop out of the
        subject, and only show up as a verifier's policy quietly failing to match."""
        known = set(self.settings["claims"]) | {"repo", "context"}
        unknown = [
            key for key in self.settings["include_claim_keys"] if key not in known
        ]
        if unknown:
            raise PluginConfigError(
                f"In {self.describe()} include_claim_keys names "
                f"{', '.join(unknown)}, which no claim provides. Available: "
                f"{', '.join(sorted(known))}"
            )

    # --- keys -----------------------------------------------------------------

    def _load_keys(self) -> list[dict]:
        paths = []
        if self.settings["key_dir"]:
            directory = Path(self.settings["key_dir"])
            if not directory.is_dir():
                raise PluginConfigError(
                    f"In {self.describe()} key_dir {directory} is not a directory"
                )
            # Sorted by name, so a date-stamped key sorts after the one it replaces.
            paths.extend(sorted(directory.glob("*.pem")))
        if self.settings["private_key_file"]:
            path = Path(self.settings["private_key_file"])
            if path not in paths:
                paths.append(path)

        if not paths:
            # Fail closed: a configured-but-empty key_dir (a failed volume mount) must
            # not degrade to a throwaway key that silently breaks every verifier's JWKS
            # cache. Generating one is opt-in.
            if not self.settings["allow_ephemeral_key"]:
                raise PluginConfigError(
                    f"In {self.describe()} no signing key could be loaded. Set key_dir "
                    "or private_key_file, or set allow_ephemeral_key: true to generate "
                    "a throwaway in-memory key (tokens stop verifying on restart)."
                )
            self.log.warning(
                "No key_dir or private_key_file set, generating an ephemeral %s key. "
                "Tokens issued now will stop verifying when this process restarts.",
                self.settings["algorithm"],
            )
            if self.settings["algorithm"] == "ES256":
                private = ec.generate_private_key(ec.SECP256R1())
            else:
                private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            return [self._describe_key(private, "ephemeral")]

        keys = []
        for path in paths:
            private = serialization.load_pem_private_key(path.read_bytes(), password=None)
            keys.append(self._describe_key(private, str(path)))
        return keys

    def _describe_key(self, private, source) -> dict:
        public = private.public_key()
        if isinstance(private, ec.EllipticCurvePrivateKey):
            algorithm = "ES256"
        elif isinstance(private, rsa.RSAPrivateKey):
            algorithm = "RS256"
        else:
            raise PluginConfigError(
                f"In {self.describe()} the key {source} is a "
                f"{type(private).__name__}, which cannot sign an RS256 or ES256 token"
            )
        return {
            "private": private,
            "public": public,
            "alg": algorithm,
            "kid": self._thumbprint(public),
            "source": source,
        }

    def _pick_signing_key(self) -> dict:
        chosen = self.settings["signing_key"]
        if not chosen:
            # The last by filename. With a name like 2026-07-14.pem, dropping in a
            # newer key and restarting is the whole rotation.
            return self.keys[-1]

        for key in self.keys:
            if key["source"] == chosen or Path(key["source"]).name == Path(chosen).name:
                return key
        raise PluginConfigError(
            f"In {self.describe()} signing_key {chosen} is not among the loaded keys: "
            f"{', '.join(key['source'] for key in self.keys)}"
        )

    @property
    def public_key(self):
        """The key that verifies what we are signing with *now*."""
        return self.signing["public"]

    @property
    def key_id(self) -> str:
        return self.signing["kid"]

    def _thumbprint(self, public_key) -> str:
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()[:16]

    def jwks(self) -> dict:
        """The published key set, built once at configure time (see _build_jwks)."""
        return self._jwks

    def discovery(self) -> dict:
        """The OIDC discovery document, built once at configure time."""
        return self._discovery

    def _build_jwks(self) -> dict:
        """Every key a verifier might need, signing key first.

        Publishing more than one is what makes rotation safe: a token signed with
        last month's key still verifies while this month's key is in use, because the
        verifier picks the key by the token's `kid`.
        """
        published = []
        for key in [self.signing] + [k for k in self.keys if k is not self.signing]:
            algorithm = ECAlgorithm if key["alg"] == "ES256" else RSAAlgorithm
            jwk = json.loads(algorithm.to_jwk(key["public"]))
            jwk.update(kid=key["kid"], use="sig", alg=key["alg"])
            published.append(jwk)
        return {"keys": published}

    def _build_discovery(self) -> dict:
        """The OIDC discovery document, as GitHub's issuer publishes.

        This is what a cloud provider is given when you federate with an issuer: it
        finds the keys through here, so jwks_path can move without every verifier
        being reconfigured.
        """
        issuer = self.settings["issuer"].rstrip("/")
        return {
            "issuer": issuer,
            "jwks_uri": f"{issuer}{self.settings['jwks_path']}",
            "subject_types_supported": ["public", "pairwise"],
            "response_types_supported": ["id_token"],
            "scopes_supported": ["openid"],
            "id_token_signing_alg_values_supported": sorted(
                {key["alg"] for key in self.keys}
            ),
            "claims_supported": sorted(
                {"sub", "aud", "exp", "iat", "iss", "jti", "nbf"}
                | set(self.settings["claims"])
                | ({self.settings["groups_claim"]} if self.settings["emit_groups"] else set())
            ),
        }

    def hook_routes(self, app):
        """Publish the verification keys and how to find them. Public by design."""
        jwks_path = self.settings["jwks_path"]
        discovery_path = self.settings["discovery_path"]

        @app.get(jwks_path)
        async def jwks():
            return self.jwks()

        @app.get(discovery_path)
        async def openid_configuration():
            return self.discovery()

        self.log.info(
            "Publishing the build-token keys at %s, discoverable at %s",
            jwks_path, discovery_path,
        )

    # --- issuance gating ------------------------------------------------------

    def _denied(self, request) -> bool:
        """Whether this build must get no token at all, before any claim is computed."""
        build, repo = request.build, request.repo

        if self.settings["deny_forks"] and self._is_from_fork(build, repo):
            self.log.warning(
                "Build %s came from fork %s (upstream %s); issuing no token. A fork's "
                "code must not receive a token asserting the upstream's identity.",
                build.number, build.source_repo, repo.slug,
            )
            return True

        events = self.settings["require_events"]
        if events is not None and build.event not in events:
            self.log.info(
                "Build %s event %r is not in require_events %s; issuing no token",
                build.number, build.event, events,
            )
            return True

        return False

    def _is_from_fork(self, build, repo) -> bool:
        """True when the build's code originates from a different repo than this one.

        Drone serialises the fork's repository as build.source_repo (its `Fork` field);
        for a same-repo build it is empty or equal to the repo's own slug. This catches
        a fork pull request, and a promotion or rollback of fork-authored code.
        """
        source = build.source_repo or ""
        return bool(source) and source != (repo.slug or "")

    def hook_environment(self, request):
        if self._denied(request):
            return None

        payload = request.model_dump(mode="json")
        payload["derived"] = self._derive(payload)
        now = int(time.time())

        token_claims = {
            "jti": str(uuid.uuid4()),
            "iss": self.settings["issuer"],
            "aud": self.settings["audience"] or self._default_audience(payload),
            "iat": now,
            "nbf": now,
            "exp": now + self.settings["ttl"],
        }

        for name, path in self.settings["claims"].items():
            value = self._resolve(path, payload)
            if value is MISSING:
                self.log.warning(
                    "Claim %s: no %s in the request, leaving it out of the token",
                    name, path,
                )
                continue
            # An unset Drone field is "" or 0, not absent. Asserting environment ""
            # says something different from not asserting it at all, and a verifier
            # should be able to test a claim's presence. This must not catch False,
            # which is a real value a claim may legitimately have.
            if self.settings["omit_empty"] and (value is None or value == ""):
                continue
            if self.settings["numbers_as_strings"] and isinstance(value, int) \
                    and not isinstance(value, bool):
                value = str(value)
            token_claims[name] = value

        # After the claims, because include_claim_keys composes the subject out of them.
        token_claims["sub"] = self._subject(payload, token_claims)

        # The groups claim, if enabled, is derived from the same segments as the subject.
        if self.settings["emit_groups"]:
            groups = self._groups(payload, token_claims)
            if groups:
                token_claims[self.settings["groups_claim"]] = groups

        token = jwt.encode(
            token_claims,
            self.signing["private"],
            algorithm=self.signing["alg"],
            headers={"kid": self.signing["kid"]},
        )

        self.log.info(
            "Issued a build token for %s, valid %ss, signed with kid %s",
            token_claims["sub"], self.settings["ttl"], self.signing["kid"],
        )
        # Masked: a token is a credential, even a short-lived one.
        return {self.settings["variable"]: {"data": token, "mask": True}}

    def _derive(self, payload) -> dict:
        """Facts GitHub states outright that Drone leaves to be worked out."""
        build = payload.get("build", {})
        ref = build.get("ref") or ""
        # Covers both "pull_request" and Woodpecker's "pull_request_closed", so a closed
        # PR keeps its head/base refs rather than losing them.
        pull_request = str(build.get("event") or "").startswith("pull_request")

        return {
            "ref_type": "tag" if ref.startswith("refs/tags/") else
                        "branch" if ref.startswith("refs/heads/") else "",
            # Drone fills source/target on every event; GitHub only has head/base on a
            # pull request, and asserting a head_ref for a push would mislead a policy
            # written against GitHub's meaning.
            "head_ref": build.get("source", "") if pull_request else "",
            "base_ref": build.get("target", "") if pull_request else "",
            # Every Drone runner is one you run yourself.
            "runner_environment": "self-hosted",
        }

    def _default_audience(self, payload) -> str:
        """GitHub defaults `aud` to the URL of the repository owner.

        Drone gives us the repo's own URL, and the owner's is its parent — the same
        thing GitHub means by 'https://github.com/octo-org'.
        """
        link = payload.get("repo", {}).get("link", "")
        if link:
            return link.rsplit("/", 1)[0]
        return self.settings["issuer"]

    def _subject(self, payload, claims) -> str:
        """Compose `sub` the way GitHub does, from include_claim_keys.

        Each key contributes "key:value", joined with colons — so ["repo", "context"]
        gives repo:octo-org/octo-repo:environment:prod. A key whose claim is empty is
        skipped rather than contributing a dangling separator.
        """
        if self.settings["subject"]:
            return self._interpolate(self.settings["subject"], payload)
        return ":".join(self._subject_segments(payload, claims))

    def _subject_segments(self, payload, claims) -> list[str]:
        """The non-empty "key:value" pieces the subject is joined from.

        Kept separate from _subject so the groups claim can reuse them: the groups are
        the subject and each of its prefixes at these segment boundaries.
        """
        segments = []
        for key in self.settings["include_claim_keys"]:
            if key == "context":
                # GitHub's contextual segment: what the build is actually doing. May be
                # empty (e.g. a bare event with no ref), in which case it contributes
                # nothing rather than a dangling separator.
                context = self._context(payload)
                if context:
                    segments.append(context)
                continue

            # "repo" is GitHub's alias for the repository claim; every other key names
            # a claim in the token itself, so custom claims can compose a subject too.
            claim = "repository" if key == "repo" else key
            value = claims.get(claim, "")
            if value == "" or value is None:
                self.log.debug("Subject: claim %s is empty, leaving it out", claim)
                continue
            segments.append(f"{key}:{self._escape(value)}")

        return segments

    def _groups(self, payload, claims) -> list[str]:
        """The subject and each of its segment-prefixes, for the groups claim.

        For sub repo:acme/web:ref:refs/heads/main this yields
        [repo:acme/web, repo:acme/web:ref:refs/heads/main]. A Kubernetes API server maps
        these via groupsClaim, so RBAC can bind the coarse repo:acme/web (every build of
        the repo) or a specific tier — and the same strings are what an IAM trust policy
        matches on `sub`. A raw `subject` template has no segments, so its whole value is
        emitted as a single group.
        """
        if self.settings["subject"]:
            subject = self._interpolate(self.settings["subject"], payload)
            return [subject] if subject else []
        segments = self._subject_segments(payload, claims)
        return [":".join(segments[:i]) for i in range(1, len(segments) + 1)]

    def _context(self, payload) -> str:
        build = payload.get("build", {})
        if build.get("deploy_to"):
            return f"environment:{self._escape(build['deploy_to'])}"
        if build.get("event") == "pull_request":
            return "pull_request"
        if build.get("ref"):
            return f"ref:{self._escape(build['ref'])}"
        return ""

    def _escape(self, value) -> str:
        # A colon inside a value would otherwise be indistinguishable from the
        # separator between segments, and a subject is matched by string comparison.
        return str(value).replace(":", "%3A")

    def _resolve(self, path, payload):
        """Look a dotted path up in the request: repo.slug, build.params.REASON."""
        value = payload
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return MISSING
            value = value[part]
        return value

    def _interpolate(self, template, payload):
        """Fill {repo.slug}-style placeholders in a template from the request.

        A single left-to-right pass: a resolved value is never rescanned, so a value
        that itself contains braces (deploy_to is attacker-chosen on a promotion)
        cannot drive further substitution or loop. Substituted values are escaped like
        subject segments, so a colon in a value can't be confused with a separator.
        """
        def substitute(match):
            path = match.group(1)
            value = self._resolve(path, payload)
            if value is MISSING:
                self.log.warning("No %s in the request, using '' in %r", path, template)
                value = ""
            return self._escape(value)

        return _PLACEHOLDER.sub(substitute, template)
