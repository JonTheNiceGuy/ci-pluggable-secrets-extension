"""Speak Woodpecker's secret extension, using the same plugins.

Woodpecker has no environment extension. Its nearest equivalent is the *secret*
extension: Woodpecker asks an HTTP service what secrets a pipeline should get, and
merges them with the ones configured in its own UI. So the plugins here can serve
Woodpecker too — what differs is the transport, not the question being asked.

Three things had to be reconciled:

* The payload. Woodpecker sends {repo, pipeline}, with its own field names. It is
  normalised here into the same request the plugins already see, so a plugin never
  learns which CI system it is talking to.
* The event vocabulary. Woodpecker says "deployment" where Drone says "promote", and
  "manual" where Drone says "custom". Without mapping these, a plugin keyed on
  `build.event == "promote"` would silently never fire on Woodpecker — the worst kind
  of bug, because a deploy would just quietly get no credentials.
* The response. Woodpecker wants {"secrets": [...]}, each with the events it applies
  to, and rejects a secret that names no event.
"""

import logging

from pydantic import BaseModel, ConfigDict

from ci_pluggable_secrets_extension.models import Build, EnvironRequest, Repo

# Woodpecker's event names, mapped to the ones the plugins already use (Drone's).
# Anything not listed passes through unchanged (push, pull_request, tag, cron, release,
# pull_request_closed) — the native name is always kept as `event_native` too. The
# mapped `event`/`event_name` therefore mirrors the CI's own vocabulary, not GitHub's:
# a plugin or verifier that keys on it must expect `promote`/`custom`/`tag`/`cron`,
# which differ from GitHub's `push`/`workflow_dispatch`/`schedule`.
EVENTS = {
    "deployment": "promote",
    "manual": "custom",
}


class WoodpeckerModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class WoodpeckerRepo(WoodpeckerModel):
    id: int = 0
    forge_remote_id: str = ""
    owner: str = ""
    name: str = ""
    full_name: str = ""
    forge_url: str = ""
    clone_url: str = ""
    default_branch: str = ""
    private: bool = False
    visibility: str = ""
    active: bool = False
    config_file: str = ""
    timeout: int = 0


class WoodpeckerPipeline(WoodpeckerModel):
    id: int = 0
    number: int = 0
    parent: int = 0
    event: str = ""
    status: str = ""
    deploy_to: str = ""
    deploy_task: str = ""
    commit: str = ""
    branch: str = ""
    ref: str = ""
    refspec: str = ""
    title: str = ""
    message: str = ""
    author: str = ""
    author_email: str = ""
    sender: str = ""
    forge_url: str = ""
    variables: dict[str, str] = {}
    created: int = 0
    started: int = 0
    finished: int = 0


class WoodpeckerRequest(WoodpeckerModel):
    """The body Woodpecker POSTs to a secret extension."""

    repo: WoodpeckerRepo = WoodpeckerRepo()
    pipeline: WoodpeckerPipeline = WoodpeckerPipeline()
    # netrc arrives only when the server is configured to send it. It holds forge
    # credentials, so it is deliberately not passed on to plugins.


class Secret(BaseModel):
    """One entry in the response Woodpecker expects."""

    name: str
    value: str
    # Empty means every image, which is what an environment variable means in Drone.
    images: list[str] = []
    # Woodpecker rejects a secret that names no event, so this is never empty.
    events: list[str]


def full_ref(pipeline) -> str:
    """Woodpecker's `ref` is not always a git ref.

    On a push it is "refs/heads/main"; on a pipeline started through the API — which
    includes every deployment — it can be the bare branch name. Left alone, the token's
    `ref` claim would say "main" on Woodpecker and "refs/heads/main" on Drone for the
    same commit, and `ref_type` would be missing entirely, so a verifier's policy would
    match on one CI system and not the other.
    """
    ref = pipeline.ref
    if ref.startswith("refs/"):
        return ref
    # A release is tag-shaped: its bare ref names a tag, not a branch.
    if pipeline.event in ("tag", "release") and ref:
        return f"refs/tags/{ref}"
    if pipeline.branch:
        return f"refs/heads/{pipeline.branch}"
    return ref


def to_request(incoming: WoodpeckerRequest) -> EnvironRequest:
    """Normalise Woodpecker's payload into the request the plugins already understand."""
    repo, pipeline = incoming.repo, incoming.pipeline
    native_event = pipeline.event

    return EnvironRequest(
        repo=Repo(
            id=repo.id,
            uid=str(repo.forge_remote_id),
            namespace=repo.owner,
            name=repo.name,
            slug=repo.full_name or f"{repo.owner}/{repo.name}",
            link=repo.forge_url,
            git_http_url=repo.clone_url,
            default_branch=repo.default_branch,
            private=repo.private,
            visibility=repo.visibility,
            active=repo.active,
            config=repo.config_file,
            timeout=repo.timeout,
        ),
        build=Build(
            id=pipeline.id,
            number=pipeline.number,
            parent=pipeline.parent,
            status=pipeline.status,
            event=EVENTS.get(native_event, native_event),
            link=pipeline.forge_url,
            title=pipeline.title,
            message=pipeline.message,
            after=pipeline.commit,
            ref=full_ref(pipeline),
            target=pipeline.branch,
            source=pipeline.branch,
            author_login=pipeline.author,
            author_email=pipeline.author_email,
            sender=pipeline.sender or pipeline.author,
            params=pipeline.variables,
            deploy_to=pipeline.deploy_to,
            created=pipeline.created,
            started=pipeline.started,
            finished=pipeline.finished,
            # Preserved so a plugin that needs to be exact can be, and so nothing is
            # lost in translation.
            event_native=native_event,
            ci="woodpecker",
        ),
    )


def to_secrets(variables, event) -> list[Secret]:
    """Turn the plugins' variables into the secrets Woodpecker asked for.

    Every variable becomes a secret scoped to the event of the pipeline that asked for
    it — Woodpecker rejects a secret with no events, and this pipeline's event is the
    only one these values were computed for.
    """
    secrets = []
    for variable in variables:
        # Woodpecker rejects a secret with an empty value, and it rejects the whole
        # response along with it — so one plugin returning "" would cost every other
        # plugin its variables. Drop it here instead.
        if not variable.data:
            logging.warning(
                "Variable %s is empty, and Woodpecker rejects empty secrets — "
                "leaving it out", variable.name,
            )
            continue
        secrets.append(
            Secret(name=variable.name, value=variable.data, images=[], events=[event])
        )
    return secrets
