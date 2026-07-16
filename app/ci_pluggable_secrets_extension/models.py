from pydantic import BaseModel, ConfigDict, field_validator


class DroneModel(BaseModel):
    # Drone adds fields to these payloads between releases; accepting unknown keys
    # keeps an older extension working against a newer server.
    model_config = ConfigDict(extra="allow")


class Repo(DroneModel):
    id: int = 0
    uid: str = ""
    user_id: int = 0
    namespace: str = ""
    name: str = ""
    slug: str = ""
    scm: str = ""
    git_http_url: str = ""
    git_ssh_url: str = ""
    link: str = ""
    default_branch: str = ""
    private: bool = False
    visibility: str = ""
    active: bool = False
    config: str = ""
    trusted: bool = False
    protected: bool = False
    ignore_forks: bool = False
    ignore_pulls: bool = False
    cancel_pulls: bool = False
    timeout: int = 0
    counter: int = 0
    synced: int = 0
    created: int = 0
    updated: int = 0
    version: int = 0


class Build(DroneModel):
    id: int = 0
    repo_id: int = 0
    number: int = 0
    parent: int = 0
    status: str = ""
    error: str = ""
    event: str = ""
    action: str = ""
    link: str = ""
    timestamp: int = 0
    title: str = ""
    message: str = ""
    before: str = ""
    after: str = ""
    ref: str = ""
    source_repo: str = ""
    source: str = ""
    target: str = ""
    author_login: str = ""
    author_name: str = ""
    author_email: str = ""
    author_avatar: str = ""
    sender: str = ""
    params: dict[str, str] = {}
    cron: str = ""
    deploy_to: str = ""
    deploy_id: int = 0
    started: int = 0
    finished: int = 0
    created: int = 0
    updated: int = 0
    version: int = 0


class EnvironRequest(DroneModel):
    """The body Drone POSTs to the environment extension."""

    repo: Repo = Repo()
    build: Build = Build()


class SecretRequest(DroneModel):
    """The body Drone POSTs to the *secret* extension, asking for one named secret.

    `name` is the value a step referenced with `from_secret`; the extension answers with
    the matching variable (if any of the plugins produced it) or a 404.
    """

    path: str = ""
    name: str = ""
    repo: Repo = Repo()
    build: Build = Build()


class Variable(BaseModel):
    """One entry in the array Drone expects back."""

    # Reject unknown keys: a plugin returning {"data": ..., "masked": True} (a typo for
    # "mask") would otherwise be silently accepted with mask=False, and the secret would
    # reach the build log unmasked. Fail loudly instead.
    model_config = ConfigDict(extra="forbid")

    name: str
    data: str
    mask: bool = False

    # Only the Drone *secret* endpoint uses these — they map to drone.Secret's per-secret
    # gating. Both default False, i.e. the secret is withheld from pull-request builds
    # (the safe default); a plugin opts a secret into PR use via the expanded return form.
    pull_request: bool = False
    pull_request_push: bool = False

    @field_validator("data", mode="before")
    @classmethod
    def _stringify(cls, value):
        # A plugin may hand back a number or bool for a variable's value. Drone only
        # carries strings, so coerce here — and coerce identically whether the plugin
        # used the flat {"name": 1} form or the expanded {"name": {"data": 1}} form.
        if value is None or isinstance(value, str):
            return value
        return str(value)

    def to_environment(self) -> dict:
        """The shape the Drone environment extension (and the Woodpecker path) expect —
        without the secret-only gating fields."""
        return {"name": self.name, "data": self.data, "mask": self.mask}

    def to_drone_secret(self) -> dict:
        """The drone.Secret shape the Drone secret extension returns."""
        return {
            "name": self.name,
            "data": self.data,
            "pull_request": self.pull_request,
            "pull_request_push": self.pull_request_push,
        }
