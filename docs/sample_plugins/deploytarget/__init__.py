from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class DeployTarget(BaseEnvironPlugin):
    """Hand out per-environment variables, but only to a build that asked for them.

    Drone sets `deploy_to` only on a promotion — a deliberate act by someone with
    access to the repo. Keying off it means production credentials never reach a
    build triggered by a push, a cron, or a fork's pull request, even though the
    extension is called for all of them.
    """

    friendly_name = "deploytarget"
    version = "0.1.0"
    # This plugin hands out deploy credentials, so it declares itself fail-closed: if it
    # errors, the build fails even under on_plugin_error: skip, rather than deploying
    # with no credentials. See the README's "Error handling" section.
    fail_closed = True
    options = [
        {
            "name": "targets",
            "type": dict,
            "default": {},
            "help": "Deploy target name -> the variables a build promoted to it gets",
        },
        {
            "name": "require_promote",
            "type": bool,
            "default": True,
            "help": "Only inject on promote/rollback events, never on a push",
        },
        {
            "name": "announce",
            "type": bool,
            "default": True,
            "help": "Also set DEPLOY_TARGET to the matched target name",
        },
    ]

    promotion_events = ("promote", "rollback")

    def hook_environment(self, request):
        build = request.build

        if self.settings["require_promote"] and build.event not in self.promotion_events:
            self.log.debug(
                "Build %s is a %s, not a promotion — no deploy variables",
                build.number, build.event,
            )
            return None

        target = build.deploy_to
        if not target:
            self.log.debug("Build %s names no deploy target", build.number)
            return None

        variables = self.settings["targets"].get(target)
        if variables is None:
            # Failing shut: an unrecognised target gets nothing rather than the
            # variables of some other environment.
            self.log.warning(
                "Build %s promoted to unknown target %r — configured targets are %s",
                build.number, target, sorted(self.settings["targets"]) or "none",
            )
            return None

        self.log.info(
            "Build %s promoted to %s by %s — injecting %s",
            build.number, target, build.sender or "unknown", ", ".join(sorted(variables)),
        )

        variables = dict(variables)
        if self.settings["announce"]:
            variables.setdefault("DEPLOY_TARGET", target)
        return variables
