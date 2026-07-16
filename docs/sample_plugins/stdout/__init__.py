import json
import sys

from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class Stdout(BaseEnvironPlugin):
    """Log the whole request to stdout, and announce itself in the response."""

    friendly_name = "stdout"
    version = "0.1.0"
    options = [
        {
            "name": "pretty",
            "type": bool,
            "default": True,
            "help": "Indent the request JSON rather than printing it on one line",
        },
        {
            "name": "variable",
            "type": str,
            "default": "stdout_plugin",
            "help": "The name of the variable this plugin adds to the response",
        },
    ]

    def hook_environment(self, request):
        payload = request.model_dump(mode="json")
        # flush: under a container runtime stdout is a pipe, so it is block-buffered
        # and the log of a request would otherwise appear long after the build asked.
        print(
            json.dumps(payload, indent=2 if self.settings["pretty"] else None),
            file=sys.stdout,
            flush=True,
        )
        return {self.settings["variable"]: "enabled"}
