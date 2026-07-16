"""Log the request the CI hands the extension, and contribute nothing.

A bundled, built-in plugin (like buildtoken), off unless you enable it. A pure observer:
unlike the `stdout` example, which also announces itself with a variable, `logreceive`
returns None, so it changes nothing about the build. It exists to show exactly what Drone
or Woodpecker passes into the stack — useful when writing a new plugin, or when a build is
not getting the variable you expected and you want to see the request the extension
actually received.

What it logs is the request the *plugins* see (an `EnvironRequest`: repo + build
metadata). That is not secret material — secrets flow the other way, in the response —
and a Woodpecker request has already been normalised, so its `netrc` never reaches here.
"""

import json
import logging

from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class LogReceive(BaseEnvironPlugin):
    friendly_name = "logreceive"
    version = "0.1.0"
    options = [
        {
            "name": "level",
            "type": str,
            "default": "INFO",
            "choices": ["DEBUG", "INFO", "WARNING"],
            "help": "The level to log the request at",
        },
    ]

    def hook_environment(self, request):
        payload = request.model_dump(mode="json")
        level = logging.getLevelNamesMapping()[self.settings["level"]]
        # One compact line, never indented: a log record must stay on a single line, or
        # aggregators split each brace onto its own entry. json.dumps escapes any newline
        # inside a value (e.g. a commit message), so the whole request stays on one line.
        self.log.log(
            level,
            "received request: %s",
            json.dumps(payload, separators=(",", ":")),
        )
        # Contribute nothing: this plugin only observes.
        return None
