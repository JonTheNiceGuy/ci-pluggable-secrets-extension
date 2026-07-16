import copy
import inspect
import logging


class PluginConfigError(Exception):
    """Raised when a plugin's config-file section is invalid."""


class BaseEnvironPlugin:
    """Base class every environment plugin inherits from.

    A plugin is installed by dropping a package into a plugin search path; it is
    enabled by naming it in the config file. Any method named `hook_<name>` is
    registered against the `<name>` hook automatically, so `hook_environment`
    makes the plugin contribute to the response Drone receives.

    `options` declares the settings the plugin accepts from its config-file
    section, using the same spec-dict style as the tool's argparse options:
    name, default, choices, required, type, help.
    """

    hook_prefix = "hook_"
    options: list[dict] = []
    friendly_name = "UNDEFINED"
    version = "0.0.0"

    # A plugin that hands out credentials should set this. When True, an error from this
    # plugin fails the request even under the global on_plugin_error: skip — silently
    # shipping a green build with a credential missing is worse than failing it.
    fail_closed = False

    # The registry sets this to the plugin's unique config-key name when it loads. Used
    # to key results (friendly_name is not guaranteed unique); "" until then.
    registry_name: str = ""

    def __init__(self):
        # A plugin must name itself: friendly_name keys its results, its logger, and its
        # /healthz entry. A helper subclass that forgot to would otherwise ship as
        # "UNDEFINED" and quietly collide with any other that did the same.
        if not self.friendly_name or self.friendly_name == "UNDEFINED":
            raise PluginConfigError(
                f"{type(self).__name__} must set a friendly_name class attribute"
            )
        self.settings: dict = {}
        self.log = logging.getLogger(f"plugin.{self.friendly_name}")

    def register_hooks(self) -> list:
        cls = type(self)
        discovered = []
        for name in dir(cls):
            # Only real methods are hooks. `hook_prefix` itself starts with the prefix
            # but is a config knob, not a hook, and a callable attribute that is not a
            # function (say, a callable instance) is not one either.
            if not name.startswith(self.hook_prefix) or name == "hook_prefix":
                continue
            if inspect.isfunction(getattr(cls, name)):
                discovered.append(name[len(self.hook_prefix):])
        return sorted(discovered)

    def configure(self, settings: dict) -> None:
        settings = dict(settings or {})
        settings.pop("enabled", None)
        declared = {}

        for item in self.options:
            name = item.get("name")
            if name is None:
                raise PluginConfigError(f"In {self.describe()} an option is missing a name")

            if name in settings:
                value = settings.pop(name)
            elif "default" in item:
                # Copy it: a mutable default ({}/[]) would otherwise be shared by every
                # instance of the plugin, so one instance mutating self.settings would
                # leak into the next.
                value = copy.deepcopy(item["default"])
            elif item.get("required"):
                raise PluginConfigError(
                    f"In {self.describe()} the required option {name} was not set"
                )
            else:
                value = None

            choices = item.get("choices")
            if choices is not None and value not in choices:
                raise PluginConfigError(
                    f"In {self.describe()} the option {name} must be one of "
                    f"{choices}, got {value!r}"
                )

            expected = item.get("type")
            if expected is not None and value is not None and not isinstance(value, expected):
                raise PluginConfigError(
                    f"In {self.describe()} the option {name} must be "
                    f"{expected.__name__}, got {type(value).__name__}"
                )

            declared[name] = value

        for name in settings:
            self.log.warning(
                "In %s the option %s is not recognised and will be ignored",
                self.describe(), name,
            )

        self.settings = declared

    def run_hook(self, hook, request=None):
        method = getattr(self, f"{self.hook_prefix}{hook}", None)
        if method is None:
            return None
        return method(request)

    def describe(self):
        return f"{self.friendly_name}: {self.version}"
