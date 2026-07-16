"""Discovery and dispatch for environment plugins.

A plugin is installed by placing a package on a plugin search path — this
directory, or any directory listed under `plugin_paths` in the config file — and
enabled by naming it in the config file's `plugins` section. Each plugin's
`hook_<name>` methods are registered against the `<name>` hook, so dispatch never
needs to know which plugins exist.
"""

import importlib
import importlib.util
import logging
import pkgutil
import sys
from pathlib import Path

from ci_pluggable_secrets_plugin import BaseEnvironPlugin

BUILTIN_PATH = Path(__file__).parent
# External drop-in plugins load under this namespace. It is deliberately CI-agnostic:
# the extension serves both Drone and Woodpecker, and the example plugins under
# docs/sample_plugins/ are loaded this way via `plugin_paths`.
EXTERNAL_NAMESPACE = "ci_environ_plugins"


class PluginLoadError(Exception):
    """Raised when an enabled plugin cannot be found or loaded."""


def discover(plugin_paths=None) -> dict[str, Path]:
    """Map plugin name to the search path it was found on, nearest path first."""
    found: dict[str, Path] = {}
    for path in [BUILTIN_PATH, *(plugin_paths or [])]:
        if not path.is_dir():
            logging.warning("Plugin path %s does not exist, skipping", path)
            continue
        for _, name, _ in pkgutil.iter_modules([str(path)]):
            if name in found:
                logging.warning(
                    "Plugin %s found in %s shadows the one in %s", name, found[name], path
                )
                continue
            found[name] = path
    return found


def _import(name, path):
    if path == BUILTIN_PATH:
        return importlib.import_module(f"{__name__}.{name}")

    # Plugins dropped into an external directory are not importable as
    # `plugins.<name>`, so load them under their own namespace by file location.
    module_name = f"{EXTERNAL_NAMESPACE}.{name}"
    if module_name in sys.modules:
        return sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(
        module_name,
        path / name / "__init__.py",
        submodule_search_locations=[str(path / name)],
    )
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_file_location(module_name, path / f"{name}.py")
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"Plugin {name} in {path} is not an importable module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _plugin_class(module):
    """The one BaseEnvironPlugin subclass a plugin module defines.

    Only classes defined *in this module* count, so an imported base class (or a base a
    plugin subclasses) is never mistaken for the plugin — which the old "first subclass
    by dir() order" could do, silently loading the wrong class. More than one is an
    error: a module is one plugin.
    """
    candidates = [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and issubclass(obj, BaseEnvironPlugin)
        and obj is not BaseEnvironPlugin
        and obj.__module__ == module.__name__
    ]
    if len(candidates) > 1:
        raise PluginLoadError(
            f"Module {module.__name__} defines more than one plugin class "
            f"({', '.join(c.__name__ for c in candidates)}); a plugin module must "
            "define exactly one"
        )
    return candidates[0] if candidates else None


class Registry:
    """The set of loaded plugins and their hooks for one application.

    Held on `app.state.registry` so two apps built in one process do not share (and
    retroactively rewrite) each other's plugins. A module-level default instance backs
    the `plugins` / `hooks` / `load_plugins_and_hooks` / `run_hook` names below, which
    remain as convenience aliases.
    """

    def __init__(self):
        self.plugins: dict[str, BaseEnvironPlugin] = {}
        self.hooks: dict[str, list[BaseEnvironPlugin]] = {}

    def load(self, config=None, plugin_paths=None) -> dict:
        """Load every plugin enabled in the config and register its hooks.

        Config order is preserved: it determines the order plugins run in, and so
        which plugin wins when two contribute the same variable.
        """
        # Cleared in place, not reassigned, so the module-level aliases stay valid.
        self.plugins.clear()
        self.hooks.clear()

        if config is None:
            enabled = {}
        elif isinstance(config, dict):
            enabled = dict(config)
        else:
            enabled = dict(config.plugins)

        paths = plugin_paths if plugin_paths is not None else getattr(config, "plugin_paths", [])
        available = discover(paths)

        for name, settings in enabled.items():
            if settings.get("enabled") is False:
                logging.debug("Plugin %s is disabled in the config, skipping", name)
                continue
            if name not in available:
                raise PluginLoadError(
                    f"Plugin {name} is enabled in the config but was not found on any "
                    f"plugin path (searched: {', '.join(str(p) for p in [BUILTIN_PATH, *paths])})"
                )

            module = _import(name, available[name])
            plugin_class = _plugin_class(module)
            if plugin_class is None:
                raise PluginLoadError(
                    f"Plugin {name} defines no BaseEnvironPlugin subclass"
                )

            plugin = plugin_class()
            plugin.configure(settings)
            # The config key is this plugin's unique name in the registry; results are
            # keyed by it, not by the free-text friendly_name two plugins could share.
            plugin.registry_name = name
            self.plugins[name] = plugin
            logging.debug("Loaded plugin: %s from %s", plugin.describe(), available[name])

        for name, plugin in self.plugins.items():
            for hook in plugin.register_hooks():
                self.hooks.setdefault(hook, []).append(plugin)
                logging.debug("Registered hook %s in %s", hook, plugin.describe())

        for name in available:
            if name not in self.plugins:
                logging.debug("Plugin %s is installed but not enabled in the config", name)

        return self.plugins

    def run_hook(self, hook, request=None, on_error="fail") -> dict:
        """Run every plugin registered against `hook`, keyed by its registry name."""
        results = {}
        for plugin in self.hooks.get(hook, []):
            # Registry name is unique; friendly_name is not, and keying results by it
            # would let one plugin's output silently overwrite another's.
            key = getattr(plugin, "registry_name", None) or plugin.friendly_name
            try:
                results[key] = plugin.run_hook(hook, request)
            except Exception:
                logging.exception("Plugin %s failed on the %s hook", plugin.describe(), hook)
                # A fail-closed plugin (a credential issuer) overrides on_error: skip —
                # its variables missing must fail the build, not be quietly dropped.
                if on_error == "fail" or getattr(plugin, "fail_closed", False):
                    raise
        return results


# A process-wide default registry, and the aliases that delegate to it. Code that wants
# isolation (a second app, a test) can construct its own Registry and pass it to
# create_app instead.
default_registry = Registry()
plugins = default_registry.plugins
hooks = default_registry.hooks


def load_plugins_and_hooks(config=None, plugin_paths=None) -> dict:
    return default_registry.load(config, plugin_paths)


def run_hook(hook, request=None, on_error="fail") -> dict:
    return default_registry.run_hook(hook, request, on_error)
