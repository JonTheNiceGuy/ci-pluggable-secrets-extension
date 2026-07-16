import pytest

from ci_pluggable_secrets_plugin import BaseEnvironPlugin, PluginConfigError
from ci_pluggable_secrets_extension import config as configuration
from ci_pluggable_secrets_extension import plugins
from ci_pluggable_secrets_extension.models import EnvironRequest
from ci_pluggable_secrets_extension.plugins import Registry

from .conftest import EXAMPLE_PLUGINS


@pytest.fixture(autouse=True)
def _clean_default_registry():
    """These tests load into the process-wide default registry; clear it after each so
    one test's plugins cannot leak into the next."""
    yield
    plugins.plugins.clear()
    plugins.hooks.clear()


def _write_plugin(directory, package, source):
    (directory / package).mkdir(parents=True)
    (directory / package / "__init__.py").write_text(source)

EXTERNAL_PLUGIN = '''
from ci_pluggable_secrets_plugin import BaseEnvironPlugin


class Greeter(BaseEnvironPlugin):
    friendly_name = "greeter"
    version = "9.9.9"
    options = [{"name": "greeting", "default": "hello"}]

    def hook_environment(self, request):
        return {"GREETING": self.settings["greeting"]}
'''


def write_config(tmp_path, body):
    path = tmp_path / "config.yaml"
    path.write_text(f"server:\n  secret: s3cret\n{body}")
    return configuration.load(path)


def test_a_plugin_dropped_onto_a_plugin_path_is_loaded(tmp_path, body):
    external = tmp_path / "plugins"
    (external / "greeter").mkdir(parents=True)
    (external / "greeter" / "__init__.py").write_text(EXTERNAL_PLUGIN)

    config = write_config(
        tmp_path,
        f"plugin_paths:\n  - {external}\nplugins:\n  greeter:\n    greeting: g'day\n",
    )
    loaded = plugins.load_plugins_and_hooks(config)

    assert loaded["greeter"].describe() == "greeter: 9.9.9"
    assert plugins.hooks["environment"] == [loaded["greeter"]]

    request = EnvironRequest.model_validate_json(body)
    results = plugins.run_hook("environment", request)
    assert results == {"greeter": {"GREETING": "g'day"}}


def test_an_installed_but_unlisted_plugin_does_not_run(tmp_path):
    config = write_config(tmp_path, f"plugin_paths:\n  - {EXAMPLE_PLUGINS}\nplugins: {{}}\n")
    assert plugins.load_plugins_and_hooks(config) == {}
    assert "stdout" in plugins.discover([EXAMPLE_PLUGINS])


def test_an_explicitly_disabled_plugin_does_not_run(tmp_path):
    config = write_config(
        tmp_path,
        f"plugin_paths:\n  - {EXAMPLE_PLUGINS}\nplugins:\n  stdout:\n    enabled: false\n",
    )
    assert plugins.load_plugins_and_hooks(config) == {}


def test_a_missing_plugin_is_a_startup_error(tmp_path):
    config = write_config(tmp_path, "plugins:\n  nonexistent:\n")
    with pytest.raises(plugins.PluginLoadError, match="not found on any plugin path"):
        plugins.load_plugins_and_hooks(config)


def test_config_order_is_the_hook_order(tmp_path):
    external = tmp_path / "plugins"
    (external / "greeter").mkdir(parents=True)
    (external / "greeter" / "__init__.py").write_text(EXTERNAL_PLUGIN)

    config = write_config(
        tmp_path,
        f"plugin_paths:\n  - {external}\n  - {EXAMPLE_PLUGINS}\n"
        "plugins:\n  greeter:\n  stdout:\n",
    )
    plugins.load_plugins_and_hooks(config)
    assert [p.friendly_name for p in plugins.hooks["environment"]] == ["greeter", "stdout"]


def test_hooks_are_registered_from_method_names():
    class Multi(BaseEnvironPlugin):
        friendly_name = "multi"

        def hook_environment(self, request): ...
        def hook_startup(self, request): ...
        def helper(self): ...

    assert Multi().register_hooks() == ["environment", "startup"]


def test_defaults_are_applied_and_unknown_options_ignored(caplog):
    class Configured(BaseEnvironPlugin):
        friendly_name = "configured"
        options = [{"name": "colour", "default": "blue"}]

    plugin = Configured()
    plugin.configure({"typo": True})

    assert plugin.settings == {"colour": "blue"}
    assert "not recognised" in caplog.text


def test_a_required_option_must_be_set():
    class Configured(BaseEnvironPlugin):
        friendly_name = "configured"
        options = [{"name": "token", "required": True}]

    with pytest.raises(PluginConfigError, match="required option token"):
        Configured().configure({})


def test_an_option_is_checked_against_its_choices_and_type():
    class Configured(BaseEnvironPlugin):
        friendly_name = "configured"
        options = [
            {"name": "mode", "choices": ["on", "off"], "default": "off"},
            {"name": "count", "type": int, "default": 1},
        ]

    with pytest.raises(PluginConfigError, match="must be one of"):
        Configured().configure({"mode": "sideways"})

    with pytest.raises(PluginConfigError, match="must be int"):
        Configured().configure({"count": "lots"})


def test_the_secret_can_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DRONE_ENV_PLUGIN_SECRET", "from-the-env")
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  secret: ${DRONE_ENV_PLUGIN_SECRET}\nplugins:\n  stdout:\n")
    assert configuration.load(path).secret == "from-the-env"


def test_a_missing_secret_is_a_startup_error(tmp_path, monkeypatch):
    monkeypatch.delenv("DRONE_ENV_PLUGIN_SECRET", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  port: 3000\n")
    with pytest.raises(configuration.ConfigError, match="no shared secret"):
        configuration.load(path)


# --- config validation (T4-2) --------------------------------------------------

def test_an_invalid_log_level_is_a_startup_error(tmp_path):
    """Caught at load, not deep inside logging where it would surface obscurely."""
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  secret: s3cret\n  log_level: LOUD\n")
    with pytest.raises(configuration.ConfigError, match="log_level"):
        configuration.load(path)


def test_a_non_mapping_woodpecker_block_is_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  secret: s3cret\nwoodpecker: true\n")
    with pytest.raises(configuration.ConfigError, match="woodpecker must be a mapping"):
        configuration.load(path)


def test_woodpecker_with_both_key_sources_is_rejected(tmp_path):
    """The file would silently win, so the config would not mean what it says."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "server:\n  secret: s3cret\n"
        "woodpecker:\n"
        "  public_key_file: /keys/woodpecker.pem\n"
        "  public_key_url: http://woodpecker/api/signature/public-key\n"
    )
    with pytest.raises(configuration.ConfigError, match="both public_key_file"):
        configuration.load(path)


def test_a_non_mapping_drone_secret_block_is_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  secret: s3cret\ndrone_secret: true\n")
    with pytest.raises(configuration.ConfigError, match="drone_secret must be a mapping"):
        configuration.load(path)


def test_woodpecker_and_drone_secret_cannot_share_a_path(tmp_path):
    """They speak different protocols, so they cannot share an endpoint."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "server:\n  secret: s3cret\n"
        "woodpecker:\n  path: /secrets\n  public_key_file: /keys/woodpecker.pem\n"
        "drone_secret:\n  path: /secrets\n"
    )
    with pytest.raises(configuration.ConfigError, match="distinct paths"):
        configuration.load(path)


def test_the_woodpecker_key_refresh_age_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("WOODPECKER_SECRET_AGE_SECONDS", "45")
    path = tmp_path / "config.yaml"
    path.write_text(
        "server:\n  secret: s3cret\n"
        "woodpecker:\n  public_key_file: /keys/woodpecker.pem\n"
    )
    assert configuration.load(path).woodpecker.key_max_age == 45


# --- registry & loading hardening (Tier 3) ------------------------------------

def test_two_plugins_sharing_a_friendly_name_both_contribute(tmp_path, body):
    """Results are keyed by the unique registry name, not the free-text friendly_name —
    otherwise one twin silently overwrites the other's variables (T3-2)."""
    ext = tmp_path / "plugins"
    for pkg, var in (("alpha", "ALPHA"), ("beta", "BETA")):
        _write_plugin(
            ext, pkg,
            "from ci_pluggable_secrets_plugin import BaseEnvironPlugin\n"
            "class P(BaseEnvironPlugin):\n"
            "    friendly_name = 'twin'\n"
            "    def hook_environment(self, request):\n"
            f"        return {{'{var}': '1'}}\n",
        )
    config = write_config(tmp_path, f"plugin_paths:\n  - {ext}\nplugins:\n  alpha:\n  beta:\n")
    plugins.load_plugins_and_hooks(config)

    request = EnvironRequest.model_validate_json(body)
    results = plugins.run_hook("environment", request)
    assert results == {"alpha": {"ALPHA": "1"}, "beta": {"BETA": "1"}}


def test_a_mutable_option_default_is_not_shared_between_instances():
    """One instance mutating self.settings must not leak into the next (T3-3)."""
    class WithDict(BaseEnvironPlugin):
        friendly_name = "withdict"
        options = [{"name": "data", "default": {}}]

    first = WithDict()
    first.configure({})
    first.settings["data"]["poison"] = True

    second = WithDict()
    second.configure({})
    assert second.settings["data"] == {}


def test_a_module_with_two_plugin_classes_is_an_error(tmp_path):
    """A plugin module is one plugin; two own-module classes is ambiguous (T3-4)."""
    ext = tmp_path / "plugins"
    _write_plugin(
        ext, "twoclass",
        "from ci_pluggable_secrets_plugin import BaseEnvironPlugin\n"
        "class A(BaseEnvironPlugin):\n    friendly_name = 'a'\n"
        "class B(BaseEnvironPlugin):\n    friendly_name = 'b'\n",
    )
    config = write_config(tmp_path, f"plugin_paths:\n  - {ext}\nplugins:\n  twoclass:\n")
    with pytest.raises(plugins.PluginLoadError, match="more than one plugin class"):
        plugins.load_plugins_and_hooks(config)


def test_a_plugin_without_a_friendly_name_is_rejected():
    """A nameless plugin would ship as "UNDEFINED" and collide with any other (T3-5)."""
    class Nameless(BaseEnvironPlugin):
        pass

    with pytest.raises(PluginConfigError, match="friendly_name"):
        Nameless()


def test_logreceive_logs_the_request_and_contributes_nothing(caplog, body):
    """The bundled pure-observer plugin: it logs what the CI sent and returns None."""
    import logging

    from ci_pluggable_secrets_extension.models import EnvironRequest
    from ci_pluggable_secrets_extension.plugins.logreceive import LogReceive

    plugin = LogReceive()
    plugin.configure({})
    request = EnvironRequest.model_validate_json(body)

    with caplog.at_level(logging.INFO, logger="plugin.logreceive"):
        assert plugin.hook_environment(request) is None

    assert "received request" in caplog.text
    assert "octocat/hello-world" in caplog.text


def test_hook_discovery_ignores_non_function_hook_attributes():
    """A hook_-prefixed attribute that is not a method is not a hook (T3-5)."""
    class Weird(BaseEnvironPlugin):
        friendly_name = "weird"
        hook_note = "this is a string, not a hook"

        def hook_environment(self, request): ...

    assert Weird().register_hooks() == ["environment"]


def test_two_registries_do_not_share_state():
    """An app's plugins live on its own registry; a second app does not inherit them
    (T3-1)."""
    first = Registry()
    first.load({"stdout": {}}, plugin_paths=[EXAMPLE_PLUGINS])
    second = Registry()
    second.load({}, plugin_paths=[EXAMPLE_PLUGINS])

    assert "stdout" in first.plugins
    assert second.plugins == {}
    assert "environment" in first.hooks
    assert second.hooks == {}
