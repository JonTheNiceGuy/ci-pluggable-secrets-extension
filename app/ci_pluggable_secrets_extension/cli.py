import argparse
import logging
import sys

import uvicorn

from ci_pluggable_secrets_extension import config as configuration
from ci_pluggable_secrets_extension import plugins
from ci_pluggable_secrets_extension.server import create_app

DEFAULT_CONFIG = "config.yaml"


def main():
    parser = argparse.ArgumentParser(
        description="A pluggable Drone CI environment extension."
    )
    parser.add_argument(
        "-c", "--config", default=DEFAULT_CONFIG,
        help=f"Path to the config file (default: {DEFAULT_CONFIG})",
    )
    subparsers = parser.add_subparsers(dest="action", title="Actions")
    subparsers.add_parser("serve", help="Run the extension HTTP server")
    subparsers.add_parser("plugins", help="List the plugins and hooks that would load")

    args = parser.parse_args()
    if not args.action:
        parser.parse_args(["-h"])

    try:
        config = configuration.load(args.config)
    except configuration.ConfigError as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")

    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    )

    try:
        plugins.load_plugins_and_hooks(config)
    except Exception as exc:
        logging.error("%s", exc)
        sys.exit(1)

    if args.action == "plugins":
        return describe_plugins(config)
    return serve(config)


def describe_plugins(config):
    installed = plugins.discover(config.plugin_paths)
    for name, path in sorted(installed.items()):
        plugin = plugins.plugins.get(name)
        if plugin is None:
            print(f"  [ ] {name} (installed in {path}, not enabled in the config)")
            continue
        hooks = ", ".join(plugin.register_hooks()) or "no hooks"
        print(f"  [x] {plugin.describe()} — hooks: {hooks}")
        for option, value in plugin.settings.items():
            print(f"        {option} = {value!r}")


def serve(config):
    app = create_app(config)
    logging.info(
        "Serving %d plugin(s) on http://%s:%s — point DRONE_ENV_PLUGIN_ENDPOINT here",
        len(plugins.plugins), config.host, config.port,
    )
    uvicorn.run(
        app, host=config.host, port=config.port,
        log_level=config.log_level.lower(),
        limit_concurrency=config.limit_concurrency,
    )


if __name__ == "__main__":
    main()
