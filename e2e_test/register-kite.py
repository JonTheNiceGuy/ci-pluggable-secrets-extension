#!/usr/bin/env python3
"""Register the pagekite kite the testenv exposes the extension issuer on.

pagekite only registers a brand-new .pagekite.me name interactively (on first use), which
the non-interactive tunnel container cannot do — so an unregistered kite name is rejected
with a 401 and never routes. This registers it up front through pagekite.net's XML-RPC API
using the account credentials in e2e_test/.env.pagekite, and sets the kite's shared secret
to `kitesecret` so the tunnel can authenticate.

Idempotent: if the kite already exists on the account it is left as-is. Reads everything
from the environment (up.sh sources .env.pagekite):

    pagekite_email     the pagekite.net account email
    pagekite_password  the account password (used only to obtain a short-lived credential)
    KITE               the kite name to register, e.g. environ-you.pagekite.me
    kitesecret         the kite's shared secret, matching the tunnel
"""
import os
import sys
import xmlrpc.client

API = "https://pagekite.net/xmlrpc/"


def need(*names):
    """The first of these env vars that is set, or a clear exit naming the canonical one."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    sys.exit(
        f"register-kite: set {names[0]} in e2e_test/.env.pagekite "
        "(see .env.pagekite.example)."
    )


def main():
    # Accept the obvious name variants so an existing .env.pagekite just works.
    email = need("pagekite_email", "email")
    password = need("pagekite_password", "password")
    kite = need("KITE")
    secret = need("kitesecret")

    api = xmlrpc.client.ServerProxy(API, allow_none=True)

    def call(method, *args, what):
        """An XML-RPC call that always returns ('ok', payload) or exits with the reason.

        The service answers ('ok', ...) on success and ('<error>', ...) otherwise; guard
        the shape so an unexpected response is a clear failure rather than a traceback.
        """
        try:
            resp = getattr(api, method)(*args)
        except (xmlrpc.client.Error, OSError) as exc:
            sys.exit(f"register-kite: {what} failed: {exc}")
        if not (isinstance(resp, (list, tuple)) and resp and resp[0] == "ok"):
            status = resp[0] if isinstance(resp, (list, tuple)) and resp else resp
            sys.exit(f"register-kite: {what} refused ({status!r}).")
        return resp

    # Passing an empty credential asks the service to mint a fresh short-lived one, so the
    # password is only sent this once per run. -> ('ok', (acct_id, credential))
    _, session = call("login", email, password, "", what="pagekite.net login")
    acct, cred = session

    # Already registered on this account? Then there is nothing to do — its secret was set
    # to this same kitesecret when it was first registered. -> ('ok', {kite: bytes, ...})
    _, kites = call("get_kite_stats", acct, cred, what="listing kites")
    if isinstance(kites, dict) and kite in kites:
        print(f"register-kite: {kite} already registered — nothing to do.")
        return

    call("add_kite_with_secret", acct, cred, kite, secret, True,
         what=f"registering {kite}")
    print(f"register-kite: registered {kite}.")


if __name__ == "__main__":
    main()
