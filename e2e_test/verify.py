"""Prove the extension is really in the loop, without touching a browser.

Logs into Drone by driving its OAuth handshake with Gitea the way a browser would,
activates the demo repo, triggers a build, and asserts that the variable the stdout
plugin returns actually lands in the build environment.

    uv run --project app python e2e_test/verify.py
"""

import os
import re
import sys
import time
from pathlib import Path

import httpx2 as httpx

REPO = "drone-environ-demo"
EXPECTED = "stdout_plugin=enabled"


def environment():
    env = Path(__file__).parent / ".env"
    if not env.is_file():
        sys.exit("e2e_test/.env is missing — run e2e_test/up.sh first")
    for line in env.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)
    return os.environ


def csrf(html):
    match = re.search(r'name="_csrf"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else ""


def login(client, gitea, drone, user, password):
    page = client.get(f"{gitea}/user/login")
    response = client.post(f"{gitea}/user/login", data={
        "_csrf": csrf(page.text), "user_name": user, "password": password,
    })
    if response.status_code not in (302, 303):
        sys.exit(f"Gitea rejected the login: HTTP {response.status_code}")

    response = client.get(f"{drone}/login")
    response = client.get(response.headers["location"])

    # Gitea shows a consent form the first time. Since 1.27 its CSRF token is carried
    # in a cookie and an X-Csrf-Token header rather than a hidden form field.
    if response.status_code == 200:
        form = dict(re.findall(
            r'name="(client_id|state|redirect_uri|scope|nonce)"\s+value="([^"]*)"',
            response.text,
        ))
        form["granted"] = "true"
        response = client.post(
            f"{gitea}/login/oauth/grant",
            data=form,
            headers={"X-Csrf-Token": client.cookies.get("_csrf") or ""},
        )

    while response.status_code in (302, 303):
        location = response.headers["location"]
        response = client.get(location if location.startswith("http") else drone + location)


def main():
    env = environment()
    host = env.get("HOST_ADDR", "172.17.0.1")
    gitea, drone = f"http://{host}:3000", f"http://{host}:8080"
    user, password = env["GITEA_ADMIN_USER"], env["GITEA_ADMIN_PASSWORD"]

    with httpx.Client(follow_redirects=False, timeout=30) as client:
        login(client, gitea, drone, user, password)
        whoami = client.get(f"{drone}/api/user").json()
        print(f"logged into Drone as {whoami['login']}")

        client.post(f"{drone}/api/user/repos")  # sync
        for _ in range(20):
            repos = client.get(f"{drone}/api/user/repos").json() or []
            if any(r["name"] == REPO for r in repos):
                break
            time.sleep(1)
        else:
            sys.exit(f"Drone never synced {REPO} from Gitea")

        client.post(f"{drone}/api/repos/{user}/{REPO}")  # activate; 409 if already on
        response = client.post(f"{drone}/api/repos/{user}/{REPO}/builds?branch=main")
        if response.status_code >= 400:
            sys.exit(f"could not trigger a build: HTTP {response.status_code} {response.text}")
        number = response.json()["number"]
        print(f"triggered build #{number}, waiting for it")

        build = {}
        for _ in range(120):
            build = client.get(f"{drone}/api/repos/{user}/{REPO}/builds/{number}").json()
            if build["status"] not in ("pending", "running"):
                break
            time.sleep(2)

        logs = client.get(f"{drone}/api/repos/{user}/{REPO}/builds/{number}/logs/1/2")
        output = "\n".join(line["out"] for line in logs.json()) if logs.status_code == 200 else ""

    print(f"build #{number}: {build.get('status')}")
    if build.get("status") != "success" or EXPECTED not in output:
        print(output)
        sys.exit(f"FAILED: the build did not report {EXPECTED!r}")

    print(f"PASSED: the build environment contains {EXPECTED} — the runner called the "
          "extension and used its answer")


if __name__ == "__main__":
    main()
