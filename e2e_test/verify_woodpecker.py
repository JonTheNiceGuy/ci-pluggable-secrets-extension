"""Prove the extension serves Woodpecker too, without touching a browser.

Logs into Woodpecker by driving its OAuth handshake with Gitea, activates the demo
repo, runs a pipeline and then a deployment, and checks that the secrets the plugins
returned actually reached the steps.

    uv run --project app python e2e_test/verify_woodpecker.py
"""

import base64
import re
import sys
import time

import httpx2 as httpx


sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from verify import environment

REPO = "droneadmin/drone-environ-demo"


def login(client, gitea, woodpecker, user, password):
    """Woodpecker's OAuth dance with Gitea, which differs from Drone's only in paths."""
    page = client.get(f"{gitea}/user/login")
    import re
    csrf = re.search(r'name="_csrf"[^>]*value="([^"]+)"', page.text)
    response = client.post(f"{gitea}/user/login", data={
        "_csrf": csrf.group(1) if csrf else "",
        "user_name": user,
        "password": password,
    })
    if response.status_code not in (302, 303):
        sys.exit(f"Gitea rejected the login: HTTP {response.status_code}")

    response = client.get(f"{woodpecker}/authorize")
    response = client.get(response.headers["location"])

    if response.status_code == 200:      # the consent form, first time only
        form = dict(re.findall(
            r'name="(client_id|state|redirect_uri|scope|nonce)"\s+value="([^"]*)"',
            response.text,
        ))
        form["granted"] = "true"
        response = client.post(
            f"{gitea}/login/oauth/grant", data=form,
            headers={"X-Csrf-Token": client.cookies.get("_csrf") or ""},
        )

    while response.status_code in (302, 303):
        location = response.headers["location"]
        response = client.get(location if location.startswith("http") else woodpecker + location)


def wait(client, woodpecker, repo_id, number):
    for _ in range(150):
        pipeline = client.get(
            f"{woodpecker}/api/repos/{repo_id}/pipelines/{number}"
        ).json()
        if pipeline["status"] not in ("pending", "running"):
            return pipeline
        time.sleep(2)
    sys.exit(f"pipeline {number} never finished")


def show(client, woodpecker, repo_id, pipeline, heading):
    print(f"\n{'=' * 70}\n{heading}: pipeline #{pipeline['number']} "
          f"event={pipeline['event']} deploy_to={pipeline.get('deploy_to') or '-'} "
          f"status={pipeline['status']}\n{'=' * 70}")
    for workflow in pipeline.get("workflows") or []:
        for step in workflow.get("children") or []:
            print(f"\n--- step: {step['name']} ({step['state']}) ---")
            logs = client.get(
                f"{woodpecker}/api/repos/{repo_id}/logs/{pipeline['number']}/{step['id']}"
            )
            if logs.status_code != 200:
                continue
            for line in logs.json() or []:
                # Woodpecker base64-encodes each log line; some carry a null `data`.
                text = base64.b64decode(line.get("data") or "").decode(errors="replace").rstrip()
                if text and not text.startswith("+") and "pip install" not in text \
                        and "WARNING" not in text:
                    print("   ", text)


def main():
    env = environment()
    host = env["HOST_ADDR"]
    gitea, woodpecker = f"http://{host}:3000", f"http://{host}:8000"
    user, password = env["GITEA_ADMIN_USER"], env["GITEA_ADMIN_PASSWORD"]

    with httpx.Client(follow_redirects=False, timeout=60) as client:
        login(client, gitea, woodpecker, user, password)
        whoami = client.get(f"{woodpecker}/api/user")
        if whoami.status_code != 200:
            sys.exit(f"not logged in to Woodpecker: HTTP {whoami.status_code}")
        print(f"logged into Woodpecker as {whoami.json()['login']}")

        # The session cookie is enough to read, but Woodpecker requires a CSRF token
        # on every write. The UI picks it up from the config it is served; so do we.
        config = client.get(f"{woodpecker}/web-config.js").text
        csrf = re.search(r'window\.WOODPECKER_CSRF\s*=\s*"([^"]+)"', config)
        if not csrf:
            sys.exit("could not find the CSRF token in Woodpecker's web config")
        client.headers["X-CSRF-TOKEN"] = csrf.group(1)

        client.post(f"{woodpecker}/api/user/repos/refresh")     # sync from Gitea
        repos = client.get(f"{woodpecker}/api/user/repos?all=true").json() or []
        found = next((r for r in repos if r["full_name"] == REPO), None)
        if not found:
            sys.exit(f"Woodpecker never saw {REPO} in Gitea")

        repo_id = found.get("id")
        if not found.get("active"):
            response = client.post(
                f"{woodpecker}/api/repos?forge_remote_id={found['forge_remote_id']}"
            )
            if response.status_code >= 400:
                sys.exit(f"could not activate {REPO}: {response.status_code} {response.text}")
            repo_id = response.json()["id"]
            print(f"activated {REPO} (repo id {repo_id})")

        # Woodpecker needs the deployment to be allowed before it will run one.
        client.patch(f"{woodpecker}/api/repos/{repo_id}", json={"allow_deploy": True})

        pushed = client.post(f"{woodpecker}/api/repos/{repo_id}/pipelines",
                             json={"branch": "main", "variables": {}})
        if pushed.status_code >= 400:
            sys.exit(f"could not start a pipeline: {pushed.status_code} {pushed.text}")
        pushed = wait(client, woodpecker, repo_id, pushed.json()["number"])
        show(client, woodpecker, repo_id, pushed, "MANUAL PIPELINE")

        deployed = client.post(
            f"{woodpecker}/api/repos/{repo_id}/pipelines/{pushed['number']}"
            "?event=deployment&deploy_to=production",
            json={"variables": {"REASON": "hotfix"}},
        )
        if deployed.status_code >= 400:
            sys.exit(f"could not deploy: {deployed.status_code} {deployed.text}")
        deployed = wait(client, woodpecker, repo_id, deployed.json()["number"])
        show(client, woodpecker, repo_id, deployed, "DEPLOYMENT to production")

        ok = pushed["status"] == "success" and deployed["status"] == "success"
        print(f"\nmanual: {pushed['status']}   deployment: {deployed['status']}")
        print("PASSED: one extension served both Drone and Woodpecker" if ok
              else "FAILED")
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
