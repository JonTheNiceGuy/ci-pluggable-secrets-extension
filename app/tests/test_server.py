import json
import time

import anyio
import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ci_pluggable_secrets_extension import plugins
from ci_pluggable_secrets_extension.models import EnvironRequest, Variable
from ci_pluggable_secrets_extension.server import MAX_BODY_BYTES, combine, create_app, normalise
from ci_pluggable_secrets_extension.signature import sign

from .conftest import BUILD_REQUEST, SECRET


@pytest.fixture
def client(config):
    return TestClient(create_app(config))


def post(client, body, secret=SECRET):
    headers = sign(secret, "POST", "/", {"Content-Type": "application/json"}, body)
    return client.post("/", content=body, headers=headers)


def test_signed_request_returns_the_stdout_plugin_variable(client, body, capfd):
    response = post(client, body)

    assert response.status_code == 200
    assert response.json() == [
        {"name": "stdout_plugin", "data": "enabled", "mask": False}
    ]

    logged = json.loads(capfd.readouterr().out.strip().splitlines()[-1])
    assert logged["build"]["number"] == BUILD_REQUEST["build"]["number"]
    assert logged["repo"]["slug"] == BUILD_REQUEST["repo"]["slug"]


def test_badly_signed_request_is_rejected(client, body):
    assert post(client, body, secret="wrong").status_code == 400


def test_unsigned_request_is_rejected(client, body):
    assert client.post("/", content=body).status_code == 400


def test_unknown_drone_fields_do_not_break_the_request(client):
    payload = json.loads(json.dumps(BUILD_REQUEST))
    payload["build"]["some_future_field"] = "surprise"
    assert post(client, json.dumps(payload).encode()).status_code == 200


def test_a_failing_plugin_fails_the_request(client, body, config):
    class Exploding:
        friendly_name = "boom"

        def describe(self):
            return "boom: 0.0.1"

        def run_hook(self, hook, request=None):
            raise RuntimeError("no vault for you")

    plugins.hooks["environment"].append(Exploding())
    assert post(client, body).status_code == 500


def test_a_failing_plugin_can_be_skipped_instead(client, body, config):
    class Exploding:
        friendly_name = "boom"

        def describe(self):
            return "boom: 0.0.1"

        def run_hook(self, hook, request=None):
            raise RuntimeError("no vault for you")

    config.on_plugin_error = "skip"
    plugins.hooks["environment"].append(Exploding())

    response = post(client, body)
    assert response.status_code == 200
    assert [v["name"] for v in response.json()] == ["stdout_plugin"]


def test_a_fail_closed_plugin_is_not_skipped_even_under_skip(client, body, config):
    """A credential plugin declares itself fail-closed, so an error from it fails the
    build even when on_plugin_error is skip — a green build with a credential missing is
    worse than a failed one."""
    class Critical:
        friendly_name = "critical"
        fail_closed = True

        def describe(self):
            return "critical: 0.0.1"

        def run_hook(self, hook, request=None):
            raise RuntimeError("could not fetch the credential")

    config.on_plugin_error = "skip"
    plugins.hooks["environment"].append(Critical())
    assert post(client, body).status_code == 500


def test_the_fired_context_is_logged(client, body, caplog):
    """One INFO line naming which plugins fired and in what build context."""
    import logging

    with caplog.at_level(logging.INFO, logger="ci_pluggable_secrets_extension"):
        assert post(client, body).status_code == 200

    assert "stdout fired in the context of octocat/hello-world/" in caplog.text
    assert "due to push" in caplog.text


def test_healthz_lists_loaded_plugins(client):
    assert client.get("/healthz").json() == {
        "status": "ok",
        "plugins": ["stdout: 0.1.0"],
    }


@pytest.mark.parametrize(
    "result,expected",
    [
        (None, []),
        ({"a": "1"}, [Variable(name="a", data="1")]),
        ({"a": 1}, [Variable(name="a", data="1")]),
        ({"a": {"data": "1", "mask": True}}, [Variable(name="a", data="1", mask=True)]),
        # Expanded form coerces data like the flat form does (T1-4b).
        ({"a": {"data": 1, "mask": True}}, [Variable(name="a", data="1", mask=True)]),
        ([{"name": "a", "data": "1"}], [Variable(name="a", data="1")]),
        (Variable(name="a", data="1"), [Variable(name="a", data="1")]),
    ],
)
def test_normalise_accepts_every_plugin_return_shape(result, expected):
    assert normalise("test", result) == expected


def test_normalise_rejects_nonsense():
    with pytest.raises(TypeError, match="expected a dict"):
        normalise("test", "just a string")


def test_later_plugins_win_on_a_conflict(caplog):
    merged = combine({
        "first": {"shared": "a", "own": "1"},
        "second": {"shared": "b"},
    })
    assert merged == [
        Variable(name="shared", data="b"),
        Variable(name="own", data="1"),
    ]
    assert "overrides the variable shared" in caplog.text


def test_request_model_parses_a_drone_payload(body):
    request = EnvironRequest.model_validate_json(body)
    assert request.build.event == "push"
    assert request.build.params == {"KEY": "value"}
    assert request.repo.namespace == "octocat"


def test_a_typo_for_mask_is_rejected_rather_than_silently_unmasking():
    """{"masked": True} (a typo for "mask") must not yield mask=False and leak the
    secret to the build log; the unknown key is refused."""
    with pytest.raises(ValidationError):
        normalise("test", {"secret": {"data": "s3cret", "masked": True}})


def test_an_oversized_body_is_rejected_before_it_is_buffered(client):
    """A signature covers the body, so the body is read before it can be verified. An
    unauthenticated client must not be able to make that read unbounded."""
    oversized = b"x" * (MAX_BODY_BYTES + 1)
    # Deliberately unsigned: the size check comes first, so this never reaches verify().
    assert client.post("/", content=oversized).status_code == 413


def test_a_slow_plugin_does_not_serialise_requests_on_the_event_loop(client, body):
    """Plugins are synchronous and may block (RSA signing, network I/O). If they ran on
    the event loop, N concurrent builds would take N x one build; off the loop they
    overlap."""
    class Slow:
        friendly_name = "slow"

        def describe(self):
            return "slow: 0.0.1"

        def run_hook(self, hook, request=None):
            time.sleep(0.3)
            return {}

    plugins.hooks["environment"].append(Slow())
    headers = sign(SECRET, "POST", "/", {"Content-Type": "application/json"}, body)
    transport = httpx.ASGITransport(app=client.app)

    async def scenario():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            async def once():
                response = await ac.post("/", content=body, headers=headers)
                assert response.status_code == 200

            start = time.perf_counter()
            async with anyio.create_task_group() as tg:
                for _ in range(4):
                    tg.start_soon(once)
            return time.perf_counter() - start

    elapsed = anyio.run(scenario)
    # Four 0.3s plugins serialised on the loop would take >=1.2s; off it they overlap.
    assert elapsed < 1.0
