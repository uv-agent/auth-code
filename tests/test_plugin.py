from __future__ import annotations

import json
import logging
import re
from http import HTTPStatus
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

import pytest
from uv_agent.plugins import CommandResult, SetupPlugin, TranscriptAction

from uv_agent_auth_code import MANIFEST, _SERVICES, _config_for_host, plugin, setup, stop
import uv_agent_auth_code.service as service_module
from uv_agent_auth_code.service import AuthCodeConfig, AuthCodeService, ChallengeStore, generate_code


class ActionRecorder:
    def __init__(self) -> None:
        self.registered: dict[str, dict[str, object]] = {}

    def register(self, action_id: str, handler, *, doc: str = "", schema: dict | None = None):
        self.registered[action_id] = {"handler": handler, "doc": doc, "schema": schema or {}}
        return self.registered[action_id]


class CommandRecorder:
    def __init__(self) -> None:
        self.registered: dict[str, dict[str, object]] = {}

    def register(self, name: str, handler, *, description="", aliases=()):
        self.registered[name] = {
            "handler": handler,
            "description": description,
            "aliases": tuple(aliases),
        }
        return self.registered[name]


def host_info(*, invocation: str = "daemon", lifetime: str = "persistent") -> SimpleNamespace:
    return SimpleNamespace(
        invocation=invocation,
        lifetime=lifetime,
        is_persistent=lifetime == "persistent",
    )


def make_context(*, plugin_host=None, **config):
    return SimpleNamespace(
        config=config,
        host=plugin_host or host_info(),
        logger=logging.getLogger("test.auth-code"),
        actions=ActionRecorder(),
        commands=CommandRecorder(),
    )


def test_plugin_entrypoint_manifest() -> None:
    loaded = plugin()

    assert isinstance(loaded, SetupPlugin)
    assert loaded.manifest is MANIFEST
    assert loaded.manifest.id == "auth-code"
    assert loaded.manifest.capabilities == ("action", "command", "http_server")
    assert loaded.manifest.activation == "always"
    assert loaded.stop is stop


def test_setup_requires_token() -> None:
    context = make_context(host="127.0.0.1", port=0)

    with pytest.raises(ValueError, match="token"):
        setup(context)

    assert id(context) not in _SERVICES
    assert context.actions.registered == {}
    assert context.commands.registered == {}


def test_session_host_uses_ephemeral_port_without_changing_bind_host() -> None:
    config = AuthCodeConfig(token="test-token", host="0.0.0.0", port=8765)

    result = _config_for_host(config, host_info(invocation="tui", lifetime="session"))

    assert result.host == "0.0.0.0"
    assert result.port == 0


def test_persistent_host_uses_configured_port() -> None:
    config = AuthCodeConfig(token="test-token", host="0.0.0.0", port=8765)

    result = _config_for_host(config, host_info(invocation="daemon", lifetime="persistent"))

    assert result is config


def test_setup_session_host_uses_os_assigned_port_and_reports_mode() -> None:
    context = make_context(
        plugin_host=host_info(invocation="tui", lifetime="session"),
        token="test-token",
        host="127.0.0.1",
        port=1,
    )
    setup(context)
    try:
        service = _SERVICES[id(context)]
        assert service.config.port == 0
        assert service.port > 0

        command = context.commands.registered["/auth-code"]["handler"]
        status = command({"arg": ""}, context=context)

        assert status.actions[0].kind == "event"
        assert "mode: tui/session" in status.actions[0].text
        assert f"bind: 127.0.0.1:{service.port}" in status.actions[0].text
    finally:
        stop(context)


def test_generate_code_is_six_alphanumeric_chars_with_letter_and_digit() -> None:
    for _ in range(100):
        code = generate_code()
        assert re.fullmatch(r"[A-Z0-9]{6}", code)
        assert any(char.isalpha() for char in code)
        assert any(char.isdigit() for char in code)


def test_challenge_verify_is_case_insensitive_and_consumes_code() -> None:
    store = ChallengeStore(ttl_s=120)
    code = store.snapshot()["code"]

    assert store.verify(code.lower())["verified"] is True
    second = store.verify(code)

    assert second["ok"] is False
    assert second["verified"] is False
    assert second["reason"] == "invalid"


def test_challenge_verify_rotates_expired_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "generate_code", lambda: "ABC123")
    store = ChallengeStore(ttl_s=1)
    code = store.snapshot()["code"]
    monkeypatch.setattr(service_module, "generate_code", lambda: "XYZ789")
    store._expires_at = 0.0

    result = store.verify(code)

    assert result["ok"] is False
    assert result["verified"] is False
    assert result["reason"] == "expired"
    assert store.snapshot()["code"] != code


def test_http_page_requires_token_then_serves_challenge_and_verify_action() -> None:
    context = make_context(token="test-token", host="127.0.0.1", port=0, ttl_s=120)
    opener = build_opener(HTTPCookieProcessor())
    setup(context)
    try:
        service = _SERVICES[id(context)]
        assert isinstance(service, AuthCodeService)
        assert service.url.startswith("http://127.0.0.1:")
        assert "auth_code.verify" in context.actions.registered
        assert "/auth-code" in context.commands.registered

        with pytest.raises(HTTPError) as unauthorized:
            opener.open(service.url + "/", timeout=3)
        assert unauthorized.value.code == HTTPStatus.UNAUTHORIZED

        with opener.open(service.url + "/?token=test-token", timeout=3) as response:
            page = response.read().decode("utf-8")
        assert response.status == HTTPStatus.OK
        assert "Current challenge" in page

        with opener.open(service.url + "/api/challenge", timeout=3) as response:
            challenge = json.loads(response.read().decode("utf-8"))
        assert response.status == HTTPStatus.OK
        assert re.fullmatch(r"[A-Z0-9]{6}", challenge["code"])

        handler = context.actions.registered["auth_code.verify"]["handler"]
        first = handler({"code": challenge["code"].lower()}, context=context)
        second = handler({"code": challenge["code"]}, context=context)

        assert first["ok"] is True
        assert first["verified"] is True
        assert second["ok"] is False
        assert second["verified"] is False
        assert second["reason"] == "invalid"

        command = context.commands.registered["/auth-code"]["handler"]
        status = command({"arg": ""}, context=context)

        assert isinstance(status, CommandResult)
        assert status.actions
        assert isinstance(status.actions[0], TranscriptAction)
        assert status.actions[0].kind == "event"
        assert "auth-code server" in status.actions[0].text
        assert f"bind: 127.0.0.1:{service.port}" in status.actions[0].text
        assert f"url: {service.url}" in status.actions[0].text
    finally:
        stop(context)


def test_bearer_token_can_fetch_api_without_cookie() -> None:
    service = AuthCodeService(AuthCodeConfig(token="bearer-token", host="127.0.0.1", port=0, ttl_s=120))
    service.start()
    opener = build_opener()
    try:
        request = Request(
            service.url + "/api/challenge",
            headers={"Authorization": "Bearer bearer-token"},
        )
        with opener.open(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert response.status == HTTPStatus.OK
        assert re.fullmatch(r"[A-Z0-9]{6}", payload["code"])
    finally:
        service.stop()
