from __future__ import annotations

import json
import logging
import re
from http import HTTPStatus
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

import pytest
from uv_agent.plugins import SetupPlugin

from uv_agent_auth_code import MANIFEST, _SERVICES, plugin, setup, stop
import uv_agent_auth_code.service as service_module
from uv_agent_auth_code.service import AuthCodeConfig, AuthCodeService, ChallengeStore, generate_code


class ActionRecorder:
    def __init__(self) -> None:
        self.registered: dict[str, dict[str, object]] = {}

    def register(self, action_id: str, handler, *, doc: str = "", schema: dict | None = None):
        self.registered[action_id] = {"handler": handler, "doc": doc, "schema": schema or {}}
        return self.registered[action_id]


def make_context(**config):
    return SimpleNamespace(
        config=config,
        logger=logging.getLogger("test.auth-code"),
        actions=ActionRecorder(),
    )


def test_plugin_entrypoint_manifest() -> None:
    loaded = plugin()

    assert isinstance(loaded, SetupPlugin)
    assert loaded.manifest is MANIFEST
    assert loaded.manifest.id == "auth-code"
    assert loaded.manifest.capabilities == ("action", "http_server")
    assert loaded.stop is stop


def test_setup_requires_token() -> None:
    context = make_context(host="127.0.0.1", port=0)

    with pytest.raises(ValueError, match="token"):
        setup(context)

    assert id(context) not in _SERVICES
    assert context.actions.registered == {}


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
