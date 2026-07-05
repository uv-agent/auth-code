from __future__ import annotations

from typing import Any

from uv_agent.plugins import PluginManifest, SetupPlugin

from .service import AuthCodeConfig, AuthCodeService

MANIFEST = PluginManifest(
    id="auth_code",
    version="0.1.0",
    display_name={"en": "Auth Code", "zh": "验证码鉴权"},
    description={
        "en": "Starts a token-protected web page with a short-lived challenge code and exposes auth_code.verify.",
        "zh": "启动受 token 保护的验证码页面，并提供 auth_code.verify action。",
    },
    capabilities=("action", "http_server"),
    config_schema={
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
            "host": {"type": "string", "default": "0.0.0.0"},
            "port": {"type": "integer", "minimum": 0, "maximum": 65535, "default": 8765},
            "ttl_s": {"type": "integer", "minimum": 1, "default": 120},
            "session_ttl_s": {"type": "integer", "minimum": 60, "default": 43200},
        },
        "required": ["token"],
    },
)

_SERVICES: dict[int, AuthCodeService] = {}


def plugin() -> SetupPlugin:
    return SetupPlugin(manifest=MANIFEST, setup=setup, stop=stop)


def setup(context) -> None:
    config = AuthCodeConfig.from_mapping(context.config)
    service = AuthCodeService(config, logger=context.logger)
    service.start()
    _SERVICES[id(context)] = service
    try:
        context.actions.register(
            "auth_code.verify",
            _verify_action,
            doc="Verify the current auth-code challenge. Payload: {'code': 'A7K2Q9'}.",
            schema={
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        )
    except Exception:
        _SERVICES.pop(id(context), None)
        service.stop()
        raise
    context.logger.info("Auth code server started url=%s", service.url)


def stop(context) -> None:
    service = _SERVICES.pop(id(context), None)
    if service is not None:
        service.stop()


def _verify_action(payload: dict[str, Any], context=None) -> dict[str, Any]:
    if context is None:
        return {"ok": False, "verified": False, "reason": "missing_context"}
    service = _SERVICES.get(id(context))
    if service is None:
        return {"ok": False, "verified": False, "reason": "service_unavailable"}
    return service.verify(str(payload.get("code") or ""))
