from __future__ import annotations

from dataclasses import replace
from typing import Any

from uv_agent.plugins import CommandResult, PluginManifest, SetupPlugin, TranscriptAction

from .service import AuthCodeConfig, AuthCodeService

MANIFEST = PluginManifest(
    id="auth-code",
    version="0.1.0",
    display_name={"en": "Auth Code", "zh": "验证码鉴权"},
    description={
        "en": "Starts a token-protected web page with a short-lived challenge code and exposes auth_code.verify.",
        "zh": "启动受 token 保护的验证码页面，并提供 auth_code.verify action。",
    },
    capabilities=("action", "command", "http_server"),
    activation="always",
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
    config = _config_for_host(config, context.host)
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
        context.commands.register(
            "/auth-code",
            _status_command,
            description={"en": "Show auth-code server address", "zh": "显示 auth-code 服务地址"},
        )
    except Exception:
        _SERVICES.pop(id(context), None)
        service.stop()
        raise
    context.logger.info(
        "Auth code server started invocation=%s lifetime=%s bind=%s:%s url=%s",
        context.host.invocation,
        context.host.lifetime,
        service.config.host,
        service.port,
        service.url,
    )


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


def _status_command(payload: dict[str, Any], context=None) -> CommandResult:
    if context is None:
        return CommandResult((TranscriptAction("error", "auth-code status unavailable: missing context"),))
    service = _SERVICES.get(id(context))
    if service is None:
        return CommandResult((TranscriptAction("error", "auth-code server is not running"),))
    text = (
        "auth-code server\n"
        f"mode: {context.host.invocation}/{context.host.lifetime}\n"
        f"bind: {service.config.host}:{service.port}\n"
        f"url: {service.url}"
    )
    return CommandResult((TranscriptAction("event", text),))


def _config_for_host(config: AuthCodeConfig, host) -> AuthCodeConfig:
    if host.is_persistent:
        return config
    return replace(config, port=0)
