# uv-agent auth code plugin

This plugin starts a small token-protected HTTP page that shows a single
six-character challenge code. Other uv-agent plugins can call the
`auth_code.verify` action with a user-provided code.

The code is uppercase alphanumeric, case-insensitive when verified, short lived,
and consumed after one successful verification.

## Configuration

```json
{
  "plugins": {
    "auth-code": {
      "enabled": true,
      "config": {
        "token": "replace-with-a-long-random-token",
        "host": "0.0.0.0",
        "port": 8765,
        "ttl_s": 120
      }
    }
  }
}
```

`token` is required. The page can be opened as:

```text
http://127.0.0.1:8765/?token=replace-with-a-long-random-token
```

After token login, the plugin stores an in-memory HttpOnly session cookie.

In a persistent daemon host, `port` is used as configured. In a TUI/session host,
the plugin keeps the configured `host` binding but asks the OS for an ephemeral
port. Run `/auth-code` in the TUI to show the actual bind address and local URL.

## Action

```python
result = await context.actions.call("auth_code.verify", {"code": "A7K2Q9"})
```

The plugin id is `auth-code`. The action id remains `auth_code.verify` because
uv-agent action ids use dotted Python-style names.

Successful verification returns:

```json
{"ok": true, "verified": true}
```

Failed verification returns `ok: false`, `verified: false`, and a `reason`.
