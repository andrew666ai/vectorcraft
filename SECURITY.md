# Security

VectorCraft is a local drawing app for personal use. It is not a hosted service. Files, pasted data, and automation requests are untrusted input: the engine returns errors instead of crashing.

## Reporting

Describe the version, platform, component, and a minimal reproduction. Leave out tokens, private paths, and document contents. Do not post a working exploit on a public issue; contact the repository owner and ask for a private channel first.

## Desktop use

Starting the app with no `--control` flag does not listen on a port. Menus, tools, and file dialogs behave as before.

## Loopback control

`vectorcraft --control <port>` (or `VECTORCRAFT_CONTROL_PORT`) binds `127.0.0.1` only. Every connection must authenticate before any method runs:

```json
{"id": 1, "method": "auth", "params": {"token": "<64 hex characters>"}}
```

The token is 256 random bits. On first use the app writes it to `control-token` next to the UI preferences (mode `0600` on Unix) and prints that path, not the token. You can instead pass `--control-token-file`, `--control-token`, `VECTORCRAFT_CONTROL_TOKEN_FILE`, or `VECTORCRAFT_CONTROL_TOKEN`. Do not commit the token. Prefer the file over a command-line flag so the secret stays out of shell history.

A missing or wrong token gets `{"ok": false, "error": "authentication required"}` and the connection closes. No control method is dispatched.

Budgets, per listener: 16 connections, 1 MiB request lines, 8 MiB replies, and 30 second socket timeouts. An over-budget reply is an error line; the command may already have finished.

This is a same-machine lock so other users and web pages cannot drive the app. An authenticated client can call the whole control surface. The channel is not encrypted. Do not tunnel or proxy it.

## MCP

Prefer stdio. `vectorcraft-cli mcp` and `vectorcraft-cli mcp --headless` do not open a TCP port, and the tools are unchanged. `vectorcraft-cli mcp --connect` bridges to loopback control and sends the same bearer token (flags and env vars above, or the existing `control-token` file). It refuses any host that is not loopback. Stdio request lines are limited to 1 MiB, and a JSON-RPC batch is limited to 256 messages.

## Links opened in a browser

Help links, object URLs, and opening a file the app just wrote go through one check. Only `https` URLs, and `file` URLs with no remote host, are handed to the system. Other schemes are refused.

## Not in this build

There is no per-tool capability list, session expiry, or security audit log. Those target a multi-user service; this app is one person on one machine. Untrusted documents can still use a lot of memory; that is separate from this control lock.
