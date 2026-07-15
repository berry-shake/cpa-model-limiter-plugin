# CLIProxyAPI Model Limiter Plugin

A CLIProxyAPI frontend auth plugin that restricts which models specific
inbound API keys may use. It registers as an exclusive `FrontendAuthProvider`
and inspects the API key (headers/query) together with the requested model
(JSON body `model` field, or the Gemini-style `/models/<model>:<action>` URL
path) in a single authentication pass.

The host `api-keys` list stays the single, complete source of key validity —
restricted keys remain listed there like every other key. The plugin reads
that list directly from the host configuration file and applies three checks:

1. The key must be present in the host `api-keys` list, otherwise reject.
2. A key without a plugin rule is unrestricted (any model).
3. A key with a rule may only request models matching its allow patterns.

Rules only subtract capability from keys that `api-keys` already grants; a
rule for a key missing from `api-keys` never admits it.

The plugin also ships a **Model Limiter** menu page for the official
management panel: it lists every host API key, shows which are restricted,
and lets you edit model patterns per key. The page auto-loads without a
management key and saves rule changes by rewriting `config.yaml` directly.
The host detects the file change and hot-reloads the plugin configuration
immediately. See [Panel endpoints](#panel-endpoints) below — the read/write
endpoints are **unauthenticated at the host layer**, but the panel denies
iframe embedding and rejects cross-origin browser requests by default
(configurable via `allowed_origins`).

## Requirements

- CLIProxyAPI v7.2.71 or newer with dynamic plugin support
- Linux amd64/arm64, macOS amd64/arm64, or Windows amd64
- cgo-enabled CLIProxyAPI build on Unix platforms

## Install

### Automatic (plugin store)

Release assets follow the CLIProxyAPI plugin store layout
(`model-limiter_<version>_<goos>_<goarch>.zip` plus `checksums.txt`), so
the host can install the plugin from GitHub releases when a `store` block is
configured:

```yaml
plugins:
  enabled: true
  configs:
    model-limiter:
      enabled: true
      store:
        id: model-limiter
        name: Model Limiter
        description: Restrict which models each inbound API key may use.
        author: berry-shake
        version: 0.1.3
        release-tag: v0.1.3
        repository: https://github.com/berry-shake/cpa-model-limiter-plugin
        install:
          type: github-release
```

### Manual

1. Download the zip matching the host platform and extract
   `model-limiter.<so|dylib|dll>`.
2. Put it in the preferred platform directory:

   ```text
   plugins/linux/amd64/model-limiter.so
   plugins/linux/arm64/model-limiter.so
   plugins/darwin/amd64/model-limiter.dylib
   plugins/darwin/arm64/model-limiter.dylib
   plugins/windows/amd64/model-limiter.dll
   ```

3. Enable and configure the plugin in the CLIProxyAPI host configuration.

## Configuration

| Key | Type | Description |
| --- | --- | --- |
| `keys` | list | Restriction rules. Each entry has `api-key` (string, required, unique) and `models` (string list, optional). `*` wildcards are allowed in model patterns. An empty or missing `models` list allows every model for that key. The key must also exist in the host `api-keys` list; a rule alone never grants access. Keys without a rule are unrestricted. |
| `allowed_origins` | string | Comma-separated list of trusted origins that may iframe the panel and call `/state`/`/apply` cross-origin. Blank (default) applies the strictest posture: iframe embedding is denied via `frame-ancestors 'none'` and cross-origin browser requests are rejected. |

Example — `sk-team-a` and `sk-team-b` are model-restricted; all keys,
restricted or not, stay in the host `api-keys` list:

```yaml
api-keys:
  - sk-admin           # unrestricted
  - sk-ci              # unrestricted
  - sk-team-a          # restricted below
  - sk-team-b          # restricted below

plugins:
  enabled: true
  configs:
    model-limiter:
      enabled: true
      keys:
        - api-key: sk-team-a
          models:
            - gpt-5.2
            - claude-*
        - api-key: sk-team-b
          models:
            - gemini-2.5-flash
            - gemini-2.5-pro
```

Prefer editing rules on the **Model Limiter** menu page of the management
panel; it validates input and writes `config.yaml` directly.

### Panel endpoints

The panel page is served at `/v0/resource/plugins/model-limiter/panel` and
talks to two same-origin JSON endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v0/resource/plugins/model-limiter/state` | Returns `{plugin_version, api_keys, rules}`. |
| GET | `/v0/resource/plugins/model-limiter/apply?rules=<base64url json>` | Parses the payload (`[{"api_key":"...","models":[...]}]`), rewrites `config.yaml`, and returns the updated state. Pass `rules=W10` (base64 of `[]`) to clear every rule. |

Both endpoints are **unauthenticated at the host layer** — the host restricts
`/v0/resource/*` routes to `GET`, so writes are encoded in the query string.
The plugin defends browsers on top of that:

- The panel page ships with `Content-Security-Policy: frame-ancestors 'none'`
  by default, so no other page can iframe it.
- `/state` and `/apply` reject cross-origin browser requests unless the
  request's `Origin` (falling back to `Referer`) matches `allowed_origins`.
  Detection uses `Sec-Fetch-Site` first, then `Origin`; requests without any
  browser context headers (CLI tools) still pass so the endpoints remain
  scriptable from the host.

Add trusted origins with `allowed_origins`:

```yaml
plugins:
  configs:
    model-limiter:
      allowed_origins: "https://ops.example.com,https://intranet.example.com"
```

Anyone reaching the HTTP port from a non-browser client (`curl`, scripts) can
still read the api-keys list and rewrite the rule set. Bind the server to a
trusted network, put it behind a proxy that enforces auth on
`/v0/resource/*`, or disable the plugin if that trade-off is unacceptable.

Behavior notes:

- Model patterns are matched case-insensitively; `*` matches any sequence
  (`claude-*`, `*-flash`, `gemini-*-pro*`).
- Thinking suffixes are stripped before matching: a request for
  `gpt-5.2(high)` or `claude-sonnet-4-5(16384)` matches the plain model name.
- The model is read from the JSON body `model` field (OpenAI, Claude, Codex
  formats) or from the URL path for Gemini-style
  `/v1beta/models/<model>:generateContent` routes. The URL path wins when
  both are present.
- Requests without a resolvable model (for example `GET /v1/models`) only go
  through the key check.
- Keys are compared exactly after trimming surrounding whitespace.
- The host `api-keys` list is read from the same config file the server
  loaded (`--config` flag or `config.yaml` in the working directory) and is
  cached until the file changes; a transient read or parse failure falls back
  to the last good snapshot.
- A failed plugin config reload resets to empty rules instead of keeping
  stale ones: keys in `api-keys` become temporarily unrestricted rather than
  locked out. The parse error is logged through the host logger.
- Rejections surface to clients as HTTP 401 (the host access manager owns the
  error shape), not as a 403 "model not allowed" message. Rejected requests
  are logged with a masked key and the offending model.

## Fail-closed notes

The plugin registers as an *exclusive* frontend auth provider, replacing the
builtin `config-api-key` check (the decision semantics are identical for
unrestricted keys):

- If the plugin panics, the host fuses it and every request is denied with
  401 until the plugin or configuration is reloaded. Auth fails closed, never
  open.
- If the host config file cannot be read and no snapshot exists yet, requests
  are denied and the error is logged.
- If the host `api-keys` list is empty, the plugin denies all requests. This
  differs from a pluginless host, which treats empty `api-keys` as
  "no authentication required".

## Build locally

```bash
go test ./...
go build -buildmode=c-shared \
  -ldflags '-X main.pluginVersion=0.1.3-dev' \
  -o model-limiter.dylib .
```

Use `.so` on Linux and `.dll` on Windows. The c-shared build also produces a
C header; the host does not need it.

## Security notes

- The panel page needs no management key: `/state` and `/apply` are
  unauthenticated at the host layer. Browsers are gated by the panel's
  `frame-ancestors 'none'` CSP and by the cross-origin check on
  `/state`/`/apply`; both open up when `allowed_origins` is set. Non-browser
  clients (curl, scripts) bypass the browser checks — restrict network
  exposure accordingly (loopback bind, VPN, or an auth-enforcing reverse
  proxy on `/v0/resource/*`).
- Writes go straight to `config.yaml` using an atomic temp-file rename so
  concurrent readers never see a partial file. Comments and unrelated
  settings are preserved by rewriting only the `plugins.configs.model-limiter.keys`
  subtree.
- API keys live in the host `config.yaml` under `api-keys` and
  `plugins.configs`; protect the file accordingly.
- Logs mask keys (`sk-a****klmn`) and never include full credentials.
