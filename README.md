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
and lets you edit model patterns per key. Rule changes are saved by rewriting
`config.yaml` directly; the host detects the file change and hot-reloads the
plugin configuration immediately. The data endpoints are `/v0/management`
routes, so the host checks the management key before the plugin sees the
request. Inside the management panel the page reuses the key the panel
remembered; otherwise it asks for one. See [Panel endpoints](#panel-endpoints)
below.

## Requirements

- CLIProxyAPI v7.2.71 or newer with dynamic plugin support; v8.0.40 or newer
  recommended (explicit 403 for blocked models since v8.0.39, decoded
  compressed bodies since v8.0.40)
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
        version: 0.3.0
        release-tag: v0.3.0
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
| `allowed_origins` | string | Comma-separated list of extra origins that may iframe the panel page. Blank (default) allows only same-origin embedding (`frame-ancestors 'self'`), which is what the CPA management panel needs. The data endpoints always require the management key regardless of this setting. |

Example — `sk-team-a` and `sk-team-b` are model-restricted; all keys,
restricted or not, stay in the host `api-keys` list:

```yaml
access:
  api-keys:
    - sk-admin         # unrestricted
    - sk-ci            # unrestricted
    - sk-team-a        # restricted below
    - sk-team-b        # restricted below

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

The panel page is served at `/v0/resource/plugins/model-limiter/panel`
(unauthenticated, page shell only) and talks to two management routes:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v0/management/plugins/model-limiter/state` | Returns `{plugin_version, api_keys, rules}`. |
| POST | `/v0/management/plugins/model-limiter/apply` | Body `{"rules":[{"api_key":"...","models":[...]}]}`. Rewrites `config.yaml` and returns the updated state. Send `{"rules":[]}` to clear every rule; a body without `rules` is rejected. |

The host's management middleware checks `Authorization: Bearer <management key>`
before forwarding either route (and applies its usual remote-management and IP
ban rules), so a missing or wrong key gets 401/403 from the host itself:

```bash
curl -H "Authorization: Bearer $MANAGEMENT_KEY" \
  http://127.0.0.1:8317/v0/management/plugins/model-limiter/state

curl -X POST -H "Authorization: Bearer $MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"api_key":"sk-team-a","models":["gpt-5*"]}]}' \
  http://127.0.0.1:8317/v0/management/plugins/model-limiter/apply
```

How the page gets the key:

- Opened inside the CPA management panel (same-origin iframe), it reads the
  key the panel saved in `localStorage` when "remember password" is checked.
  It understands both the official panel and CPAMP storage formats, only uses
  a key saved for this origin, and never writes it back.
- Otherwise, or when the host rejects the saved key, it shows a sign-in form.
  The key entered there stays in page memory only; a reload asks again.

Add extra origins that may iframe the page with `allowed_origins`:

```yaml
plugins:
  configs:
    model-limiter:
      allowed_origins: "https://ops.example.com,https://intranet.example.com"
```

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
- Compressed (`Content-Encoding: zstd`) bodies are checked through the decoded
  copy CLIProxyAPI v8.0.40+ passes to auth plugins. When a restricted key sends
  an encoded body the plugin cannot read (older hosts, or coding lists the host
  leaves to the handler) and the model is not in the URL path, the request is
  rejected with 415 instead of skipping the model check; the still-encoded
  bytes are never searched for a model. Unrestricted keys are not affected.
- Keys are compared exactly after trimming surrounding whitespace.
- The host `api-keys` list is read from the same config file the server
  loaded (`--config` flag or `config.yaml` in the working directory) and is
  taken from `access.api-keys` (v8 layout) or, in legacy files without it,
  the top-level `api-keys` list. A top-level `api-keys` mapping is the v8
  upstream key section and is never treated as client keys. The list is
  cached until the file changes; a transient read or parse failure falls back
  to the last good snapshot. On the auth hot path the cached snapshot is
  served lock-free for up to one second between file checks, so a config
  edit takes at most one second to be noticed.
- A failed plugin config reload resets to empty rules instead of keeping
  stale ones: keys in `api-keys` become temporarily unrestricted rather than
  locked out. The parse error is logged through the host logger.
- A known key requesting a blocked model gets HTTP 403 with
  `{"error":"model \"<model>\" is not allowed for this API key"}`. Missing or
  unknown keys still get the host's own 401. Hosts older than v8.0.39 ignore
  the explicit deny and answer 401 for both. Rejected requests are logged with
  a masked key and the offending model.

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
  -ldflags '-X main.pluginVersion=0.3.0-dev' \
  -o model-limiter.dylib .
```

Use `.so` on Linux and `.dll` on Windows. The c-shared build also produces a
C header; the host does not need it.

## Security notes

- Reading the api-keys list and rewriting rules both require the CPA
  management key: `/state` and `/apply` are `/v0/management` routes guarded by
  the host. Only the page shell and logo are public `/v0/resource` assets, and
  they contain no data.
- The panel page sends `frame-ancestors 'self'` (plus any `allowed_origins`),
  so other sites cannot embed it.
- Writes go straight to `config.yaml` using an atomic temp-file rename so
  concurrent readers never see a partial file. Comments and unrelated
  settings are preserved by rewriting only the `plugins.configs.model-limiter.keys`
  subtree.
- API keys live in the host `config.yaml` under `access.api-keys` (legacy:
  `api-keys`) and `plugins.configs`; protect the file accordingly.
- Logs mask keys (`sk-a****klmn`) and never include full credentials.
