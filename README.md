# CLIProxyAPI Model Limiter Plugin

A CLIProxyAPI frontend auth plugin that restricts which models specific
inbound API keys may use. It registers as a `FrontendAuthProvider` and
inspects the API key (headers/query) together with the requested model (JSON
body `model` field, or the Gemini-style `/models/<model>:<action>` URL path)
in a single authentication pass.

Only the keys listed in the plugin config are governed by the plugin; every
other key keeps flowing through the host `api-keys` provider untouched. When
the plugin accepts a listed key, authentication succeeds immediately; when it
rejects one (unknown model), the host access manager falls through to the
builtin `config-api-key` provider, which denies the key as long as it is not
listed in `api-keys`.

**The one rule that keeps enforcement hard: a restricted key must appear only
in the plugin config, never in the host `api-keys` list.** If a restricted
key is duplicated into `api-keys`, the fallback path re-admits it for any
model.

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
        version: 0.1.0
        release-tag: v0.1.0
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
| `exclusive` | boolean | Register as the only active frontend auth provider. Defaults to `false`, which is the recommended mode: unlisted keys keep working through the host `api-keys`. Set `true` only to fully replace the host `api-keys` check with the plugin allow list (every valid key must then be listed under `keys`). |
| `keys` | list | Restricted key rules. Each entry has `api-key` (string, required, unique) and `models` (string list, optional). `*` wildcards are allowed in model patterns. An empty or missing `models` list allows every model for that key. Keys not listed here are handled by the host `api-keys` provider. |

Example — `sk-team-a` and `sk-team-b` are model-restricted, all other keys in
the host `api-keys` list keep full access:

```yaml
api-keys:
  - sk-admin          # unrestricted keys stay here as usual
  - sk-ci

plugins:
  enabled: true
  configs:
    model-limiter:
      enabled: true
      keys:
        - api-key: sk-team-a   # restricted keys live ONLY here
          models:
            - gpt-5.2
            - claude-*
        - api-key: sk-team-b
          models:
            - gemini-2.5-flash
            - gemini-2.5-pro
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
- Keys are compared exactly after trimming surrounding whitespace.
- A failed config reload resets the plugin to empty rules instead of keeping
  stale ones; restricted keys then fall back to the host `api-keys` provider,
  where they are not listed and stay denied. The parse error is logged
  through the host logger.
- Rejections surface to clients as HTTP 401 (the host access manager owns the
  error shape), not as a 403 "model not allowed" message. Rejected requests
  are logged with a masked key and the offending model.

## Build locally

```bash
go test ./...
go build -buildmode=c-shared \
  -ldflags '-X main.pluginVersion=0.1.0-dev' \
  -o model-limiter.dylib .
```

Use `.so` on Linux and `.dll` on Windows. The c-shared build also produces a
C header; the host does not need it.

## Security notes

- Never duplicate a restricted key into the host `api-keys` list: the
  fallback path would re-admit it for any model. This is the only invariant
  the operator must maintain.
- API keys live in the host `config.yaml` under `plugins.configs`; protect
  the file accordingly.
- Logs mask keys (`sk-a****klmn`) and never include full credentials.
