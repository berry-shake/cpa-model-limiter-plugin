package plugin

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// ProviderID is the frontend auth provider identifier reported to the host.
const ProviderID = "model-limiter"

// LogFunc forwards a log line to the host logger.
type LogFunc func(level, message string, fields map[string]any)

// Service dispatches plugin lifecycle and frontend auth RPC methods.
type Service struct {
	version string
	logFn   LogFunc

	mu  sync.RWMutex
	cfg Config
}

type rpcCapabilities struct {
	FrontendAuthProvider          bool `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool `json:"frontend_auth_provider_exclusive"`
}

type rpcRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  rpcCapabilities    `json:"capabilities"`
}

type rpcIdentifierResponse struct {
	Identifier string `json:"identifier"`
}

type rpcLifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

// New builds a Service with an empty (deny-all) rule set until the host
// delivers configuration at plugin.register time.
func New(version string, logFn LogFunc) *Service {
	if strings.TrimSpace(version) == "" {
		version = "0.0.0-dev"
	}
	if logFn == nil {
		logFn = func(string, string, map[string]any) {}
	}
	return &Service{version: version, logFn: logFn, cfg: DefaultConfig()}
}

// Call handles one plugin RPC method and always returns a JSON envelope.
func (s *Service) Call(method string, request []byte) []byte {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		s.applyConfig(request)
		return okEnvelope(rpcRegistration{
			SchemaVersion: pluginabi.SchemaVersion,
			Metadata: pluginapi.Metadata{
				Name:             "Model Limiter",
				Version:          s.version,
				Author:           "berry-shake",
				GitHubRepository: "https://github.com/berry-shake/cpa-model-limiter-plugin",
				ConfigFields: []pluginapi.ConfigField{
					{
						Name:        "exclusive",
						Type:        pluginapi.ConfigFieldTypeBoolean,
						Description: "Register as the only active frontend auth provider (default false). Leave false so unlisted keys keep flowing through the host api-keys; restricted keys must then NOT be duplicated into api-keys or the fallback would re-admit them.",
					},
					{
						Name:        "keys",
						Type:        pluginapi.ConfigFieldTypeArray,
						Description: "Restricted key rules. Each entry: api-key (string) plus models (string list, * wildcards allowed). An empty or missing models list allows every model for that key. Keys not listed here are handled by the host api-keys provider.",
					},
				},
			},
			Capabilities: rpcCapabilities{
				FrontendAuthProvider:          true,
				FrontendAuthProviderExclusive: s.snapshot().Exclusive,
			},
		})
	case pluginabi.MethodPluginShutdown:
		return okEnvelope(struct{}{})
	case pluginabi.MethodFrontendAuthIdentifier:
		return okEnvelope(rpcIdentifierResponse{Identifier: ProviderID})
	case pluginabi.MethodFrontendAuthAuthenticate:
		var req pluginapi.FrontendAuthRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return ErrorEnvelope("invalid_request", "decode frontend auth request: "+errUnmarshal.Error())
		}
		return okEnvelope(s.Authenticate(req))
	default:
		return ErrorEnvelope("unknown_method", "unknown method: "+method)
	}
}

// applyConfig parses plugins.configs.model-limiter from the host RPC
// payload. A missing or malformed payload resets to the empty default: with
// no rules every request falls through to the host api-keys provider, so
// restricted keys (absent from api-keys) stay rejected rather than silently
// regaining access under stale rules.
func (s *Service) applyConfig(request []byte) {
	cfg := DefaultConfig()
	if len(request) > 0 {
		var lifecycle rpcLifecycleRequest
		if errUnmarshal := json.Unmarshal(request, &lifecycle); errUnmarshal == nil && len(lifecycle.ConfigYAML) > 0 {
			parsed, errParse := ParseConfig(lifecycle.ConfigYAML)
			if errParse != nil {
				s.logFn("warn", "model-limiter: config parse failed, resetting to empty rules", map[string]any{"error": errParse.Error()})
			} else {
				cfg = parsed
			}
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	s.logFn("info", "model-limiter: configuration applied", map[string]any{
		"keys":      len(cfg.Rules),
		"exclusive": cfg.Exclusive,
	})
}

func (s *Service) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Authenticate decides whether the inbound request key may use the requested
// model. Only keys listed in the plugin config are handled here; any other
// key returns a non-authenticated response, which the host access manager
// treats as "not handled" and passes to the next provider (the builtin
// api-keys check). A restricted key with a denied model also falls through —
// enforcement holds because restricted keys must not appear in api-keys.
func (s *Service) Authenticate(req pluginapi.FrontendAuthRequest) pluginapi.FrontendAuthResponse {
	cfg := s.snapshot()

	key := ExtractAPIKey(req.Headers, req.Query)
	if key == "" {
		return pluginapi.FrontendAuthResponse{}
	}

	rule, ok := cfg.RuleForKey(key)
	if !ok {
		if cfg.Exclusive {
			s.logFn("warn", "model-limiter: unknown api key rejected (exclusive mode)", map[string]any{"key": MaskKey(key)})
		}
		return pluginapi.FrontendAuthResponse{}
	}

	model := ExtractModel(req.Path, req.Body)
	if model != "" && !rule.AllowsModel(model) {
		s.logFn("warn", "model-limiter: model not allowed for key", map[string]any{
			"key":   MaskKey(key),
			"model": model,
		})
		return pluginapi.FrontendAuthResponse{}
	}

	return pluginapi.FrontendAuthResponse{
		Authenticated: true,
		Principal:     key,
		Metadata: map[string]string{
			"provider": ProviderID,
			"model":    model,
		},
	}
}

func okEnvelope(result any) []byte {
	rawResult, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		return ErrorEnvelope("marshal_failed", errMarshal.Error())
	}
	raw, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: rawResult})
	return raw
}

// ErrorEnvelope builds a failure envelope for RPC and ABI initialization errors.
func ErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(pluginabi.Envelope{
		OK: false,
		Error: &pluginabi.Error{
			Code:    code,
			Message: message,
		},
	})
	return raw
}
