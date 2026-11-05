package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// ProviderID is the frontend auth provider identifier reported to the host.
const ProviderID = "model-limiter"

const panelPath = "/v0/resource/plugins/model-limiter/panel"

const (
	configKeys           = "keys"
	configAllowedOrigins = "allowed_origins"
)

// maxSchemaVersion is the newest plugin RPC contract this plugin implements.
// Schema 6 makes the host return management JSON verbatim instead of
// HTML-escaping its strings. It is pinned rather than taken from
// pluginabi.SchemaVersion so an SDK bump cannot silently opt into newer
// contracts or make older hosts refuse to load the plugin.
const maxSchemaVersion = pluginabi.SchemaVersionRawManagementResponse

// LogFunc forwards a log line to the host logger.
type LogFunc func(level, message string, fields map[string]any)

// Service dispatches plugin lifecycle and frontend auth RPC methods.
type Service struct {
	version  string
	logFn    LogFunc
	hostKeys HostKeysResolver
	writer   *configWriter

	mu  sync.RWMutex
	cfg Config
}

type rpcCapabilities struct {
	FrontendAuthProvider          bool `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool `json:"frontend_auth_provider_exclusive"`
	ManagementAPI                 bool `json:"management_api"`
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
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type resourceDeclaration struct {
	Path        string `json:"path"`
	Menu        string `json:"menu,omitempty"`
	Description string `json:"description,omitempty"`
}

type routeDeclaration struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type managementRegistration struct {
	Routes    []routeDeclaration    `json:"routes,omitempty"`
	Resources []resourceDeclaration `json:"resources,omitempty"`
}

type managementRPCRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   map[string][]string
	Body    []byte
}

// New builds a Service. Until the host delivers configuration at
// plugin.register time the rule set is empty, which means "no model
// restrictions" — the api-keys membership gate still applies.
func New(version string, logFn LogFunc, hostKeys HostKeysResolver) *Service {
	if strings.TrimSpace(version) == "" {
		version = "0.0.0-dev"
	}
	if logFn == nil {
		logFn = func(string, string, map[string]any) {}
	}
	if hostKeys == nil {
		hostKeys = NewHostKeysResolver()
	}
	return &Service{
		version:  version,
		logFn:    logFn,
		hostKeys: hostKeys,
		writer:   newConfigWriter(HostConfigPath),
		cfg:      DefaultConfig(),
	}
}

// Call handles one plugin RPC method and always returns a JSON envelope.
func (s *Service) Call(method string, request []byte) []byte {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		s.applyConfig(request)
		return okEnvelope(rpcRegistration{
			SchemaVersion: negotiateSchemaVersion(request),
			Metadata: pluginapi.Metadata{
				Name:             "Model Limiter",
				Version:          s.version,
				Author:           "berry-shake",
				GitHubRepository: "https://github.com/berry-shake/cpa-model-limiter-plugin",
				Logo:             logoPath,
				ConfigFields: []pluginapi.ConfigField{
					{
						Name:        configKeys,
						Type:        pluginapi.ConfigFieldTypeArray,
						Description: "Restriction rules. Each entry: api-key (string) plus models (string list, * wildcards allowed). The key must also exist in the host api-keys list; a rule alone never grants access. Keys without a rule are unrestricted. Prefer the Model Limiter menu page for editing.",
					},
					{
						Name:        configAllowedOrigins,
						Type:        pluginapi.ConfigFieldTypeString,
						Description: "额外允许以 iframe 嵌入面板页面的来源列表（逗号分隔）。留空时只允许同源（CPA 管理面板）嵌入（frame-ancestors 'self'）。数据接口走 /v0/management，始终需要管理密钥。",
					},
				},
			},
			Capabilities: rpcCapabilities{
				FrontendAuthProvider:          true,
				FrontendAuthProviderExclusive: true,
				ManagementAPI:                 true,
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
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration{
			// The panel page and logo are browser-navigable resources without
			// data; the endpoints behind them require the management key.
			Routes: []routeDeclaration{
				{Method: http.MethodGet, Path: statePath, Description: "List host api-keys and model restriction rules."},
				{Method: http.MethodPost, Path: applyPath, Description: "Replace model restriction rules and rewrite config.yaml."},
			},
			Resources: []resourceDeclaration{
				{Path: "/panel", Menu: "Model Limiter", Description: "Edit per-key model restrictions."},
				{Path: "/logo.png"},
			},
		})
	case pluginabi.MethodManagementHandle:
		var req managementRPCRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return ErrorEnvelope("invalid_request", "decode management request: "+errUnmarshal.Error())
		}
		return okEnvelope(s.handleManagement(req))
	default:
		return ErrorEnvelope("unknown_method", "unknown method: "+method)
	}
}

// applyConfig parses plugins.configs.model-limiter from the host RPC
// payload. A missing or malformed payload resets to the empty default: no
// model restrictions, while the api-keys membership gate keeps applying.
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
	s.logFn("info", "model-limiter: configuration applied", map[string]any{"rules": len(cfg.Rules)})
}

// negotiateSchemaVersion answers plugin.register with the newest schema both
// sides implement. Hosts advertise theirs in the lifecycle request; one that
// advertises nothing only knows the original contract.
func negotiateSchemaVersion(request []byte) uint32 {
	var lifecycle rpcLifecycleRequest
	if errUnmarshal := json.Unmarshal(request, &lifecycle); errUnmarshal != nil || lifecycle.SchemaVersion == 0 {
		return 1
	}
	return min(lifecycle.SchemaVersion, maxSchemaVersion)
}

func (s *Service) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// AllowedOrigins returns a defensive copy of the configured trusted origins.
// An empty result keeps panel embedding same-origin only.
func (s *Service) AllowedOrigins() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.cfg.AllowedOrigins) == 0 {
		return nil
	}
	out := make([]string, len(s.cfg.AllowedOrigins))
	copy(out, s.cfg.AllowedOrigins)
	return out
}

// Rules returns the current rule set as a stable, sorted slice suitable for
// JSON serialization by the panel page.
func (s *Service) Rules() []RuleEntry {
	snap := s.snapshot()
	out := make([]RuleEntry, 0, len(snap.Rules))
	for key, rule := range snap.Rules {
		models := append([]string(nil), rule.Patterns...)
		out = append(out, RuleEntry{APIKey: key, Models: models})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].APIKey < out[j].APIKey })
	return out
}

// ApplyRules validates and writes rules to config.yml and updates the
// in-memory rule set on success. The host may also push a follow-up
// reconfigure with the same data, which is idempotent.
func (s *Service) ApplyRules(rules []RuleEntry) ([]RuleEntry, error) {
	if s.writer == nil {
		return nil, errors.New("config writer is not initialized")
	}
	if errWrite := s.writer.ApplyRules(rules); errWrite != nil {
		return nil, errWrite
	}
	normalized, _ := normalizeRules(rules)
	cfg := DefaultConfig()
	for _, rule := range normalized {
		cfg.Rules[rule.APIKey] = Rule{Patterns: append([]string(nil), rule.Models...)}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	s.logFn("info", "model-limiter: rules updated via panel", map[string]any{"rules": len(cfg.Rules)})
	return s.Rules(), nil
}

// Authenticate is the exclusive frontend auth decision. The host api-keys
// list stays the single source of key validity:
//
//  1. key must be present in the host api-keys list, otherwise reject;
//  2. a key without a rule is unrestricted;
//  3. a key with a rule must request an allowed model, and its body must be
//     readable so the model the handler runs is the one checked here.
//
// Rules only subtract capability from keys that api-keys already grants; a
// rule for a key missing from api-keys never admits it. Unknown keys get an
// empty response so the host answers with its usual 401; known keys that a
// rule blocks get an explicit deny (CLIProxyAPI v8.0.39+ forwards it, older
// hosts fall back to 401).
func (s *Service) Authenticate(req pluginapi.FrontendAuthRequest) pluginapi.FrontendAuthResponse {
	key := ExtractAPIKey(req.Headers, req.Query)
	if key == "" {
		return pluginapi.FrontendAuthResponse{}
	}

	hostKeys, errKeys := s.hostKeys()
	if errKeys != nil {
		s.logFn("error", "model-limiter: cannot read host api-keys, rejecting request", map[string]any{"error": errKeys.Error()})
		return pluginapi.FrontendAuthResponse{}
	}
	if _, known := hostKeys.Set[key]; !known {
		return pluginapi.FrontendAuthResponse{}
	}

	// Body is the raw bytes as received; for content-encoded requests the
	// host also sends the decoded body the handler will parse. A body that
	// stays encoded is never searched for a model: gjson skips leading binary
	// bytes, so a decoy object inside, say, a zstd skippable frame would be
	// read while the handler decodes and runs a different model.
	body := req.Body
	unreadable := encodedBodyUnreadable(req)
	if req.DecodedBody != nil {
		body = req.DecodedBody
	} else if unreadable {
		body = nil
	}
	model := ExtractModel(req.Path, body)
	if rule, restricted := s.snapshot().RuleForKey(key); restricted {
		if model == "" && unreadable {
			s.logFn("warn", "model-limiter: encoded body unreadable for restricted key", map[string]any{
				"key":      MaskKey(key),
				"encoding": req.Headers.Get("Content-Encoding"),
			})
			return pluginapi.FrontendAuthResponse{
				DenyStatusCode: http.StatusUnsupportedMediaType,
				DenyMessage:    "request content encoding is not supported for this API key",
			}
		}
		if model != "" && !rule.AllowsModel(model) {
			s.logFn("warn", "model-limiter: model not allowed for key", map[string]any{
				"key":   MaskKey(key),
				"model": model,
			})
			return pluginapi.FrontendAuthResponse{
				DenyStatusCode: http.StatusForbidden,
				DenyMessage:    fmt.Sprintf("model %q is not allowed for this API key", model),
			}
		}
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

// encodedBodyUnreadable reports whether the handler may run a body the plugin
// cannot inspect: the request is content-encoded, the host sent no decoded
// copy (hosts before v8.0.40, or a coding list the host leaves to the
// handler), and the raw bytes are not the JSON the handler falls back to.
func encodedBodyUnreadable(req pluginapi.FrontendAuthRequest) bool {
	if req.DecodedBody != nil || len(req.Body) == 0 {
		return false
	}
	encoding := strings.TrimSpace(req.Headers.Get("Content-Encoding"))
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return false
	}
	return !json.Valid(req.Body)
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
