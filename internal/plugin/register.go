package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// ProviderID is the frontend auth provider identifier reported to the host.
const ProviderID = "model-limiter"

const panelPath = "/v0/resource/plugins/model-limiter/panel"

const (
	configKeys           = "keys"
	configAllowedOrigins = "allowed_origins"
)

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
	ConfigYAML []byte `json:"config_yaml"`
}

type resourceDeclaration struct {
	Path        string `json:"path"`
	Menu        string `json:"menu,omitempty"`
	Description string `json:"description,omitempty"`
}

type managementRegistration struct {
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
			SchemaVersion: pluginabi.SchemaVersion,
			Metadata: pluginapi.Metadata{
				Name:             "Model Limiter",
				Version:          s.version,
				Author:           "berry-shake",
				GitHubRepository: "https://github.com/berry-shake/cpa-model-limiter-plugin",
				ConfigFields: []pluginapi.ConfigField{
					{
						Name:        configKeys,
						Type:        pluginapi.ConfigFieldTypeArray,
						Description: "Restriction rules. Each entry: api-key (string) plus models (string list, * wildcards allowed). The key must also exist in the host api-keys list; a rule alone never grants access. Keys without a rule are unrestricted. Prefer the Model Limiter menu page for editing.",
					},
					{
						Name:        configAllowedOrigins,
						Type:        pluginapi.ConfigFieldTypeString,
						Description: "受信任的来源列表（逗号分隔），允许以 iframe 嵌入面板并跨源调用资源接口。留空为最严格默认：禁止任何 iframe 嵌入（frame-ancestors 'none'），并拒绝跨源浏览器请求。",
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
			Resources: []resourceDeclaration{
				{Path: "/panel", Menu: "Model Limiter", Description: "Edit per-key model restrictions."},
				// /state and /apply back the panel page. Menu is empty so they
				// stay out of the management panel sidebar.
				{Path: "/state"},
				{Path: "/apply"},
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

func (s *Service) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// AllowedOrigins returns a defensive copy of the configured trusted origins.
// An empty result means the strictest default: iframe embedding is denied
// and cross-origin browser requests to /state and /apply are rejected.
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
//  3. a key with a rule must request an allowed model.
//
// Rules only subtract capability from keys that api-keys already grants; a
// rule for a key missing from api-keys never admits it.
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

	model := ExtractModel(req.Path, req.Body)
	if rule, restricted := s.snapshot().RuleForKey(key); restricted {
		if model != "" && !rule.AllowsModel(model) {
			s.logFn("warn", "model-limiter: model not allowed for key", map[string]any{
				"key":   MaskKey(key),
				"model": model,
			})
			return pluginapi.FrontendAuthResponse{}
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
