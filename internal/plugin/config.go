package plugin

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the parsed plugin configuration.
type Config struct {
	// Rules maps a normalized API key to its rule. Keys not listed here are
	// unrestricted; every key (listed or not) must additionally be present
	// in the host api-keys list to be accepted at all.
	Rules map[string]Rule
	// AllowedOrigins lists extra origins that may iframe the panel page in
	// addition to the same-origin CPA management panel.
	AllowedOrigins []string
}

// Rule is the per-key allow list.
type Rule struct {
	// Patterns are normalized allowed model patterns; * matches any sequence.
	// An empty list allows every model for the key.
	Patterns []string
}

type yamlConfig struct {
	Keys           []yamlKey `yaml:"keys"`
	AllowedOrigins string    `yaml:"allowed_origins"`
}

type yamlKey struct {
	APIKey string   `yaml:"api-key"`
	Models []string `yaml:"models"`
}

// DefaultConfig returns the empty default used before any host config
// arrives: no per-key restrictions, so every key present in the host
// api-keys list passes with any model.
func DefaultConfig() Config {
	return Config{Rules: map[string]Rule{}}
}

// ParseConfig parses the plugins.configs.model-limiter YAML subtree.
func ParseConfig(raw []byte) (Config, error) {
	var parsed yamlConfig
	if errUnmarshal := yaml.Unmarshal(raw, &parsed); errUnmarshal != nil {
		return Config{}, fmt.Errorf("parse plugin config: %w", errUnmarshal)
	}
	out := DefaultConfig()
	for index, entry := range parsed.Keys {
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			return Config{}, fmt.Errorf("keys[%d]: missing api-key", index)
		}
		if _, duplicate := out.Rules[key]; duplicate {
			return Config{}, fmt.Errorf("keys[%d]: duplicate api-key", index)
		}
		patterns := make([]string, 0, len(entry.Models))
		for _, model := range entry.Models {
			model = strings.ToLower(strings.TrimSpace(model))
			if model == "" {
				continue
			}
			patterns = append(patterns, model)
		}
		out.Rules[key] = Rule{Patterns: patterns}
	}
	out.AllowedOrigins = parseOrigins(parsed.AllowedOrigins)
	return out, nil
}

// parseOrigins splits a comma-separated origin list, trims whitespace and
// trailing slashes, and drops duplicates while preserving first-seen order.
// A blank input returns nil so callers can compare against the empty default.
func parseOrigins(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		origin = strings.TrimRight(origin, "/")
		if _, dup := seen[origin]; dup {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RuleForKey looks up the rule for an API key.
func (c Config) RuleForKey(key string) (Rule, bool) {
	rule, ok := c.Rules[strings.TrimSpace(key)]
	return rule, ok
}

// AllowsModel reports whether the rule permits the requested model. The model
// is compared case-insensitively after stripping any thinking suffix.
func (r Rule) AllowsModel(model string) bool {
	if len(r.Patterns) == 0 {
		return true
	}
	model = strings.ToLower(strings.TrimSpace(model))
	for _, pattern := range r.Patterns {
		if matchWildcard(pattern, model) {
			return true
		}
	}
	return false
}

// matchWildcard matches value against pattern where * matches any sequence
// (including an empty one and across any characters).
func matchWildcard(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for index := 1; index < len(parts)-1; index++ {
		part := parts[index]
		if part == "" {
			continue
		}
		position := strings.Index(value, part)
		if position < 0 {
			return false
		}
		value = value[position+len(part):]
	}
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(value, last)
}

// MaskKey redacts an API key for log output, keeping short prefix/suffix hints.
func MaskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}
