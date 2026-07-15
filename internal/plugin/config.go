package plugin

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the parsed plugin configuration.
type Config struct {
	// Exclusive registers the plugin as the only active frontend auth
	// provider. Defaults to false: the plugin governs only the keys listed
	// here while every other key keeps flowing through the host api-keys
	// provider. Enforcement stays hard as long as restricted keys are not
	// duplicated into the host api-keys list — a rejection here falls
	// through to the builtin provider, which denies unknown keys.
	Exclusive bool
	// Rules maps a normalized API key to its rule.
	Rules map[string]Rule
}

// Rule is the per-key allow list.
type Rule struct {
	// Patterns are normalized allowed model patterns; * matches any sequence.
	// An empty list allows every model for the key.
	Patterns []string
}

type yamlConfig struct {
	Exclusive *bool     `yaml:"exclusive"`
	Keys      []yamlKey `yaml:"keys"`
}

type yamlKey struct {
	APIKey string   `yaml:"api-key"`
	Models []string `yaml:"models"`
}

// DefaultConfig returns the empty default used before any host config
// arrives: no restricted keys and non-exclusive registration, so the host
// api-keys provider keeps governing all traffic.
func DefaultConfig() Config {
	return Config{Exclusive: false, Rules: map[string]Rule{}}
}

// ParseConfig parses the plugins.configs.model-limiter YAML subtree.
func ParseConfig(raw []byte) (Config, error) {
	var parsed yamlConfig
	if errUnmarshal := yaml.Unmarshal(raw, &parsed); errUnmarshal != nil {
		return Config{}, fmt.Errorf("parse plugin config: %w", errUnmarshal)
	}
	out := DefaultConfig()
	if parsed.Exclusive != nil {
		out.Exclusive = *parsed.Exclusive
	}
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
	return out, nil
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
