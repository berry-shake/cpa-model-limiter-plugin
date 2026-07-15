package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// RuleEntry is one desired restriction rule expressed by the panel page.
type RuleEntry struct {
	APIKey string
	Models []string
}

// configWriter serializes plugin-driven edits to the host config file so
// concurrent writes coming from the panel do not corrupt the shared file.
// It cannot prevent races with the host's own SaveConfigPreserveComments
// path (managed via the management API); atomic rename keeps the file valid
// even when the last-writer-wins race is lost.
type configWriter struct {
	mu   sync.Mutex
	path func() string
}

func newConfigWriter(pathFn func() string) *configWriter {
	return &configWriter{path: pathFn}
}

// ApplyRules writes the given rule set into plugins.configs.model-limiter.keys
// while preserving every other setting and its surrounding comments.
// A nil or empty slice removes the keys entry entirely, matching the
// PATCH-with-null semantics of the host management API.
func (w *configWriter) ApplyRules(rules []RuleEntry) error {
	if w == nil {
		return errors.New("config writer is not initialized")
	}
	normalized, errNorm := normalizeRules(rules)
	if errNorm != nil {
		return errNorm
	}
	path := strings.TrimSpace(w.path())
	if path == "" {
		return errors.New("host config path is not resolved")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return fmt.Errorf("read host config: %w", errRead)
	}
	var root yaml.Node
	if errUnmarshal := yaml.Unmarshal(raw, &root); errUnmarshal != nil {
		return fmt.Errorf("parse host config: %w", errUnmarshal)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return errors.New("host config is empty or invalid")
	}
	if errPatch := patchRulesNode(root.Content[0], normalized); errPatch != nil {
		return errPatch
	}

	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if errEncode := encoder.Encode(&root); errEncode != nil {
		_ = encoder.Close()
		return fmt.Errorf("encode host config: %w", errEncode)
	}
	if errClose := encoder.Close(); errClose != nil {
		return fmt.Errorf("finalize host config: %w", errClose)
	}
	return atomicWrite(path, []byte(buf.String()))
}

func normalizeRules(rules []RuleEntry) ([]RuleEntry, error) {
	out := make([]RuleEntry, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for index, entry := range rules {
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			return nil, fmt.Errorf("rules[%d]: api-key is required", index)
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("rules[%d]: duplicate api-key %q", index, key)
		}
		seen[key] = struct{}{}
		models := make([]string, 0, len(entry.Models))
		modelsSeen := make(map[string]struct{}, len(entry.Models))
		for _, model := range entry.Models {
			model = strings.ToLower(strings.TrimSpace(model))
			if model == "" {
				continue
			}
			if _, ok := modelsSeen[model]; ok {
				continue
			}
			modelsSeen[model] = struct{}{}
			models = append(models, model)
		}
		out = append(out, RuleEntry{APIKey: key, Models: models})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].APIKey < out[j].APIKey })
	return out, nil
}

// patchRulesNode replaces plugins.configs.model-limiter.keys with the given
// rule list. It creates any missing mapping nodes on the path so a fresh
// config that has never had the plugin configured still works.
func patchRulesNode(doc *yaml.Node, rules []RuleEntry) error {
	if doc == nil || doc.Kind != yaml.MappingNode {
		return errors.New("host config root is not a mapping")
	}
	plugins, errPlugins := ensureMapping(doc, "plugins")
	if errPlugins != nil {
		return errPlugins
	}
	configs, errConfigs := ensureMapping(plugins, "configs")
	if errConfigs != nil {
		return errConfigs
	}
	pluginConfig, errPluginConfig := ensureMapping(configs, ProviderID)
	if errPluginConfig != nil {
		return errPluginConfig
	}
	return setKeysField(pluginConfig, rules)
}

func ensureMapping(parent *yaml.Node, name string) (*yaml.Node, error) {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("cannot descend into %q: parent is not a mapping", name)
	}
	for index := 0; index < len(parent.Content); index += 2 {
		key := parent.Content[index]
		if key == nil || key.Kind != yaml.ScalarNode || key.Value != name {
			continue
		}
		value := parent.Content[index+1]
		if value == nil {
			value = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			parent.Content[index+1] = value
		}
		if value.Kind == yaml.AliasNode || value.Kind == yaml.DocumentNode {
			return nil, fmt.Errorf("cannot descend into %q: unsupported node kind", name)
		}
		if value.Kind != yaml.MappingNode {
			replacement := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			parent.Content[index+1] = replacement
			return replacement, nil
		}
		return value, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, key, value)
	return value, nil
}

func setKeysField(pluginConfig *yaml.Node, rules []RuleEntry) error {
	if pluginConfig == nil || pluginConfig.Kind != yaml.MappingNode {
		return errors.New("plugin config node is not a mapping")
	}
	keysIndex := -1
	for index := 0; index < len(pluginConfig.Content); index += 2 {
		key := pluginConfig.Content[index]
		if key != nil && key.Kind == yaml.ScalarNode && key.Value == "keys" {
			keysIndex = index
			break
		}
	}
	if len(rules) == 0 {
		if keysIndex >= 0 {
			pluginConfig.Content = append(pluginConfig.Content[:keysIndex], pluginConfig.Content[keysIndex+2:]...)
		}
		return nil
	}
	value := buildKeysSequence(rules)
	if keysIndex >= 0 {
		pluginConfig.Content[keysIndex+1] = value
		return nil
	}
	pluginConfig.Content = append(pluginConfig.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "keys"},
		value,
	)
	return nil
}

func buildKeysSequence(rules []RuleEntry) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, rule := range rules {
		entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "api-key"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: rule.APIKey},
		}}
		if len(rule.Models) > 0 {
			modelsSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for _, model := range rule.Models {
				modelsSeq.Content = append(modelsSeq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: model})
			}
			entry.Content = append(entry.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "models"},
				modelsSeq,
			)
		}
		seq.Content = append(seq.Content, entry)
	}
	return seq
}

// atomicWrite writes payload to a temp file next to target and renames it
// into place. Concurrent readers keep seeing the previous complete file,
// never a partial write.
func atomicWrite(target string, payload []byte) error {
	dir := filepath.Dir(target)
	tmp, errTemp := os.CreateTemp(dir, ".model-limiter-*.yaml")
	if errTemp != nil {
		return fmt.Errorf("create temp config: %w", errTemp)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		if _, errStat := os.Stat(tmpPath); errStat == nil {
			if errRemove := os.Remove(tmpPath); errRemove != nil {
				// Removing the stale temp is best-effort.
				_ = errRemove
			}
		}
	}
	if _, errWrite := tmp.Write(payload); errWrite != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp config: %w", errWrite)
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp config: %w", errSync)
	}
	if errClose := tmp.Close(); errClose != nil {
		cleanup()
		return fmt.Errorf("close temp config: %w", errClose)
	}
	if info, errStat := os.Stat(target); errStat == nil {
		if errChmod := os.Chmod(tmpPath, info.Mode().Perm()); errChmod != nil {
			// Best-effort: keep the default 0o600 if we cannot mirror the mode.
			_ = errChmod
		}
	}
	if errRename := os.Rename(tmpPath, target); errRename != nil {
		cleanup()
		return fmt.Errorf("rename temp config: %w", errRename)
	}
	return nil
}
