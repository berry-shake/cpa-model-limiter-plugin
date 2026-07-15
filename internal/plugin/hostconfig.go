package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// HostKeysResolver returns the current host api-keys set.
type HostKeysResolver func() (map[string]struct{}, error)

// hostKeysCache lazily reads api-keys from the host configuration file and
// re-parses only when the file changes. When a previously good snapshot
// exists, transient read or parse failures fall back to it so a broken write
// never locks every caller out.
type hostKeysCache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	size    int64
	keys    map[string]struct{}
	loaded  bool
}

// NewHostKeysResolver builds a resolver bound to the host process arguments.
func NewHostKeysResolver() HostKeysResolver {
	cache := &hostKeysCache{}
	return cache.resolve
}

func (c *hostKeysCache) resolve() (map[string]struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		c.path = resolveConfigFile(os.Args, os.Getwd)
	}
	info, errStat := os.Stat(c.path)
	if errStat != nil {
		if c.loaded {
			return c.keys, nil
		}
		return nil, fmt.Errorf("stat host config: %w", errStat)
	}
	if c.loaded && info.ModTime().Equal(c.modTime) && info.Size() == c.size {
		return c.keys, nil
	}
	raw, errRead := os.ReadFile(c.path)
	if errRead != nil {
		if c.loaded {
			return c.keys, nil
		}
		return nil, fmt.Errorf("read host config: %w", errRead)
	}
	keys, errParse := parseHostAPIKeys(raw)
	if errParse != nil {
		if c.loaded {
			return c.keys, nil
		}
		return nil, errParse
	}
	c.keys = keys
	c.modTime = info.ModTime()
	c.size = info.Size()
	c.loaded = true
	return c.keys, nil
}

func parseHostAPIKeys(raw []byte) (map[string]struct{}, error) {
	var parsed struct {
		APIKeys []string `yaml:"api-keys"`
	}
	if errYAML := yaml.Unmarshal(raw, &parsed); errYAML != nil {
		return nil, fmt.Errorf("parse host config: %w", errYAML)
	}
	keys := make(map[string]struct{}, len(parsed.APIKeys))
	for _, key := range parsed.APIKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys[key] = struct{}{}
	}
	return keys, nil
}

// resolveConfigFile mirrors the host's --config flag parsing so the plugin
// reads the same file the running server loaded.
func resolveConfigFile(args []string, getwd func() (string, error)) string {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--":
			return defaultConfigFile(getwd)
		case arg == "-config" || arg == "--config":
			if index+1 < len(args) {
				return args[index+1]
			}
			return defaultConfigFile(getwd)
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return defaultConfigFile(getwd)
}

func defaultConfigFile(getwd func() (string, error)) string {
	wd, errGetwd := getwd()
	if errGetwd != nil {
		return "config.yaml"
	}
	return filepath.Join(wd, "config.yaml")
}
