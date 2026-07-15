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

// HostKeysSnapshot carries the host api-keys list in the order they appear in
// config.yaml (for panel display) together with a set for O(1) membership
// checks on the auth hot path.
type HostKeysSnapshot struct {
	Ordered []string
	Set     map[string]struct{}
}

// HostKeysResolver returns the current host api-keys snapshot.
type HostKeysResolver func() (HostKeysSnapshot, error)

// hostKeysCache lazily reads api-keys from the host configuration file and
// re-parses only when the file changes. When a previously good snapshot
// exists, transient read or parse failures fall back to it so a broken write
// never locks every caller out.
type hostKeysCache struct {
	mu       sync.Mutex
	path     string
	modTime  time.Time
	size     int64
	snapshot HostKeysSnapshot
	loaded   bool
}

// NewHostKeysResolver builds a resolver bound to the host process arguments.
func NewHostKeysResolver() HostKeysResolver {
	cache := &hostKeysCache{}
	return cache.resolve
}

// HostConfigPath returns the resolved host configuration file path, mirroring
// the same --config flag parsing the server uses at startup.
func HostConfigPath() string {
	return resolveConfigFile(os.Args, os.Getwd)
}

func (c *hostKeysCache) resolve() (HostKeysSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		c.path = resolveConfigFile(os.Args, os.Getwd)
	}
	info, errStat := os.Stat(c.path)
	if errStat != nil {
		if c.loaded {
			return c.snapshot, nil
		}
		return HostKeysSnapshot{}, fmt.Errorf("stat host config: %w", errStat)
	}
	if c.loaded && info.ModTime().Equal(c.modTime) && info.Size() == c.size {
		return c.snapshot, nil
	}
	raw, errRead := os.ReadFile(c.path)
	if errRead != nil {
		if c.loaded {
			return c.snapshot, nil
		}
		return HostKeysSnapshot{}, fmt.Errorf("read host config: %w", errRead)
	}
	snapshot, errParse := parseHostAPIKeys(raw)
	if errParse != nil {
		if c.loaded {
			return c.snapshot, nil
		}
		return HostKeysSnapshot{}, errParse
	}
	c.snapshot = snapshot
	c.modTime = info.ModTime()
	c.size = info.Size()
	c.loaded = true
	return c.snapshot, nil
}

// parseHostAPIKeys returns the api-keys list preserving first-seen order and
// de-duplicated, alongside a set for membership lookups.
func parseHostAPIKeys(raw []byte) (HostKeysSnapshot, error) {
	var parsed struct {
		APIKeys []string `yaml:"api-keys"`
	}
	if errYAML := yaml.Unmarshal(raw, &parsed); errYAML != nil {
		return HostKeysSnapshot{}, fmt.Errorf("parse host config: %w", errYAML)
	}
	ordered := make([]string, 0, len(parsed.APIKeys))
	set := make(map[string]struct{}, len(parsed.APIKeys))
	for _, key := range parsed.APIKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, seen := set[key]; seen {
			continue
		}
		set[key] = struct{}{}
		ordered = append(ordered, key)
	}
	return HostKeysSnapshot{Ordered: ordered, Set: set}, nil
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
