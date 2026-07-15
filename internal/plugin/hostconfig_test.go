package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigFile(t *testing.T) {
	t.Parallel()

	getwd := func() (string, error) { return "/srv", nil }
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no flag", []string{"server"}, filepath.Join("/srv", "config.yaml")},
		{"double dash flag", []string{"server", "--config", "/etc/cpa.yaml"}, "/etc/cpa.yaml"},
		{"single dash flag", []string{"server", "-config", "/etc/cpa.yaml"}, "/etc/cpa.yaml"},
		{"double dash equals", []string{"server", "--config=/etc/cpa.yaml"}, "/etc/cpa.yaml"},
		{"single dash equals", []string{"server", "-config=/etc/cpa.yaml"}, "/etc/cpa.yaml"},
		{"terminator stops parsing", []string{"server", "--", "--config", "/etc/cpa.yaml"}, filepath.Join("/srv", "config.yaml")},
		{"flag without value", []string{"server", "--config"}, filepath.Join("/srv", "config.yaml")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveConfigFile(tt.args, getwd); got != tt.want {
				t.Fatalf("resolveConfigFile(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestParseHostAPIKeys(t *testing.T) {
	t.Parallel()

	keys, errParse := parseHostAPIKeys([]byte("port: 8317\napi-keys:\n  - sk-one\n  - '  sk-two  '\n  - ''\n"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %v", keys)
	}
	if _, ok := keys["sk-one"]; !ok {
		t.Fatal("sk-one missing")
	}
	if _, ok := keys["sk-two"]; !ok {
		t.Fatal("sk-two should be trimmed and kept")
	}

	if _, errBad := parseHostAPIKeys([]byte(":\tnot yaml")); errBad == nil {
		t.Fatal("invalid yaml should fail")
	}
}

func TestHostKeysCacheReloadAndFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if errWrite := os.WriteFile(path, []byte("api-keys:\n  - sk-one\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}

	cache := &hostKeysCache{path: path}
	keys, errResolve := cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := keys["sk-one"]; !ok || len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}

	// A subsequently broken file must not evict the last good snapshot.
	if errWrite := os.WriteFile(path, []byte(":\tnot yaml"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	keys, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := keys["sk-one"]; !ok {
		t.Fatalf("broken rewrite should keep last good snapshot, got %v", keys)
	}

	// A valid rewrite is picked up. The content length differs from the
	// first snapshot so change detection never depends on mtime granularity.
	if errWrite := os.WriteFile(path, []byte("api-keys:\n  - sk-two\n  - sk-extra\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	keys, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := keys["sk-two"]; !ok || len(keys) != 2 {
		t.Fatalf("keys after rewrite = %v", keys)
	}

	// Deleting the file also falls back to the snapshot.
	if errRemove := os.Remove(path); errRemove != nil {
		t.Fatal(errRemove)
	}
	keys, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := keys["sk-two"]; !ok {
		t.Fatalf("missing file should keep last good snapshot, got %v", keys)
	}
}

func TestHostKeysCacheErrorsWhenNeverLoaded(t *testing.T) {
	t.Parallel()

	cache := &hostKeysCache{path: filepath.Join(t.TempDir(), "missing.yaml")}
	if _, errResolve := cache.resolve(); errResolve == nil {
		t.Fatal("missing file with no snapshot should error")
	}
}
