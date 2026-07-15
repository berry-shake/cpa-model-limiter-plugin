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

	snap, errParse := parseHostAPIKeys([]byte("port: 8317\napi-keys:\n  - sk-one\n  - '  sk-two  '\n  - ''\n  - sk-one\n"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	// Order must match config.yaml; duplicates and blanks are dropped.
	if len(snap.Ordered) != 2 || snap.Ordered[0] != "sk-one" || snap.Ordered[1] != "sk-two" {
		t.Fatalf("ordered = %v", snap.Ordered)
	}
	if _, ok := snap.Set["sk-one"]; !ok {
		t.Fatal("sk-one missing from set")
	}
	if _, ok := snap.Set["sk-two"]; !ok {
		t.Fatal("sk-two should be trimmed and kept in set")
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
	snap, errResolve := cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := snap.Set["sk-one"]; !ok || len(snap.Set) != 1 || len(snap.Ordered) != 1 {
		t.Fatalf("snap = %+v", snap)
	}

	// A subsequently broken file must not evict the last good snapshot.
	if errWrite := os.WriteFile(path, []byte(":\tnot yaml"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	snap, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := snap.Set["sk-one"]; !ok {
		t.Fatalf("broken rewrite should keep last good snapshot, got %+v", snap)
	}

	// A valid rewrite is picked up. The content length differs from the
	// first snapshot so change detection never depends on mtime granularity.
	if errWrite := os.WriteFile(path, []byte("api-keys:\n  - sk-two\n  - sk-extra\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	snap, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if len(snap.Ordered) != 2 || snap.Ordered[0] != "sk-two" || snap.Ordered[1] != "sk-extra" {
		t.Fatalf("ordered after rewrite = %v", snap.Ordered)
	}

	// Deleting the file also falls back to the snapshot.
	if errRemove := os.Remove(path); errRemove != nil {
		t.Fatal(errRemove)
	}
	snap, errResolve = cache.resolve()
	if errResolve != nil {
		t.Fatal(errResolve)
	}
	if _, ok := snap.Set["sk-two"]; !ok {
		t.Fatalf("missing file should keep last good snapshot, got %+v", snap)
	}
}

func TestHostKeysCacheErrorsWhenNeverLoaded(t *testing.T) {
	t.Parallel()

	cache := &hostKeysCache{path: filepath.Join(t.TempDir(), "missing.yaml")}
	if _, errResolve := cache.resolve(); errResolve == nil {
		t.Fatal("missing file with no snapshot should error")
	}
}
