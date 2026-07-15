package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConfig = `# Head comment kept above the file.
api-keys:
  - sk-alpha
  - sk-beta

plugins:
  enabled: true
  configs:
    model-limiter:
      enabled: true
      # Rules edited via the panel below.
      keys:
        - api-key: sk-alpha
          models:
            - gpt-5.2
`

func newTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if errWrite := os.WriteFile(path, []byte(content), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	return path
}

func TestApplyRulesReplacesKeysPreservingComments(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, sampleConfig)
	writer := newConfigWriter(func() string { return path })

	err := writer.ApplyRules([]RuleEntry{
		{APIKey: "sk-beta", Models: []string{"claude-*"}},
		{APIKey: "sk-alpha", Models: []string{"gpt-5.2", "GPT-4.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	got := string(raw)
	for _, want := range []string{
		"# Head comment kept above the file.",
		"# Rules edited via the panel below.",
		"- sk-alpha",
		"- sk-beta",
		"- api-key: sk-alpha",
		"- api-key: sk-beta",
		"- gpt-5.2",
		"- gpt-4.1",
		"- claude-*",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected file to contain %q; got:\n%s", want, got)
		}
	}
	// Rules must appear sorted by api-key so the file diff is stable.
	alphaIdx := strings.Index(got, "api-key: sk-alpha")
	betaIdx := strings.Index(got, "api-key: sk-beta")
	if alphaIdx < 0 || betaIdx < 0 || alphaIdx > betaIdx {
		t.Fatalf("rules should be sorted by api-key; got:\n%s", got)
	}
}

func TestApplyRulesEmptyDropsKeysBlock(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, sampleConfig)
	writer := newConfigWriter(func() string { return path })

	if errApply := writer.ApplyRules(nil); errApply != nil {
		t.Fatal(errApply)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	got := string(raw)
	// The keys: block under model-limiter should be gone. api-keys: at the top
	// level must remain, so match the indented plugin-scoped key only.
	if strings.Contains(got, "      keys:") {
		t.Fatalf("plugin keys: block should be gone; got:\n%s", got)
	}
	if strings.Contains(got, "api-key: sk-alpha") {
		t.Fatalf("plugin rules should be cleared; got:\n%s", got)
	}
	if !strings.Contains(got, "model-limiter:") {
		t.Fatalf("plugin config block should remain; got:\n%s", got)
	}
	if !strings.Contains(got, "enabled: true") {
		t.Fatalf("neighbouring settings should be preserved; got:\n%s", got)
	}
}

func TestApplyRulesCreatesMissingPluginConfig(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, "api-keys:\n  - sk-alpha\n")
	writer := newConfigWriter(func() string { return path })

	err := writer.ApplyRules([]RuleEntry{{APIKey: "sk-alpha", Models: []string{"gpt-5.2"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	got := string(raw)
	if !strings.Contains(got, "plugins:") || !strings.Contains(got, "model-limiter:") {
		t.Fatalf("missing plugin path should be created; got:\n%s", got)
	}
	if !strings.Contains(got, "- api-key: sk-alpha") {
		t.Fatalf("rule should be written; got:\n%s", got)
	}
}

func TestApplyRulesRejectsDuplicateAndEmpty(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, sampleConfig)
	writer := newConfigWriter(func() string { return path })

	errEmpty := writer.ApplyRules([]RuleEntry{{APIKey: "  "}})
	if errEmpty == nil || !strings.Contains(errEmpty.Error(), "api-key is required") {
		t.Fatalf("expected empty api-key error, got %v", errEmpty)
	}
	errDup := writer.ApplyRules([]RuleEntry{
		{APIKey: "sk-alpha"},
		{APIKey: "sk-alpha", Models: []string{"gpt-5.2"}},
	})
	if errDup == nil || !strings.Contains(errDup.Error(), "duplicate") {
		t.Fatalf("expected duplicate api-key error, got %v", errDup)
	}
}

func TestApplyRulesDedupesModels(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, sampleConfig)
	writer := newConfigWriter(func() string { return path })

	err := writer.ApplyRules([]RuleEntry{
		{APIKey: "sk-alpha", Models: []string{"gpt-5.2", "GPT-5.2", "  gpt-5.2  ", ""}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	got := string(raw)
	if occurrences := strings.Count(got, "- gpt-5.2"); occurrences != 1 {
		t.Fatalf("expected model deduped once, saw %d in:\n%s", occurrences, got)
	}
}

func TestApplyRulesAtomicSurvivesTempCleanup(t *testing.T) {
	t.Parallel()
	path := newTempConfig(t, sampleConfig)
	writer := newConfigWriter(func() string { return path })

	if errApply := writer.ApplyRules([]RuleEntry{{APIKey: "sk-alpha", Models: []string{"gpt-5.2"}}}); errApply != nil {
		t.Fatal(errApply)
	}
	entries, errRead := os.ReadDir(filepath.Dir(path))
	if errRead != nil {
		t.Fatal(errRead)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".model-limiter-") {
			t.Fatalf("temp file leaked: %s", entry.Name())
		}
	}
}
