package plugin

import "testing"

func TestParseConfigDefaultsToNonExclusiveEmptyRules(t *testing.T) {
	t.Parallel()

	cfg, errParse := ParseConfig([]byte("enabled: true\npriority: 0\n"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	if cfg.Exclusive {
		t.Fatal("exclusive should default to false")
	}
	if len(cfg.Rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(cfg.Rules))
	}
}

func TestParseConfigReadsKeysAndModels(t *testing.T) {
	t.Parallel()

	raw := []byte(`
enabled: true
exclusive: true
keys:
  - api-key: sk-alpha
    models:
      - gpt-5.2
      - "claude-*"
  - api-key: sk-beta
`)
	cfg, errParse := ParseConfig(raw)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !cfg.Exclusive {
		t.Fatal("exclusive should be true")
	}
	rule, ok := cfg.RuleForKey("sk-alpha")
	if !ok {
		t.Fatal("sk-alpha rule missing")
	}
	if len(rule.Patterns) != 2 {
		t.Fatalf("patterns = %v", rule.Patterns)
	}
	openRule, ok := cfg.RuleForKey("sk-beta")
	if !ok {
		t.Fatal("sk-beta rule missing")
	}
	if !openRule.AllowsModel("anything") {
		t.Fatal("empty models list should allow every model")
	}
}

func TestParseConfigRejectsDuplicateAndEmptyKeys(t *testing.T) {
	t.Parallel()

	if _, errParse := ParseConfig([]byte("keys:\n  - api-key: ''\n")); errParse == nil {
		t.Fatal("empty api-key should fail")
	}
	if _, errParse := ParseConfig([]byte("keys:\n  - api-key: a\n  - api-key: a\n")); errParse == nil {
		t.Fatal("duplicate api-key should fail")
	}
}

func TestRuleAllowsModelWildcardAndCase(t *testing.T) {
	t.Parallel()

	rule := Rule{Patterns: []string{"gpt-5.2", "claude-*", "*-flash"}}
	tests := []struct {
		model string
		want  bool
	}{
		{"gpt-5.2", true},
		{"GPT-5.2", true},
		{"gpt-5.2-mini", false},
		{"claude-sonnet-4-5", true},
		{"gemini-2.5-flash", true},
		{"gemini-2.5-pro", false},
	}
	for _, tt := range tests {
		if got := rule.AllowsModel(tt.model); got != tt.want {
			t.Fatalf("AllowsModel(%q) = %v, want %v", tt.model, got, tt.want)
		}
	}
}

func TestMatchWildcardMiddleSegments(t *testing.T) {
	t.Parallel()

	if !matchWildcard("gemini-*-pro*", "gemini-2.5-pro-preview") {
		t.Fatal("middle wildcard should match")
	}
	if matchWildcard("gemini-*-pro", "gemini-2.5-flash") {
		t.Fatal("non-matching tail should fail")
	}
}

func TestMaskKey(t *testing.T) {
	t.Parallel()

	if got := MaskKey("short"); got != "****" {
		t.Fatalf("MaskKey(short) = %q", got)
	}
	if got := MaskKey("sk-abcdefghijklmn"); got != "sk-a****klmn" {
		t.Fatalf("MaskKey(long) = %q", got)
	}
}
