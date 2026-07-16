package plugin

import (
	"os"
	"strings"
	"testing"
)

// TestApplyRulesOnMountPoint is a manual check for the Docker single-file
// bind mount scenario where os.Rename returns EBUSY. It only runs when
// EBUSY_TARGET points at a mounted config file.
func TestApplyRulesOnMountPoint(t *testing.T) {
	target := os.Getenv("EBUSY_TARGET")
	if target == "" {
		t.Skip("EBUSY_TARGET not set")
	}
	writer := newConfigWriter(func() string { return target })
	if errApply := writer.ApplyRules([]RuleEntry{{APIKey: "sk-ebusy-check", Models: []string{"gpt-*"}}}); errApply != nil {
		t.Fatalf("apply on mount point: %v", errApply)
	}
	data, errRead := os.ReadFile(target)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if !strings.Contains(string(data), "sk-ebusy-check") {
		t.Fatalf("rule not written:\n%s", data)
	}
}
