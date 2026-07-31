package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateAdaptiveConfigCreatesExactRollback(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "config.json")
	output := filepath.Join(directory, "adaptive.json")
	rollback := filepath.Join(directory, "rollback.json")
	original := []byte(`{"outbounds":[{"type":"smart","tag":"auto","providers":["private-provider"],"url":"https://example.test/204?token=secret","probe_interval":"10m","site_stickiness":"15m","reach_tests":[{"url":"https://secret.example"}]}]}`)
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	count, unmapped, err := migrateAdaptiveConfig(input, output, rollback, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(unmapped) != 1 || unmapped[0] != "reach_tests" {
		t.Fatalf("unexpected report: count=%d unmapped=%v", count, unmapped)
	}
	restored, err := os.ReadFile(rollback)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatal("rollback is not byte-exact")
	}
	migrated, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(migrated, &root); err != nil {
		t.Fatal(err)
	}
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["type"] != "adaptive_pool" || outbound["shadow"] != true {
		t.Fatalf("unexpected migrated outbound: %#v", outbound)
	}
	if _, present := outbound["reach_tests"]; present {
		t.Fatal("legacy reach test leaked into adaptive config")
	}
}

func TestMigrateAdaptiveConfigRejectsSamePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, _, err := migrateAdaptiveConfig(path, path, path+".rollback", true, false); err == nil {
		t.Fatal("expected path collision rejection")
	}
}
