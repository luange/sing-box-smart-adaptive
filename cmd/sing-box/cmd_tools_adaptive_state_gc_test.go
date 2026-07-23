package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGarbageCollectAdaptiveStateHonorsActiveAndDryRun(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	old := now.Add(-60 * 24 * time.Hour)
	for _, name := range []string{"adaptive-state-active.json", "adaptive-state-active.key", "adaptive-state-orphan.json", "adaptive-state-orphan.key", "unrelated.key"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	matched, removed, err := garbageCollectAdaptiveState(directory, []string{"adaptive-state-active"}, 30*24*time.Hour, false, now)
	if err != nil || matched != 2 || removed != 0 {
		t.Fatalf("dry-run mismatch: matched=%d removed=%d err=%v", matched, removed, err)
	}
	matched, removed, err = garbageCollectAdaptiveState(directory, []string{"adaptive-state-active"}, 30*24*time.Hour, true, now)
	if err != nil || matched != 2 || removed != 2 {
		t.Fatalf("apply mismatch: matched=%d removed=%d err=%v", matched, removed, err)
	}
	for _, name := range []string{"adaptive-state-active.json", "adaptive-state-active.key", "unrelated.key"} {
		if _, err = os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("protected file removed: %s", name)
		}
	}
}
