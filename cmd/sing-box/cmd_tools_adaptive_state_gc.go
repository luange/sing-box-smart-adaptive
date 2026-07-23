package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	adaptiveStateGCDirectory string
	adaptiveStateGCActive    []string
	adaptiveStateGCRetention time.Duration
	adaptiveStateGCApply     bool
)

var commandToolsAdaptiveStateGC = &cobra.Command{
	Use:   "adaptive-state-gc",
	Short: "Garbage-collect retired AdaptivePool state/key pairs",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		matched, removed, err := garbageCollectAdaptiveState(adaptiveStateGCDirectory, adaptiveStateGCActive, adaptiveStateGCRetention, adaptiveStateGCApply, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "matched=%d removed=%d apply=%t\n", matched, removed, adaptiveStateGCApply)
	},
}

func init() {
	commandToolsAdaptiveStateGC.Flags().StringVar(&adaptiveStateGCDirectory, "directory", ".", "State directory")
	commandToolsAdaptiveStateGC.Flags().StringSliceVar(&adaptiveStateGCActive, "active", nil, "Active state stem or path (repeatable/comma-separated)")
	commandToolsAdaptiveStateGC.Flags().DurationVar(&adaptiveStateGCRetention, "retention", 30*24*time.Hour, "Minimum orphan age")
	commandToolsAdaptiveStateGC.Flags().BoolVar(&adaptiveStateGCApply, "apply", false, "Delete matched files (default is dry-run)")
	commandTools.AddCommand(commandToolsAdaptiveStateGC)
}

func garbageCollectAdaptiveState(directory string, active []string, retention time.Duration, apply bool, now time.Time) (int, int, error) {
	if retention < time.Hour {
		return 0, 0, errors.New("adaptive state GC retention must be at least one hour")
	}
	directory = filepath.Clean(directory)
	activeStems := make(map[string]struct{}, len(active))
	for _, value := range active {
		base := filepath.Base(filepath.Clean(value))
		base = strings.TrimSuffix(strings.TrimSuffix(base, ".json"), ".key")
		if !strings.HasPrefix(base, "adaptive-state-") {
			return 0, 0, errors.New("active state name is outside the adaptive-state namespace")
		}
		activeStems[base] = struct{}{}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, 0, err
	}
	type stateGroup struct {
		files  []string
		newest time.Time
	}
	groups := make(map[string]*stateGroup)
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasPrefix(name, "adaptive-state-") || !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".key") {
			continue
		}
		stem := strings.TrimSuffix(strings.TrimSuffix(name, ".json"), ".key")
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			continue
		}
		group := groups[stem]
		if group == nil {
			group = new(stateGroup)
			groups[stem] = group
		}
		group.files = append(group.files, name)
		if info.ModTime().After(group.newest) {
			group.newest = info.ModTime()
		}
	}
	matched, removed := 0, 0
	for stem, group := range groups {
		if _, active := activeStems[stem]; active || now.Sub(group.newest) < retention {
			continue
		}
		matched += len(group.files)
		if !apply {
			continue
		}
		for _, name := range group.files {
			if err = os.Remove(filepath.Join(directory, name)); err != nil {
				return matched, removed, err
			}
			removed++
		}
	}
	return matched, removed, nil
}
