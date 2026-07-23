package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	adaptiveMigrateInput    string
	adaptiveMigrateOutput   string
	adaptiveMigrateRollback string
	adaptiveMigrateShadow   bool
	adaptiveMigrateForce    bool
)

var commandToolsAdaptiveMigrate = &cobra.Command{
	Use:   "adaptive-migrate",
	Short: "Migrate legacy Smart outbounds to AdaptivePool with an exact rollback file",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		count, dropped, err := migrateAdaptiveConfig(adaptiveMigrateInput, adaptiveMigrateOutput, adaptiveMigrateRollback, adaptiveMigrateShadow, adaptiveMigrateForce)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "migrated=%d shadow=%t rollback=written unmapped_fields=%v\n", count, adaptiveMigrateShadow, dropped)
	},
}

func init() {
	commandToolsAdaptiveMigrate.Flags().StringVarP(&adaptiveMigrateInput, "input", "i", "", "Source sing-box JSON configuration")
	commandToolsAdaptiveMigrate.Flags().StringVarP(&adaptiveMigrateOutput, "output", "o", "", "Migrated configuration output")
	commandToolsAdaptiveMigrate.Flags().StringVar(&adaptiveMigrateRollback, "rollback", "", "Exact rollback configuration output")
	commandToolsAdaptiveMigrate.Flags().BoolVar(&adaptiveMigrateShadow, "shadow", true, "Start migrated groups in observation-only shadow mode")
	commandToolsAdaptiveMigrate.Flags().BoolVar(&adaptiveMigrateForce, "force", false, "Replace output files")
	for _, name := range []string{"input", "output", "rollback"} {
		_ = commandToolsAdaptiveMigrate.MarkFlagRequired(name)
	}
	commandTools.AddCommand(commandToolsAdaptiveMigrate)
}

func migrateAdaptiveConfig(inputPath, outputPath, rollbackPath string, shadow, force bool) (int, []string, error) {
	if sameCleanPath(inputPath, outputPath) || sameCleanPath(inputPath, rollbackPath) || sameCleanPath(outputPath, rollbackPath) {
		return 0, nil, errors.New("adaptive migration input, output and rollback paths must be distinct")
	}
	original, err := readLimitedRegularFile(inputPath, 16*1024*1024, false)
	if err != nil {
		return 0, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(original))
	decoder.UseNumber()
	var root map[string]any
	if err = decoder.Decode(&root); err != nil {
		return 0, nil, errors.New("invalid source configuration")
	}
	if err = ensureJSONEOF(decoder); err != nil {
		return 0, nil, errors.New("invalid source configuration")
	}
	outbounds, loaded := root["outbounds"].([]any)
	if !loaded {
		return 0, nil, errors.New("source configuration has no outbound array")
	}
	unmappedSet := make(map[string]struct{})
	migrated := 0
	for index, rawOutbound := range outbounds {
		outbound, ok := rawOutbound.(map[string]any)
		if !ok || outbound["type"] != "smart" {
			continue
		}
		outbounds[index] = migrateSmartOutbound(outbound, shadow, unmappedSet)
		migrated++
	}
	if migrated == 0 {
		return 0, nil, errors.New("source configuration contains no legacy smart outbound")
	}
	root["outbounds"] = outbounds
	migratedContent, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return 0, nil, err
	}
	migratedContent = append(migratedContent, '\n')
	// Write rollback first: a migrated file is never published without an
	// exact byte-for-byte recovery artifact.
	if err = writeExclusiveFile(rollbackPath, original, 0o600, force); err != nil {
		return 0, nil, err
	}
	if err = writeExclusiveFile(outputPath, migratedContent, 0o600, force); err != nil {
		return 0, nil, err
	}
	unmapped := make([]string, 0, len(unmappedSet))
	for field := range unmappedSet {
		unmapped = append(unmapped, field)
	}
	sort.Strings(unmapped)
	return migrated, unmapped, nil
}

func migrateSmartOutbound(source map[string]any, shadow bool, unmapped map[string]struct{}) map[string]any {
	result := make(map[string]any)
	result["type"] = "adaptive_pool"
	result["shadow"] = shadow
	for _, field := range []string{"tag", "outbounds", "providers", "exclude", "include", "use_all_providers"} {
		copyJSONField(result, source, field, field)
	}
	probe := make(map[string]any)
	copyJSONField(probe, source, "url", "url")
	copyJSONField(probe, source, "probe_interval", "coverage_interval")
	copyJSONField(probe, source, "probe_timeout", "timeout")
	if len(probe) > 0 {
		result["probe"] = probe
	}
	policy := make(map[string]any)
	policy["default"] = "adaptive"
	copyJSONField(policy, source, "max_attempts", "max_attempts")
	copyJSONField(policy, source, "attempt_timeout", "attempt_timeout")
	copyJSONField(policy, source, "site_stickiness", "adaptive_lease_ttl")
	result["policy"] = policy
	state := make(map[string]any)
	copyJSONField(state, source, "history_path", "path")
	copyJSONField(state, source, "history_retention", "retention")
	copyJSONField(state, source, "max_history_entries", "max_entries")
	if len(state) > 0 {
		result["state"] = state
	}
	mapped := map[string]struct{}{
		"type": {}, "tag": {}, "outbounds": {}, "providers": {}, "exclude": {}, "include": {}, "use_all_providers": {},
		"url": {}, "probe_interval": {}, "probe_timeout": {}, "max_attempts": {}, "attempt_timeout": {}, "site_stickiness": {},
		"history_path": {}, "history_retention": {}, "max_history_entries": {},
	}
	for field := range source {
		if _, ok := mapped[field]; !ok {
			unmapped[field] = struct{}{}
		}
	}
	return result
}

func copyJSONField(destination, source map[string]any, sourceName, destinationName string) {
	if value, loaded := source[sourceName]; loaded {
		destination[destinationName] = value
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("trailing JSON")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func sameCleanPath(first, second string) bool {
	firstAbsolute, firstErr := filepath.Abs(first)
	secondAbsolute, secondErr := filepath.Abs(second)
	return firstErr == nil && secondErr == nil && filepath.Clean(firstAbsolute) == filepath.Clean(secondAbsolute)
}
