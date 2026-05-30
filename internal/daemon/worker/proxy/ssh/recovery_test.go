// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// setupRecoveryTestDir creates a temporary directory with the given session
// directories and optional manifest contents. Returns the temp dir path.
// Each entry in sessions is a pair: (directory_suffix, manifest_json_or_empty).
// "s_" prefix is added automatically. Empty manifest means no session.json.
func setupRecoveryTestDir(t *testing.T, sessions map[string]string) string {
	t.Helper()
	td, err := os.MkdirTemp("", "bsr-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(td) })

	for suffix, manifestContent := range sessions {
		dirName := "s_" + suffix
		dirPath := filepath.Join(td, dirName)
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			t.Fatalf("failed to create session dir %s: %v", dirName, err)
		}
		if manifestContent != "" {
			if err := os.WriteFile(filepath.Join(dirPath, "session.json"), []byte(manifestContent), 0600); err != nil {
				t.Fatalf("failed to write session.json: %v", err)
			}
		}
	}
	return td
}

// countOrphanedDirs returns the number of quarantined directories (containing "-incomplete-" in the name).
func countOrphanedDirs(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() && strings.Contains(e.Name(), "-incomplete-") {
			count++
		}
	}
	return count
}

func TestRecovery_CleanSessionSkipped(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"clean1": `{"id":"s_clean1","status":"closed"}`,
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 orphaned sessions for clean dir, got %d", n)
	}

	if countOrphanedDirs(t, td) != 0 {
		t.Fatal("expected 0 quarantined directories")
	}
}

func TestRecovery_NoSessionJson(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"orphaned1": "", // no session.json
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 orphaned session, got %d", n)
	}

	if countOrphanedDirs(t, td) != 1 {
		t.Fatal("expected 1 quarantined directory")
	}

	// Verify the original directory was renamed (no longer exists).
	if _, err := os.Stat(filepath.Join(td, "s_orphaned1")); !os.IsNotExist(err) {
		t.Fatal("original session directory should no longer exist")
	}
}

func TestRecovery_ActiveStatus(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"active1": `{"id":"s_active1","status":"active"}`,
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 orphaned session, got %d", n)
	}

	if countOrphanedDirs(t, td) != 1 {
		t.Fatal("expected 1 quarantined directory")
	}

	// Verify the recovery manifest was written with recovered_incomplete status.
	// Find the quarantined directory.
	entries, _ := os.ReadDir(td)
	for _, e := range entries {
		if e.IsDir() && strings.Contains(e.Name(), "incomplete") {
			data, err := os.ReadFile(filepath.Join(td, e.Name(), "session.json"))
			if err != nil {
				t.Fatalf("failed to read recovery manifest: %v", err)
			}
			var manifest sessionManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatalf("failed to parse recovery manifest: %v", err)
			}
			if manifest.Status != "recovered_incomplete" {
				t.Fatalf("expected status 'recovered_incomplete', got '%s'", manifest.Status)
			}
			if manifest.Id != "s_active1" {
				t.Fatalf("expected id 's_active1', got '%s'", manifest.Id)
			}
		}
	}
}

func TestRecovery_MultipleOrphaned(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"clean1":  `{"id":"s_clean1","status":"closed"}`,
		"orphan1": "", // no session.json
		"orphan2": `{"id":"s_orphan2","status":"active"}`,
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 orphaned sessions, got %d", n)
	}

	if countOrphanedDirs(t, td) != 2 {
		t.Fatal("expected 2 quarantined directories")
	}

	// Clean session should still exist.
	if _, err := os.Stat(filepath.Join(td, "s_clean1")); os.IsNotExist(err) {
		t.Fatal("clean session directory should still exist")
	}

	// Original orphan directories should be gone.
	if _, err := os.Stat(filepath.Join(td, "s_orphan1")); !os.IsNotExist(err) {
		t.Fatal("orphan session directory should no longer exist in original location")
	}
	if _, err := os.Stat(filepath.Join(td, "s_orphan2")); !os.IsNotExist(err) {
		t.Fatal("orphan session directory should no longer exist in original location")
	}
}

func TestRecovery_CorruptedManifest(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"corrupt1": `this is not json`,
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 orphaned session, got %d", n)
	}

	if countOrphanedDirs(t, td) != 1 {
		t.Fatal("expected 1 quarantined directory")
	}
}

func TestRecovery_InitializingStatus(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	sessions := map[string]string{
		"init1": `{"id":"s_init1","status":"initializing"}`,
	}
	td := setupRecoveryTestDir(t, sessions)

	n, err := ScanAndRecoverOrphanedSessions(ctx, td, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 orphaned session (initializing), got %d", n)
	}

	if countOrphanedDirs(t, td) != 1 {
		t.Fatal("expected 1 quarantined directory")
	}
}

func TestRecovery_EmptyStoragePath(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	n, err := ScanAndRecoverOrphanedSessions(ctx, "", logger)
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 for empty path, got %d", n)
	}
}

func TestRecovery_NonExistentDir(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	n, err := ScanAndRecoverOrphanedSessions(ctx, "/tmp/nonexistent-bsr-dir-12345", logger)
	if err != nil {
		t.Fatalf("unexpected error for non-existent dir: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 for non-existent dir, got %d", n)
	}
}
