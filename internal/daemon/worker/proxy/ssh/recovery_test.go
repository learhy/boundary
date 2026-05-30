// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// mockLogger is a simple hclog.Logger implementation for tests.
type mockLogger struct {
	infoCalls []string
	errCalls  []string
}

func (l *mockLogger) Named(_ string) hclog.Logger                    { return l }
func (l *mockLogger) With(_ ...interface{}) hclog.Logger             { return l }
func (l *mockLogger) Debug(_ string, _ ...interface{})               {}
func (l *mockLogger) Info(_ string, args ...interface{}) {
	l.infoCalls = append(l.infoCalls, argsToString(args))
}
func (l *mockLogger) Warn(_ string, _ ...interface{})                {}
func (l *mockLogger) Error(_ string, args ...interface{}) {
	l.errCalls = append(l.errCalls, argsToString(args))
}
func (l *mockLogger) IsError() bool                                  { return true }
func (l *mockLogger) IsWarn() bool                                   { return true }
func (l *mockLogger) IsInfo() bool                                   { return true }
func (l *mockLogger) IsDebug() bool                                  { return false }
func (l *mockLogger) ImpliedArgs() []interface{}                     { return nil }
func (l *mockLogger) Reset(_ ...interface{})                         {}
func (l *mockLogger) SetLevel(_ hclog.Level)                         {}
func (l *mockLogger) GetLevel() hclog.Level                          { return hclog.NoLevel }
func (l *mockLogger) Log(_ hclog.Level, _ string, _ ...interface{})  {}
func (l *mockLogger) Slurp(_ string, _ ...interface{}) hclog.Logger  { return l }

func argsToString(args []interface{}) string {
	s := ""
	for _, a := range args {
		if s != "" {
			s += ", "
		}
		s += formatArg(a)
	}
	return s
}

func formatArg(a interface{}) string {
	switch v := a.(type) {
	case string:
		return v
	case int:
		return string(rune(v))
	default:
		return ""
	}
}

func TestScanAndRecoverOrphanedSessions_EmptyRoot(t *testing.T) {
	tmpDir := t.TempDir()

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 orphaned sessions in empty dir, got %d", count)
	}
}

func TestScanAndRecoverOrphanedSessions_NonExistentRoot(t *testing.T) {
	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), "/nonexistent/path/to/recordings", logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error for non-existent path: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 for non-existent root, got %d", count)
	}
}

func TestScanAndRecoverOrphanedSessions_NoOrphaned(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a complete session (has session_complete marker)
	sessionDir := filepath.Join(tmpDir, "sr_test123")
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, sessionCompleteMarker), []byte("done"), 0644); err != nil {
		t.Fatal(err)
	}

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 orphaned sessions (all complete), got %d", count)
	}
}

func TestScanAndRecoverOrphanedSessions_SingleOrphaned(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an orphaned session (no session_complete marker)
	orphanedDir := filepath.Join(tmpDir, "sr_orphaned1")
	if err := os.MkdirAll(orphanedDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Write some data to simulate incomplete session
	if err := os.WriteFile(filepath.Join(orphanedDir, "session.data"), []byte("incomplete data"), 0644); err != nil {
		t.Fatal(err)
	}

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 orphaned session, got %d", count)
	}

	// Verify the session was moved to quarantine
	quarantinePath := filepath.Join(tmpDir, quarantineDir)
	entries, err := os.ReadDir(quarantinePath)
	if err != nil {
		t.Errorf("Quarantine directory not created: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > len("sr_orphaned1-") && e.Name()[:len("sr_orphaned1")] == "sr_orphaned1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Orphaned session not found in quarantine: %v", entries)
	}

	// Verify the original dir is gone
	if _, err := os.Stat(orphanedDir); !os.IsNotExist(err) {
		t.Errorf("Original orphaned session dir still exists: %v", err)
	}
}

func TestScanAndRecoverOrphanedSessions_Mixed(t *testing.T) {
	tmpDir := t.TempDir()

	// Create healthy sessions (with session_complete marker)
	for i := 0; i < 2; i++ {
		sessDir := filepath.Join(tmpDir, "sr_healthy"+string(rune('0'+i)))
		if err := os.MkdirAll(sessDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sessDir, sessionCompleteMarker), []byte("done"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create orphaned sessions (no session_complete marker)
	for i := 0; i < 3; i++ {
		sessDir := filepath.Join(tmpDir, "sr_orphan"+string(rune('0'+i)))
		if err := os.MkdirAll(sessDir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 3 {
		t.Errorf("Expected 3 orphaned sessions, got %d", count)
	}

	// Verify healthy sessions are still in place
	for i := 0; i < 2; i++ {
		sessDir := filepath.Join(tmpDir, "sr_healthy"+string(rune('0'+i)))
		if _, err := os.Stat(sessDir); os.IsNotExist(err) {
			t.Errorf("Healthy session sr_healthy%c was incorrectly removed", rune('0'+i))
		}
	}
}

func TestScanAndRecoverOrphanedSessions_NonSessionDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create non-session directories
	if err := os.MkdirAll(filepath.Join(tmpDir, "some_other_dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 orphaned sessions, got %d", count)
	}
}

func TestQuarantineSessionDir_NonExistent(t *testing.T) {
	err := quarantineSessionDir(t.TempDir(), "sr_nonexistent123456789")
	if err == nil {
		t.Error("Expected error for non-existent session directory")
	}
}

func TestQuarantineSessionDir_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a session dir
	sessDir := filepath.Join(tmpDir, "sr_quarantine_test")
	if err := os.MkdirAll(sessDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessDir, "data"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	err := quarantineSessionDir(tmpDir, "sr_quarantine_test")
	if err != nil {
		t.Errorf("quarantineSessionDir failed: %v", err)
	}

	// Verify quarantine dir was created
	quarantinePath := filepath.Join(tmpDir, quarantineDir)
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		t.Error("Quarantine directory not created")
	}

	// Verify original dir is gone
	if _, err := os.Stat(sessDir); !os.IsNotExist(err) {
		t.Error("Original session directory still exists after quarantine")
	}
}

func TestQuarantineSessionDir_EmptyRoot(t *testing.T) {
	err := quarantineSessionDir("", "sr_test")
	if err == nil {
		t.Error("Expected error for empty recording root")
	}
}

func TestQuarantineSessionDir_EmptySessionId(t *testing.T) {
	err := quarantineSessionDir("/tmp", "")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestIsSessionComplete(t *testing.T) {
	tmpDir := t.TempDir()

	// No session_complete marker
	sessionDir := filepath.Join(tmpDir, "sr_incomplete")
	os.MkdirAll(sessionDir, 0755)
	if IsSessionComplete(sessionDir) {
		t.Error("Expected false for session without complete marker")
	}

	// With session_complete marker
	markerPath := filepath.Join(sessionDir, sessionCompleteMarker)
	os.WriteFile(markerPath, []byte("done"), 0644)
	if !IsSessionComplete(sessionDir) {
		t.Error("Expected true for session with complete marker")
	}
}

func TestIsSessionComplete_NonExistentDir(t *testing.T) {
	if IsSessionComplete("/nonexistent/session") {
		t.Error("Expected false for non-existent directory")
	}
}

func TestSessionPathForId(t *testing.T) {
	path := SessionPathForId("/recordings", "sr_testid")
	expected := filepath.Join("/recordings", "sr_testid")
	if path != expected {
		t.Errorf("SessionPathForId = %q, want %q", path, expected)
	}
}

func TestScanAndRecoverOrphanedSessions_TwoOrphanedSameName(t *testing.T) {
	// This tests that quarantine names are unique via timestamp
	tmpDir := t.TempDir()

	// Create two orphaned sessions
	for i := 0; i < 2; i++ {
		sessDir := filepath.Join(tmpDir, "sr_duplicate")
		if i == 0 {
			os.MkdirAll(sessDir, 0755)
		}
	}

	logger := &mockLogger{}
	count, err := ScanAndRecoverOrphanedSessions(context.Background(), tmpDir, logger)
	if err != nil {
		t.Errorf("ScanAndRecoverOrphanedSessions returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 orphaned session, got %d", count)
	}
}