// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	// sessionCompleteMarker is the filename BSR writes inside a completed session.
	sessionCompleteMarker = "session_complete"
	// quarantineDir is the subdirectory under recordingRoot where orphaned sessions are moved.
	quarantineDir = "quarantine"
	// orphanedSessionPrefix is the prefix BSR uses for session directory names.
	orphanedSessionPrefix = "sr_"
)

// ScanAndRecoverOrphanedSessions scans the recording storage root for session
// directories that were not cleanly shut down (no session_complete marker).
// Each orphaned session is moved to the quarantine subdirectory and its count
// is logged. This function is idempotent and safe to call multiple times.
// Returns the number of orphaned sessions recovered.
func ScanAndRecoverOrphanedSessions(ctx context.Context, recordingRoot string, logger hclog.Logger) (int, error) {
	if recordingRoot == "" {
		return 0, nil
	}

	entries, err := os.ReadDir(recordingRoot)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("recording root does not exist, skipping recovery scan",
				"recording_root", recordingRoot)
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read recording root: %w", err)
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), orphanedSessionPrefix) {
			continue
		}

		sessionId := entry.Name()
		sessionPath := filepath.Join(recordingRoot, sessionId)

		// Check for session_complete marker
		completeMarker := filepath.Join(sessionPath, sessionCompleteMarker)
		if _, err := os.Stat(completeMarker); err == nil {
			// Session completed cleanly — no action needed
			continue
		}

		// Orphaned session found — quarantine it
		if err := quarantineSessionDir(recordingRoot, sessionId); err != nil {
			logger.Error("failed to quarantine orphaned session",
				"session_id", sessionId,
				"session_path", sessionPath,
				"error", err)
			continue
		}

		logger.Info("recovered orphaned SSH recording session",
			"session_id", sessionId,
			"reason", "session_complete marker not found")
		count++
	}

	if count > 0 {
		logger.Info("orphaned session recovery complete",
			"orphaned_count", count,
			"recording_root", recordingRoot)
	}

	return count, nil
}

// quarantineSessionDir moves a session directory to the quarantine subdirectory
// under recordingRoot. The quarantine directory path is:
//   <recordingRoot>/quarantine/<sessionId>-<unix_timestamp>
func quarantineSessionDir(recordingRoot, sessionId string) error {
	if recordingRoot == "" || sessionId == "" {
		return fmt.Errorf("recordingRoot and sessionId are required")
	}

	// Create quarantine directory
	quarantinePath := filepath.Join(recordingRoot, quarantineDir)
	if err := os.MkdirAll(quarantinePath, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// Destination: quarantine/<sessionId>-<timestamp>
	timestamp := time.Now().Unix()
	quarantineName := fmt.Sprintf("%s-%d", sessionId, timestamp)
	destPath := filepath.Join(quarantinePath, quarantineName)

	// Source session directory
	srcPath := filepath.Join(recordingRoot, sessionId)

	// Check source exists
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("session directory not found: %w", err)
	}

	// Move the directory
	if err := os.Rename(srcPath, destPath); err != nil {
		// If Rename fails across filesystems (EXDEV), fall back to copy+delete
		if err2 := moveDirCrossFs(srcPath, destPath); err2 != nil {
			return fmt.Errorf("move failed (Rename: %v, cross-fs: %v)", err, err2)
		}
	}

	return nil
}

// moveDirCrossFs copies a directory tree to a destination on a different filesystem,
// then removes the source. Used as a fallback when os.Rename fails with EXDEV.
func moveDirCrossFs(src, dst string) error {
	return filepath.Walk(src, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, srcPath)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		return copyFile(srcPath, dstPath, info.Mode())
	})
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

// SessionPathForId returns the expected path for a session directory given its ID.
func SessionPathForId(recordingRoot, sessionId string) string {
	return path.Join(recordingRoot, sessionId)
}

// IsSessionComplete returns true if the given session directory contains a
// session_complete marker, indicating the session was cleanly shut down.
func IsSessionComplete(sessionPath string) bool {
	completeMarker := filepath.Join(sessionPath, sessionCompleteMarker)
	_, err := os.Stat(completeMarker)
	return err == nil
}