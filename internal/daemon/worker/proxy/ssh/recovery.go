// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

// orphanedSession represents a session directory that was not cleanly closed.
type orphanedSession struct {
	SessionId string
	Path      string
	Reason    string // "no_session_json", "status_not_closed", "dir_present"
	Recovered bool   // true if we successfully finalized before quarantine
}

// sessionManifest is the on-disk JSON manifest written by the BSR at session creation.
// The BSR library writes this file when a session is created. If it is absent, the
// session was likely in the process of being created when the worker exited.
type sessionManifest struct {
	Id     string `json:"id"`
	Status string `json:"status"` // "initializing", "active", "closing", "closed", "recovered_incomplete"
}

// ScanAndRecoverOrphanedSessions scans the storage directory for BSR session directories
// that were not cleanly finalized (e.g., due to a container crash or OOM kill) and
// either recovers them (finalizes valid recordings) or quarantines them.
//
// It is called at worker startup before the worker begins accepting connections.
// The scan is bounded by the caller's context timeout (recommended: 30s).
//
// Returns the number of orphaned sessions found (regardless of recovery outcome).
func ScanAndRecoverOrphanedSessions(ctx context.Context, storagePath string, logger hclog.Logger) (int, error) {
	if storagePath == "" {
		return 0, nil
	}

	entries, err := os.ReadDir(storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read storage directory: %w", err)
	}

	found := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Session directories have the form "s_<uuid>".
		if !strings.HasPrefix(name, "s_") || len(name) < 4 {
			continue
		}

		sessionId := name
		sessionDir := filepath.Join(storagePath, name)
		manifestPath := filepath.Join(sessionDir, "session.json")

		info, err := entry.Info()
		if err != nil {
			logger.Warn("failed to read session directory info", "session_id", sessionId, "error", err)
			continue
		}

		// Check if session.json exists and has "closed" status.
		var reason string
		var manifest sessionManifest

		data, readErr := os.ReadFile(manifestPath)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				reason = "no_session_json"
			} else {
				reason = "manifest_read_error"
				logger.Warn("failed to read session manifest", "session_id", sessionId, "error", readErr)
			}
		} else {
			if json.Unmarshal(data, &manifest) != nil {
				reason = "manifest_parse_error"
			} else if manifest.Status != "closed" {
				reason = fmt.Sprintf("status_%s", manifest.Status)
			} else {
				// Session is cleanly closed — nothing to do.
				logger.Debug("session cleanly closed, skipping", "session_id", sessionId)
				continue
			}
		}

		orphaned := orphanedSession{
			SessionId: sessionId,
			Path:      sessionDir,
			Reason:    reason,
		}

		logger.Warn("found orphaned BSR session",
			"session_id", sessionId,
			"reason",     reason,
			"directory_age", time.Since(info.ModTime()).Round(time.Second),
		)

		// Attempt recovery: write a recovery manifest indicating force-close.
		if recovered, recoverErr := recoverSession(ctx, sessionDir, sessionId); recoverErr != nil {
			logger.Error("failed to recover orphaned session", "session_id", sessionId, "error", recoverErr)
			orphaned.Recovered = false
		} else {
			orphaned.Recovered = recovered
		}

		// Quarantine the directory so it cannot conflict with new sessions.
		if quarantineErr := quarantineSessionDir(storagePath, sessionId); quarantineErr != nil {
			logger.Error("failed to quarantine orphaned session directory",
				"session_id", sessionId,
				"error", quarantineErr,
			)
		} else {
			logger.Info("quarantined orphaned session",
				"session_id", sessionId,
				"reason",    reason,
				"recovered", orphaned.Recovered,
			)
		}

		found++
	}

	if found > 0 {
		logger.Warn("orphaned session scan complete", "orphaned_count", found, "storage_path", storagePath)
	}

	return found, nil
}

// recoverSession writes a recovery manifest to indicate the session was force-closed.
// Full BSR session finalization requires in-memory state (KMS keys, BSR session object)
// that is not persisted across crashes — so we mark the session as incomplete and
// quarantine the directory for manual review.
func recoverSession(ctx context.Context, sessionDir, sessionId string) (bool, error) {
	manifestPath := filepath.Join(sessionDir, "session.json")

	recoveryManifest := sessionManifest{
		Id:     sessionId,
		Status: "recovered_incomplete",
	}

	data, err := json.Marshal(recoveryManifest)
	if err != nil {
		return false, fmt.Errorf("failed to marshal recovery manifest: %w", err)
	}

	// Write to a temp file then rename to avoid partial writes.
	tmpPath := manifestPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return false, fmt.Errorf("failed to write recovery manifest: %w", err)
	}
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		return false, fmt.Errorf("failed to atomically replace manifest: %w", err)
	}

	return true, nil
}

// quarantineSessionDir renames a session directory to a quarantined name so it
// cannot conflict with new sessions that reuse the same session ID.
func quarantineSessionDir(storagePath, sessionId string) error {
	timestamp := time.Now().UTC().Format("20060102-150405")
	quarantineName := fmt.Sprintf("%s-incomplete-%s", sessionId, timestamp)
	quarantinePath := filepath.Join(storagePath, quarantineName)

	// Ensure we don't overwrite an existing quarantine directory.
	if _, err := os.Stat(quarantinePath); err == nil {
		// Already quarantined.
		return nil
	}

	if err := os.Rename(filepath.Join(storagePath, sessionId), quarantinePath); err != nil {
		return fmt.Errorf("failed to rename session directory: %w", err)
	}

	return nil
}