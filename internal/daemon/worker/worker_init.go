// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package worker

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/storage"
)

// localFSRecordingStorage implements storage.RecordingStorage for OSS.
// It writes BSR files to a local filesystem path.
type localFSRecordingStorage struct {
	root string
}

func (s *localFSRecordingStorage) NewSyncingFs(ctx interface{}, bucket interface{}, opts ...interface{}) (interface{}, error) {
	// OSS implementation: BSR storage uses bsr.NewLocalFS_sessionStorage directly.
	return nil, nil
}

func init() {
	// Override the factory vars to install OSS SSH recording.
	// Enterprise packages can override these before worker startup.
	recordingStorageFactory = ossRecordingStorageFactory
	recorderManagerFactory = ossRecorderManagerFactory
}

// ossRecordingStorageFactory creates a local filesystem recording storage.
func ossRecordingStorageFactory(ctx interface{}, path string, plgClients map[string]interface{}, enableLoopback bool) (storage.RecordingStorage, error) {
	if path == "" {
		return nil, nil
	}
	return &localFSRecordingStorage{root: path}, nil
}

// ossRecorderManagerFactory creates an SshRecordingManager for OSS.
// It wires up rate limiting, graceful shutdown, and orphaned-session recovery.
func ossRecorderManagerFactory(w *Worker) (recorderManager, error) {
	if w.conf.RawConfig.Worker.RecordingStoragePath == "" {
		return nil, nil
	}

	// Get the rate limit config from worker config.
	// May be nil, in which case NewSshRecordingManager disables rate limiting.
	rateLimitCfg := w.conf.RawConfig.Worker.SshRateLimit

	// Pass the worker's base context done channel as the shutdown signal.
	// This channel is closed when the worker begins shutdown, allowing the
	// recording manager to stop accepting new sessions and drain in-flight ones.
	shutdownCh := w.baseContext.Done()

	sshRm, err := ssh.NewSshRecordingManager(
		w.conf.RawConfig.Worker.RecordingStoragePath,
		shutdownCh,
		rateLimitCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH recording manager: %w", err)
	}

	// Scan for orphaned sessions from a previous worker crash.
	// This is called once on startup before the worker begins accepting connections.
	if w.conf.Logger != nil {
		orphanedCount, scanErr := ssh.ScanAndRecoverOrphanedSessions(
			context.Background(),
			w.conf.RawConfig.Worker.RecordingStoragePath,
			w.conf.Logger,
		)
		if scanErr != nil {
			// Log but don't fail startup — the worker can still function.
			w.conf.Logger.Error("failed to scan for orphaned SSH recording sessions",
				"error", scanErr,
				"recording_root", w.conf.RawConfig.Worker.RecordingStoragePath)
		} else if orphanedCount > 0 {
			w.conf.Logger.Info("recovered orphaned SSH recording sessions on startup",
				"orphaned_count", orphanedCount,
				"recording_root", w.conf.RawConfig.Worker.RecordingStoragePath)
		}
	}

	return newSshRecordingManagerWrapper(sshRm), nil
}

// sshRecordingManagerWrapper wraps SshRecordingManager to satisfy the empty
// recorderManager interface while preserving the underlying RecordingManager.
// This allows proxy handlers to unwrap to *ssh.SshRecordingManager.
type sshRecordingManagerWrapper struct {
	rm interface{ Unwrap() *ssh.SshRecordingManager }
}

// newSshRecordingManagerWrapper creates a wrapper that can unwrap to *ssh.SshRecordingManager.
func newSshRecordingManagerWrapper(rm *ssh.SshRecordingManager) *sshRecordingManagerWrapper {
	return &sshRecordingManagerWrapper{rm: rm}
}

// Unwrap returns the underlying *ssh.SshRecordingManager.
func (w *sshRecordingManagerWrapper) Unwrap() *ssh.SshRecordingManager {
	if w.rm != nil {
		return w.rm.Unwrap()
	}
	return nil
}