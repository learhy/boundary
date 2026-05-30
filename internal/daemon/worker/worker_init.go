// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/storage"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// ossInit sets the OSS recording factories at package initialization time.
// This runs before worker.New() is called, so the factories are in place
// when the worker is constructed.
//
// Import the SSH proxy package to register the SSH handler via its init().
// Import the storage package for NewOssRecordingStorage.
func init() {
	recordingStorageFactory = ossRecordingStorageFactory
	recorderManagerFactory = ossRecorderManagerFactory
}

// ossRecordingStorageFactory creates a local-filesystem-backed RecordingStorage.
// OSS does not support storage plugins — any plugin clients passed are ignored.
func ossRecordingStorageFactory(
	_ context.Context,
	path string,
	_ map[string]plgpb.StoragePluginServiceClient,
	_ bool,
) (storage.RecordingStorage, error) {
	if path == "" {
		return nil, errors.New("worker.recording_storage_path is not configured")
	}
	return storage.NewOssRecordingStorage(context.Background(), path)
}

// ossRecorderManagerFactory creates the SshRecordingManager for the worker.
func ossRecorderManagerFactory(w *Worker) (recorderManager, error) {
	if w.RecordingStorage == nil {
		return nil, errors.New("worker has no recording storage configured")
	}
	if w.recorderManager != nil {
		return w.recorderManager, nil // already initialized
	}
	storagePath := w.conf.RawConfig.Worker.RecordingStoragePath
	wrapper := w.conf.WorkerAuthStorageKms

	// Extract rate limit config from worker configuration.
	// If nil, rate limiting is disabled in the manager.
	var sshRateLimit *ssh.SshRateLimitConfig
	if rl := w.conf.RawConfig.Worker.SshRateLimit; rl != nil {
		sshRateLimit = &ssh.SshRateLimitConfig{
			MaxConcurrentSessions: rl.MaxConcurrentSessions,
			MaxPerTarget:          rl.MaxPerTarget,
		}
	}

	mgr := ssh.NewSshRecordingManager(storagePath, wrapper, w.RecordingStorage, sshRateLimit, w.logger.Named("ssh-recording"))

	// Run recovery scan synchronously before returning the manager.
	// This ensures orphaned session directories are quarantined before
	// new sessions can be created with the same session IDs.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if n, err := ssh.ScanAndRecoverOrphanedSessions(ctx, storagePath, w.logger.Named("ssh-recovery")); err != nil {
		w.logger.Warn("orphaned session scan failed, continuing", "error", err)
	} else if n > 0 {
		w.logger.Info("orphaned session scan complete", "orphaned_count", n)
	}

	return mgr, nil
}