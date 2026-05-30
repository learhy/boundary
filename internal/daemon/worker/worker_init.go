// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package worker

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh"
	"github.com/hashicorp/boundary/internal/storage"
)

// localFSRecordingStorage implements storage.RecordingStorage for OSS.
// It writes BSR files to a local filesystem path.
type localFSRecordingStorage struct {
	root string
}

func (s *localFSRecordingStorage) NewSyncingFS(ctx interface{}, bucket interface{}, opts ...interface{}) (interface{}, error) {
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
func ossRecorderManagerFactory(w *Worker) (recorderManager, error) {
	if w.conf.RawConfig.Worker.RecordingStoragePath == "" {
		return nil, nil
	}

	sshRm, err := ssh.NewSshRecordingManager(w, w.conf.RawConfig.Worker.RecordingStoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH recording manager: %w", err)
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