// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package worker

import (
	"context"
	"errors"

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
	storagePath := w.Conf().RawConfig.Worker.RecordingStoragePath
	wrapper := w.Conf().WorkerAuthStorageKms
	return ssh.NewSshRecordingManager(storagePath, wrapper, w.RecordingStorage, w.Logger().Named("ssh-recording")), nil
}