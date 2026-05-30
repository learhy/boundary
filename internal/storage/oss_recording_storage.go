// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// ossRecordingStorage is a local-filesystem-backed RecordingStorage implementation
// for OSS deployments. It stores BSR session recordings in a configured local
// directory (RecordingStoragePath). This is used directly by the worker without
// requiring an external storage plugin.
//
// The storage layout mirrors the cloud-plugin layout:
//   recordings/
//     s_<session_id>/
//       connections/
//         cr_<conn_id>/
//           up.bsr.gz
//           down.bsr.gz
//           ...
//
// No external storage sync is performed (no upload to cloud object stores).
// This is suitable for single-worker or NFS-shared deployments.
type ossRecordingStorage struct {
	rootPath string
	mu       sync.Mutex
	tempFiles map[string]*os.File
}

var _ RecordingStorage = (*ossRecordingStorage)(nil)

// NewOssRecordingStorage creates a RecordingStorage backed by a local directory.
func NewOssRecordingStorage(ctx context.Context, path string) (RecordingStorage, error) {
	if path == "" {
		return nil, context.DeadlineExceeded // signal "not configured" to worker
	}

	// Ensure the root directory exists.
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}

	return &ossRecordingStorage{
		rootPath:  path,
		tempFiles: make(map[string]*os.File),
	}, nil
}

// NewSyncingFS returns a local FS for BSR file writing. When bucket is nil,
// this returns a local FS rooted at rootPath. Sync semantics (remote upload
// after file close) are no-ops for OSS since there is no remote storage.
func (s *ossRecordingStorage) NewSyncingFS(ctx context.Context, bucket *storagebuckets.StorageBucket, _ ...Option) (FS, error) {
	if bucket != nil {
		// OSS implementation does not support remote storage buckets.
		// This would indicate a misconfiguration (bucket assigned to worker
		// that should use OSS-only storage). Log and fall back to local.
		return nil, nil
	}
	return &ossFS{root: s.rootPath}, nil
}

// NewRemoteFS returns nil for OSS — there is no remote storage.
func (s *ossRecordingStorage) NewRemoteFS(ctx context.Context, bucket *storagebuckets.StorageBucket, _ ...Option) (FS, error) {
	return nil, nil
}

// PluginClients returns an empty map for OSS.
func (s *ossRecordingStorage) PluginClients() map[string]plgpb.StoragePluginServiceClient {
	return nil
}

// CreateTemp creates a temporary file under rootPath.
// The file is registered for cleanup on storage shutdown.
func (s *ossRecordingStorage) CreateTemp(ctx context.Context, p string) (TempFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.CreateTemp(s.rootPath, p)
	if err != nil {
		return nil, err
	}
	s.tempFiles[f.Name()] = f
	return &ossTempFile{file: f, path: f.Name()}, nil
}

// ossFS is a local filesystem FS implementation.
type ossFS struct {
	root string
}

var _ FS = (*ossFS)(nil)

// New creates a new container directory.
func (f *ossFS) New(ctx context.Context, name string) (Container, error) {
	path := filepath.Join(f.root, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return &ossContainer{path: path}, nil
}

// Open opens an existing container directory.
func (f *ossFS) Open(ctx context.Context, name string) (Container, error) {
	path := filepath.Join(f.root, name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, os.ErrNotExist
	}
	return &ossContainer{path: path}, nil
}

// ossContainer is a local directory Container implementation.
type ossContainer struct {
	path string
}

var _ Container = (*ossContainer)(nil)

// Close is a no-op for local directories.
func (c *ossContainer) Close() error {
	return nil
}

// Create creates a new file in the container directory.
func (c *ossContainer) Create(ctx context.Context, name string) (File, error) {
	path := filepath.Join(c.path, name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &ossFile{File: f}, nil
}

// OpenFile opens an existing file.
func (c *ossContainer) OpenFile(ctx context.Context, name string, opts ...Option) (File, error) {
	path := filepath.Join(c.path, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &ossFile{File: f}, nil
}

// SubContainer creates or opens a sub-directory.
func (c *ossContainer) SubContainer(ctx context.Context, name string, opts ...Option) (Container, error) {
	path := filepath.Join(c.path, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return &ossContainer{path: path}, nil
}

// ossFile wraps os.File as a storage File.
type ossFile struct {
	*os.File
}

var _ File = (*ossFile)(nil)

// Write implements File.
func (f *ossFile) Write(p []byte) (int, error) {
	return f.File.Write(p)
}

// WriteString implements File.
func (f *ossFile) WriteString(s string) (int, error) {
	return io.WriteString(f.File, s)
}

// ossTempFile wraps os.File for temp file handling.
type ossTempFile struct {
	file *os.File
	path string
}

var _ TempFile = (*ossTempFile)(nil)

func (f *ossTempFile) Write(p []byte) (int, error) {
	return f.file.Write(p)
}

func (f *ossTempFile) WriteString(s string) (int, error) {
	return io.WriteString(f.file, s)
}

func (f *ossTempFile) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(offset, whence)
}

func (f *ossTempFile) Close() error {
	os.Remove(f.path)
	return f.file.Close()
}

// Read implements fs.File for temp files.
func (f *ossTempFile) Read(p []byte) (int, error) {
	return f.file.Read(p)
}

// Stat implements fs.File for temp files.
func (f *ossTempFile) Stat() (os.FileInfo, error) {
	return f.file.Stat()
}