// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	bsrkms "github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
)

func TestBsrExportForEmail(t *testing.T) {
	outputDir := "/tmp/bsr-email-output"
	os.RemoveAll(outputDir)
	recordingsDir := filepath.Join(outputDir, "recordings")
	err := os.MkdirAll(recordingsDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	rootWrapper := aead.NewWrapper()
	rootWrapper.SetConfig(context.Background(), wrapping.WithKeyId("test-root-key"))
	rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))

	bsrkms.CreateKeys(context.Background(), rootWrapper, "s_demo12345678")

	recordingStorage, err := storage.NewOssRecordingStorage(context.Background(), recordingsDir)
	if err != nil {
		t.Fatal(err)
	}

	logger := hclog.NewNullLogger()
	mgr := NewSshRecordingManager(recordingsDir, rootWrapper, recordingStorage, nil, logger)

	sessionId := "s_demo12345678"
	connId := "cr_demo12345678"
	ctx := context.Background()

	connRecorder, err := mgr.CreateConnection(ctx, sessionId, connId)
	if err != nil {
		t.Fatal(err)
	}

	// Write session metadata
	sessionMeta := &bsr.SessionMeta{
		PublicId: sessionId,
		Endpoint: "tcp://127.0.0.1:22",
		User:     &bsr.User{PublicId: "u_admin", Name: "admin"},
		Target:   &bsr.Target{PublicId: "ttcp_test", Name: "SSH Target", DefaultPort: 22},
		Worker:   &bsr.Worker{PublicId: "w_test"},
		StaticUsernamePasswordCredentials: []bsr.StaticUsernamePasswordCredential{
			{PublicId: "cred_test", Username: "boundarytest"},
		},
	}
	mgr.SetSessionMeta(ctx, sessionId, sessionMeta)

	// Emit some SSH data chunks
	connRecorder.EmitDataChunk(bsr.Outbound, []byte("SSH_MSG_CHANNEL_DATA: ls -la\r\n"))
	connRecorder.EmitDataChunk(bsr.Inbound, []byte("SSH_MSG_CHANNEL_DATA: total 24\r\n"))
	connRecorder.EmitDataChunk(bsr.Outbound, []byte("SSH_MSG_CHANNEL_DATA: whoami\r\n"))
	connRecorder.EmitDataChunk(bsr.Inbound, []byte("SSH_MSG_CHANNEL_DATA: boundarytest\r\n"))
	connRecorder.EmitDataChunk(bsr.Outbound, []byte("SSH_MSG_CHANNEL_DATA: hostname\r\n"))
	connRecorder.EmitDataChunk(bsr.Inbound, []byte("SSH_MSG_CHANNEL_DATA: dev\r\n"))

	connRecorder.Close(ctx)
	mgr.Shutdown(ctx)

	t.Logf("BSR recording created at: %s", recordingsDir)
}
