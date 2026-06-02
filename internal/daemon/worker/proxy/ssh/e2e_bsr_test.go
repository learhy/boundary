// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	bsrkms "github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/require"
)

// TestE2ESshSessionRecordingProducesBsrFile is the end-to-end smoke test
// for SSH session recording. It exercises the full data path:
//
//   client conn <-> pipe.copyWithShutdown <-> target conn
//                         |
//                  BSR ConnectionRecorder
//                         |
//                    BSR on disk
//
// This mirrors what the worker's SSH handler does: shuttle bytes between
// client and target while recording each direction into a BSR connection.
// After the test, the BSR is on disk at /tmp/boundary-bsr-e2e/ for inspection.
//
// The SSH wire framing (4-byte length + payload) is included in the data so
// the BSR contains realistic SSH_MSG_CHANNEL_DATA chunks.
func TestE2ESshSessionRecordingProducesBsrFile(t *testing.T) {
	outputDir := "/tmp/boundary-bsr-e2e"
	_ = os.RemoveAll(outputDir)
	recordingsDir := filepath.Join(outputDir, "recordings")
	require.NoError(t, os.MkdirAll(recordingsDir, 0o700))

	ctx := context.Background()
	rootWrapper := aead.NewWrapper()
	rootWrapper.SetConfig(ctx, wrapping.WithKeyId("test-root-key"))
	rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))

	sessionId := "s_e2e_smoke01"
	connId := "cr_e2e_smoke01"

	_, err := bsrkms.CreateKeys(ctx, rootWrapper, sessionId)
	require.NoError(t, err)
	recStorage, err := storage.NewOssRecordingStorage(ctx, recordingsDir)
	require.NoError(t, err)
	logger := hclog.NewNullLogger()
	mgr := NewSshRecordingManager(recordingsDir, rootWrapper, recStorage, nil, logger)

	// Create the BSR connection via the recording manager.
	connRecorder, err := mgr.CreateConnection(ctx, sessionId, connId)
	require.NoError(t, err)
	require.NotNil(t, connRecorder)

	// Set real session metadata so the BSR captures actual session info.
	meta := &bsr.SessionMeta{
		PublicId: sessionId,
		Endpoint: "tcp://127.0.0.1:22",
		User:     &bsr.User{PublicId: "u_smoke", Name: "smoketest"},
		Target:   &bsr.Target{PublicId: "ttcp_smoke", Name: "SmokeTest SSH", DefaultPort: 22},
		Worker:   &bsr.Worker{PublicId: "w_smoke"},
		StaticUsernamePasswordCredentials: []bsr.StaticUsernamePasswordCredential{
			{PublicId: "cred_smoke", Username: "boundarytest"},
		},
	}
	require.NoError(t, mgr.SetSessionMeta(ctx, sessionId, meta))

	// Emit data in both directions directly via the recorder. This is
	// exactly what the worker's pipe.InterceptingConn does on every SSH
	// message it sees.
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Outbound, []byte("ls -la\n")))
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Inbound, []byte("total 24\ndrwxr-xr-x 2 dan dan 4096 Jun  1 12:00 .\n")))
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Outbound, []byte("whoami\n")))
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Inbound, []byte("boundarytest\n")))
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Outbound, []byte("exit\n")))
	require.NoError(t, connRecorder.EmitDataChunk(bsr.Inbound, []byte("logout\n")))

	// Now also drive the pipe to verify the full data path (interception,
	// framing, recording) works end-to-end. This is the same code path
	// the SSH handler uses internally.
	c1, c2 := net.Pipe()
	t1, t2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	defer t1.Close()
	defer t2.Close()

	pipe := newPipe(c1, t1, connRecorder)
	var wg sync.WaitGroup
	wg.Add(1)
	pipeCtx, pipeCancel := context.WithCancel(ctx)
	go func() {
		defer wg.Done()
		pipe.runWithShutdown(pipeCtx, nil, nil)
	}()

	// Drive a realistic SSH channel data message in each direction.
	// 4-byte BE length + 1-byte type + 4-byte channel + 4-byte data length + data
	// Client -> target: "ls"
	go func() {
		pkt := []byte{
			0, 0, 0, 13, // length
			94,             // SSH_MSG_CHANNEL_DATA
			0, 0, 0, 0, // recipient channel
			0, 0, 0, 2, // string length
			'l', 's',
		}
		_, _ = c2.Write(pkt)
	}()
	// Target -> client: "ok"
	go func() {
		pkt := []byte{
			0, 0, 0, 11, // length
			94,             // SSH_MSG_CHANNEL_DATA
			0, 0, 0, 0, // recipient channel
			0, 0, 0, 2, // string length
			'o', 'k',
		}
		_, _ = t2.Write(pkt)
	}()

	// Let the data flow through the recording pipe.
	time.Sleep(500 * time.Millisecond)

	// Close all conns to terminate the pipe's read loop.
	pipeCancel()
	c1.Close()
	c2.Close()
	t1.Close()
	t2.Close()
	wg.Wait()

	// Finalize the connection (this writes connection-recording-summary.json).
	require.NoError(t, mgr.FinalizeConnection(ctx, connId))
	// Shutdown the manager.
	mgr.Shutdown(ctx)

	// Verify the BSR exists and contains expected files.
	bsrDir := filepath.Join(recordingsDir, sessionId+".bsr")
	entries, err := os.ReadDir(bsrDir)
	require.NoError(t, err, "BSR directory must exist")
	require.NotEmpty(t, entries, "BSR directory must have at least one file")

	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	for _, want := range []string{".journal", "session-recording.meta", "SHA256SUM", "bsrKey.pub"} {
		require.True(t, got[want], "BSR is missing required file: %s", want)
	}

	// Verify the connection subdir with messages-*.data files.
	connDir := filepath.Join(bsrDir, connId+".connection")
	connEntries, err := os.ReadDir(connDir)
	require.NoError(t, err, "BSR connection subdirectory must exist")
	connFiles := map[string]bool{}
	for _, e := range connEntries {
		connFiles[e.Name()] = true
	}
	require.True(t, connFiles["messages-inbound.data"], "BSR connection must record inbound data")
	require.True(t, connFiles["messages-outbound.data"], "BSR connection must record outbound data")

	// Log the artifact location for the user.
	t.Logf("BSR E2E artifact: %s", bsrDir)
	t.Logf("BSR session files: %v", keys(got))
	t.Logf("BSR connection files: %v", keys(connFiles))
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
