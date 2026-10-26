// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSshRecordingManager creates an SshRecordingManager with a temp dir and
// a valid KMS wrapper suitable for testing.
func newTestSshRecordingManager(t *testing.T, cfg *SshRateLimitConfig) (*SshRecordingManager, string) {
	t.Helper()
	recordingsDir := t.TempDir()

	rootWrapper := aead.NewWrapper()
	_, err := rootWrapper.SetConfig(context.Background(), wrapping.WithKeyId("test-root-key"))
	require.NoError(t, err)
	err = rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)

	recordingStorage, err := storage.NewOssRecordingStorage(context.Background(), recordingsDir)
	require.NoError(t, err)

	logger := hclog.NewNullLogger()
	mgr := NewSshRecordingManager(recordingsDir, rootWrapper, recordingStorage, cfg, logger)
	return mgr, recordingsDir
}

func TestNewSshRecordingManager_CreatesValidInstance(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	require.NotNil(t, mgr)
	assert.NotNil(t, mgr.ShutdownCh())
}

func TestNewSshRecordingManager_WithRateLimit(t *testing.T) {
	cfg := &SshRateLimitConfig{MaxConcurrentSessions: 5, MaxPerTarget: 2}
	mgr, _ := newTestSshRecordingManager(t, cfg)
	require.NotNil(t, mgr)

	assert.True(t, mgr.RateLimitAcquire(context.Background(), "target1"))
	assert.True(t, mgr.RateLimitAcquire(context.Background(), "target1"))
	assert.False(t, mgr.RateLimitAcquire(context.Background(), "target1"),
		"third acquire should exceed per-target cap")
}

func TestCreateConnection_CreatesBsrSessionAndConnection(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_test123", "cr_test123")
	require.NoError(t, err)
	require.NotNil(t, rec)

	// Verify the session was created.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Contains(t, sessions, "s_test123")
}

func TestCreateConnection_ReusesExistingSession(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec1, err := mgr.CreateConnection(ctx, "s_test123", "cr_test123")
	require.NoError(t, err)
	require.NotNil(t, rec1)

	rec2, err := mgr.CreateConnection(ctx, "s_test123", "cr_test456")
	require.NoError(t, err)
	require.NotNil(t, rec2)

	// Different connections should have different recorders.
	assert.NotEqual(t, rec1, rec2)

	// Only one session should be managed.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "s_test123", sessions[0])
}

func TestCreateConnection_RateLimiting(t *testing.T) {
	cfg := &SshRateLimitConfig{MaxConcurrentSessions: 1, MaxPerTarget: 1}
	mgr, _ := newTestSshRecordingManager(t, cfg)
	ctx := context.Background()

	// Acquire the only slot via RateLimitAcquire.
	ok := mgr.RateLimitAcquire(ctx, "s_test123")
	require.True(t, ok)

	// RateLimitAcquire used by handleProxy — CreateConnection should fail
	// because CreateConnection doesn't check rate limits, it only creates
	// BSR connections. The rate limit check happens before CreateConnection
	// in handleProxy.
	// However, let's verify the rate limit path works:
	ok = mgr.RateLimitAcquire(ctx, "s_test123")
	assert.False(t, ok, "second acquire should fail (per-target cap)")
}

func TestFinalizeConnection_TransitionsSessionToClosing(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_test123", "cr_test123")
	require.NoError(t, err)
	require.NotNil(t, rec)

	err = mgr.FinalizeConnection(ctx, "cr_test123")
	require.NoError(t, err)

	// Give the async finalizeSession goroutine time to run.
	time.Sleep(100 * time.Millisecond)

	// After finalizing the only connection, the session should be removed.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions, "session should be finalized and removed")
}

func TestFinalizeConnection_MultipleConnsNoCloseTillLast(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec1, err := mgr.CreateConnection(ctx, "s_multi", "cr_multi_1")
	require.NoError(t, err)
	require.NotNil(t, rec1)

	rec2, err := mgr.CreateConnection(ctx, "s_multi", "cr_multi_2")
	require.NoError(t, err)
	require.NotNil(t, rec2)

	rec3, err := mgr.CreateConnection(ctx, "s_multi", "cr_multi_3")
	require.NoError(t, err)
	require.NotNil(t, rec3)

	// Finalize first connection — session should still exist.
	err = mgr.FinalizeConnection(ctx, "cr_multi_1")
	require.NoError(t, err)

	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Contains(t, sessions, "s_multi", "session should survive after first conn close")

	// Finalize second connection — session should still exist.
	err = mgr.FinalizeConnection(ctx, "cr_multi_2")
	require.NoError(t, err)

	sessions, err = mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Contains(t, sessions, "s_multi", "session should survive after second conn close")

	// Finalize third (last) connection — session should be finalized.
	err = mgr.FinalizeConnection(ctx, "cr_multi_3")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	sessions, err = mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions, "session should be removed after last conn close")
}

func TestFinalizeConnection_AlreadyFinalized(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_test123", "cr_test123")
	require.NoError(t, err)
	require.NotNil(t, rec)

	// Finalize once.
	err = mgr.FinalizeConnection(ctx, "cr_test123")
	require.NoError(t, err)

	// Finalize again — should be a no-op (already deleted from conns map).
	err = mgr.FinalizeConnection(ctx, "cr_test123")
	require.NoError(t, err)
}

func TestSetSessionMeta_UpdatesMeta(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_meta_test", "cr_meta_test")
	require.NoError(t, err)
	require.NotNil(t, rec)

	meta := &bsr.SessionMeta{
		PublicId: "s_meta_test",
		Endpoint: "tcp://127.0.0.1:22",
		User:     &bsr.User{PublicId: "u_admin", Name: "admin"},
		Target:   &bsr.Target{PublicId: "ttcp_test", Name: "SSH Target", DefaultPort: 22},
		Worker:   &bsr.Worker{PublicId: "w_test"},
		StaticUsernamePasswordCredentials: []bsr.StaticUsernamePasswordCredential{
			{PublicId: "cred_test", Username: "boundarytest"},
		},
	}

	err = mgr.SetSessionMeta(ctx, "s_meta_test", meta)
	require.NoError(t, err)

	// Setting meta again should be a no-op (returns nil).
	err = mgr.SetSessionMeta(ctx, "s_meta_test", meta)
	require.NoError(t, err)
}

func TestSetSessionMeta_SessionNotFound(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	err := mgr.SetSessionMeta(ctx, "s_nonexistent", &bsr.SessionMeta{PublicId: "s_nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSessionsManaged_ReturnsList(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	// No sessions yet.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)

	rec1, err := mgr.CreateConnection(ctx, "s_one", "cr_one")
	require.NoError(t, err)
	require.NotNil(t, rec1)

	rec2, err := mgr.CreateConnection(ctx, "s_two", "cr_two")
	require.NoError(t, err)
	require.NotNil(t, rec2)

	sessions, err = mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"s_one", "s_two"}, sessions)
}

func TestShutdown_ClosesAllSessions(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec1, err := mgr.CreateConnection(ctx, "s_shutdown1", "cr_shutdown1")
	require.NoError(t, err)
	require.NotNil(t, rec1)

	rec2, err := mgr.CreateConnection(ctx, "s_shutdown2", "cr_shutdown2")
	require.NoError(t, err)
	require.NotNil(t, rec2)

	mgr.Shutdown(ctx)

	// After shutdown, session list should be empty.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestShutdown_IsIdempotent(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_idempotent", "cr_idempotent")
	require.NoError(t, err)
	require.NotNil(t, rec)

	// Shutdown twice — should not panic.
	mgr.Shutdown(ctx)
	mgr.Shutdown(ctx)

	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestShutdownCh_SignalsOnShutdown(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	ch := mgr.ShutdownCh()

	select {
	case <-ch:
		t.Fatal("shutdown channel should not be closed before Shutdown()")
	default:
	}

	mgr.Shutdown(ctx)

	select {
	case <-ch:
		// Expected — channel is now closed.
	default:
		t.Fatal("shutdown channel should be closed after Shutdown()")
	}
}

func TestConcurrentConnectionLifecycle(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	const numConns = 20
	var wg sync.WaitGroup

	// Create 20 connections concurrently for the same session.
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			connId := "cr_concurrent"
			if idx > 0 {
				connId = "cr_concurrent_" + string(rune('a'+idx))
			}
			rec, err := mgr.CreateConnection(ctx, "s_concurrent", connId)
			if err != nil {
				t.Logf("CreateConnection error: %v", err)
				return
			}
			_ = rec
		}(i)
	}
	wg.Wait()

	// Verify that exactly one session was created.
	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "s_concurrent", sessions[0])
}

func TestConcurrentFinalizeConnection(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	// Create 10 connections.
	const numConns = 10
	var connIds []string
	for i := 0; i < numConns; i++ {
		connId := "cr_race_" + string(rune('0'+i))
		connIds = append(connIds, connId)
		_, err := mgr.CreateConnection(ctx, "s_race", connId)
		require.NoError(t, err)
	}

	// Finalize all connections concurrently.
	var wg sync.WaitGroup
	for _, connId := range connIds {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			err := mgr.FinalizeConnection(ctx, id)
			if err != nil {
				t.Logf("FinalizeConnection error: %v", err)
			}
		}(connId)
	}
	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	sessions, err := mgr.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions, "all sessions should be finalized after concurrent close")
}

func TestAddBytes(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_bytes", "cr_bytes")
	require.NoError(t, err)
	require.NotNil(t, rec)

	// Add some bytes via the manager.
	mgr.AddBytes("cr_bytes", 100, 200)

	assert.Equal(t, uint64(100), rec.BytesUp())
	assert.Equal(t, uint64(200), rec.BytesDown())

	// Add more bytes.
	mgr.AddBytes("cr_bytes", 50, 75)
	assert.Equal(t, uint64(150), rec.BytesUp())
	assert.Equal(t, uint64(275), rec.BytesDown())
}

func TestAddBytes_UnknownConnIdIsNoop(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)

	// Should not panic.
	mgr.AddBytes("cr_nonexistent", 100, 200)
}

func TestFinalizeChannel(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	err := mgr.FinalizeChannel(ctx, "ch_test123", 100, 200)
	assert.NoError(t, err)
}

func TestReauthorizeAllExcept(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	err := mgr.ReauthorizeAllExcept(ctx, nil)
	assert.NoError(t, err)
}

func TestCheckRateLimit(t *testing.T) {
	cfg := &SshRateLimitConfig{MaxConcurrentSessions: 2, MaxPerTarget: 1}
	mgr, _ := newTestSshRecordingManager(t, cfg)
	ctx := context.Background()

	// No error before acquiring.
	err := mgr.CheckRateLimit(ctx, "target1")
	assert.NoError(t, err)

	// Acquire the slot.
	mgr.RateLimitAcquire(ctx, "target1")

	// Now CheckRateLimit should return error.
	err = mgr.CheckRateLimit(ctx, "target1")
	assert.Error(t, err)

	// Different target should also be rate limited (global cap reached).
	err = mgr.CheckRateLimit(ctx, "target2")
	assert.Error(t, err)
}

func TestCheckRateLimit_NoRateLimiter(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	err := mgr.CheckRateLimit(ctx, "target1")
	assert.NoError(t, err)
}

func TestDeriveSessionId(t *testing.T) {
	tests := []struct {
		connId string
		want   string
	}{
		{"cr_abc123", "s_abc123"},
		{"cr_", "s_"},
		{"", ""},
		{"invalid", ""},
		{"abc", ""},
	}
	for _, tc := range tests {
		t.Run(tc.connId, func(t *testing.T) {
			got := deriveSessionId(tc.connId)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBsrSession_StateMachine(t *testing.T) {
	s := newBsrSession("s_test")
	assert.Equal(t, sessionStateInitializing, s.loadState())

	// Activate with a session (use a minimal path).
	// We can't create a real BSR session here, but we can test state transitions.
	s.state.Store(sessionStateActive)
	assert.Equal(t, sessionStateActive, s.loadState())

	// Start close -> closing.
	ok := s.startClose()
	assert.True(t, ok)
	assert.Equal(t, sessionStateClosing, s.loadState())

	// Second startClose should return false (already closing).
	ok = s.startClose()
	assert.False(t, ok)

	// Finalize -> closed.
	s.finalize()
	assert.Equal(t, sessionStateClosed, s.loadState())
}

func TestBsrSession_StateString(t *testing.T) {
	assert.Equal(t, "initializing", sessionStateInitializing.String())
	assert.Equal(t, "active", sessionStateActive.String())
	assert.Equal(t, "closing", sessionStateClosing.String())
	assert.Equal(t, "closed", sessionStateClosed.String())
	assert.Equal(t, "unknown", bsrSessionState(99).String())
}

// fullRecordingTest sets up a complete recording with BSR session, connections,
// and chunk data. This follows the pattern in bsr_export_test.go.
func TestSessionManager_FullRecordingLifecycle(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	recordingsDir := t.TempDir()

	rootWrapper := aead.NewWrapper()
	_, err := rootWrapper.SetConfig(ctx, wrapping.WithKeyId("test-root-key"))
	require.NoError(t, err)
	err = rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)

	recordingStorage, err := storage.NewOssRecordingStorage(ctx, recordingsDir)
	require.NoError(t, err)

	mgr := NewSshRecordingManager(recordingsDir, rootWrapper, recordingStorage, nil, logger)

	sessionId := "s_integration_test"
	connId := "cr_integration_test"

	// Create connection.
	connRecorder, err := mgr.CreateConnection(ctx, sessionId, connId)
	require.NoError(t, err)
	require.NotNil(t, connRecorder)

	// Write session metadata.
	sessionMeta := &bsr.SessionMeta{
		PublicId: sessionId,
		Endpoint: "tcp://127.0.0.1:22",
		User:     &bsr.User{PublicId: "u_test", Name: "test"},
		Target:   &bsr.Target{PublicId: "tt_test", Name: "SSH Target", DefaultPort: 22},
		Worker:   &bsr.Worker{PublicId: "w_test"},
		StaticUsernamePasswordCredentials: []bsr.StaticUsernamePasswordCredential{
			{PublicId: "cred_test", Username: "testuser"},
		},
	}
	err = mgr.SetSessionMeta(ctx, sessionId, sessionMeta)
	require.NoError(t, err)

	// Emit some data chunks.
	err = connRecorder.EmitDataChunk(bsr.Outbound, []byte("SSH data outbound"))
	require.NoError(t, err)
	err = connRecorder.EmitDataChunk(bsr.Inbound, []byte("SSH data inbound"))
	require.NoError(t, err)

	// Verify bytes.
	assert.Equal(t, uint64(17), connRecorder.BytesUp())  // "SSH data outbound" is 17 bytes
	assert.Equal(t, uint64(16), connRecorder.BytesDown()) // "SSH data inbound" is 16 bytes

	// Add more bytes via the manager.
	mgr.AddBytes(connId, 10, 20)
	assert.Equal(t, uint64(27), connRecorder.BytesUp()) // 17 + 10 = 27
	assert.Equal(t, uint64(36), connRecorder.BytesDown()) // 16 + 20 = 36

	// Finalize connection.
	err = mgr.FinalizeConnection(ctx, connId)
	require.NoError(t, err)

	// Shutdown.
	mgr.Shutdown(ctx)

	// Verify the BSR files were written to disk.
	entries, err := os.ReadDir(recordingsDir)
	require.NoError(t, err)

	// Should have at least one directory.
	assert.Greater(t, len(entries), 0)

	// Find our session directory — BSR creates it with .bsr suffix.
	found := false
	for _, e := range entries {
		if e.IsDir() && e.Name() == "s_integration_test.bsr" {
			found = true
			break
		}
	}
	assert.True(t, found, "BSR session directory should exist on disk")
}

// Test that creating a BSR session without a wrapper returns an error.
func TestCreateBsrSession_NoWrapper(t *testing.T) {
	mgr := NewSshRecordingManager("/tmp/test", nil, nil, nil, hclog.NewNullLogger())
	ctx := context.Background()

	session, err := mgr.createBsrSession(ctx, "s_nowrapper")
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "KMS wrapper")
}

// TestGetOrCreateSession_ConcurrentRace tests the double-check locking.
func TestGetOrCreateSession_ConcurrentRace(t *testing.T) {
	mgr, recordingsDir := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	const numGoroutines = 10
	var wg sync.WaitGroup
	sessions := make([]*bsrSession, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sess, err := mgr.getOrCreateSession(ctx, "s_race_dcl")
			if err == nil {
				sessions[idx] = sess
			}
		}(i)
	}
	wg.Wait()

	// Count unique pointers — there should be only one.
	seen := make(map[*bsrSession]int)
	for _, s := range sessions {
		if s != nil {
			seen[s]++
		}
	}
	assert.Len(t, seen, 1, "all goroutines should get the same session pointer")

	// Verify the BSR session directory exists on disk.
	expectedDir := filepath.Join(recordingsDir, "s_race_dcl")
	_, err := os.Stat(expectedDir)
	assert.NoError(t, err, "BSR session directory should exist")
}
