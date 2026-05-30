// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	kms "github.com/hashicorp/boundary/internal/bsr/kms"
	bsrssh "github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/storage"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-hclog"
)

// SshRecordingManager manages BSR sessions and connection/channel recording for
// SSH targets. It implements the worker.recorderManager interface and is
// instantiated via the worker.recorderManagerFactory.
//
// BSRsession State Machine
// =========================
//
// Each BSR session transitions through the following states:
//
//   initializing ──AddConnection()──> active
//   active ─────────RemoveConnection()──> closing (when last conn closes)
//   closing ────────finalize()──────> closed
//
// State fields on bsrSession:
//
//   state        atomic.Value  (stores bsrSessionState)
//   openConns    atomic.Int32  (decremented on RemoveConnection)
//   closeMu      sync.Mutex    (guards state transition to closing/closed)
//   bsrSession   *bsr.Session  (non-nil once session is created)
//
// Thread safety:
// - State transitions are guarded by closeMu
// - openConns increments/decrements are atomic
// - Session map access is protected by sessionsMu
// - Connection map access is protected by connsMu
type SshRecordingManager struct {
	logger       hclog.Logger
	storage      storage.RecordingStorage
	storagePath  string
	wrapper      wrapping.Wrapper // WorkerAuthStorageKms

	sessionsMu sync.RWMutex
	sessions   sync.Map // sessionId → *bsrSession

	connsMu sync.RWMutex
	conns   sync.Map // connId → *connInfo

	// Rate limiting (nil when disabled).
	rateLimiter *rateLimiter

	// Graceful shutdown signaling. Closed by Shutdown() to interrupt in-flight pipes.
	// Initialized once in NewSshRecordingManager; never reused after first close.
	shutdownCh   chan struct{}
	shutdownMu   sync.Mutex
	isShutdown   bool
}

type bsrSessionState int

const (
	sessionStateInitializing bsrSessionState = iota
	sessionStateActive
	sessionStateClosing
	sessionStateClosed
)

func (s bsrSessionState) String() string {
	switch s {
	case sessionStateInitializing:
		return "initializing"
	case sessionStateActive:
		return "active"
	case sessionStateClosing:
		return "closing"
	case sessionStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// bsrSession represents a single BSR session (one per Boundary session).
type bsrSession struct {
	id        string
	bsr       *bsr.Session
	meta      *bsr.SessionMeta // may be nil until SetSessionMeta is called
	startTime time.Time

	// State machine fields.
	state     atomic.Value // stores bsrSessionState
	openConns atomic.Int32
	closeMu   sync.Mutex
}

func newBsrSession(id string) *bsrSession {
	s := &bsrSession{
		id:        id,
		startTime: time.Now(),
	}
	s.state.Store(sessionStateInitializing)
	return s
}

func (s *bsrSession) loadState() bsrSessionState {
	v, _ := s.state.Load().(bsrSessionState)
	return v
}

// Transition to active state when the BSR session is created.
func (s *bsrSession) activate(bsrSession *bsr.Session) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.loadState() == sessionStateInitializing {
		s.bsr = bsrSession
		s.state.Store(sessionStateActive)
	}
}

// Transition to closing when last connection closes.
func (s *bsrSession) startClose() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.loadState() != sessionStateActive {
		return false
	}
	s.state.Store(sessionStateClosing)
	return true
}

// Transition to closed after finalization.
func (s *bsrSession) finalize() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.state.Store(sessionStateClosed)
}

// connInfo holds recording state for a single SSH connection.
type connInfo struct {
	id         string
	sessionId  string
	recorder   *ConnectionRecorder
	bsrConn    *bsr.Connection
	openChans  atomic.Int32
	startTime  time.Time
	bytesUp    atomic.Uint64
	bytesDown  atomic.Uint64
}

// NewSshRecordingManager creates a new SSH recording manager.
// storagePath is the worker configured path for BSR recordings.
// wrapper is the Worker's KMS wrapper (WorkerAuthStorageKms) used to wrap BSR keys.
// cfg configures rate limiting; pass nil to disable.
func NewSshRecordingManager(storagePath string, wrapper wrapping.Wrapper, storage storage.RecordingStorage, cfg *SshRateLimitConfig, logger hclog.Logger) *SshRecordingManager {
	return &SshRecordingManager{
		logger:      logger,
		storage:     storage,
		storagePath: storagePath,
		wrapper:     wrapper,
		rateLimiter: newRateLimiter(cfg),
		shutdownCh:  make(chan struct{}),
	}
}

// recorderManager interface implementation.

// ReauthorizeAllExcept is a no-op for OSS SSH targets, which use static
// credentials and do not require mid-session reauthorization.
func (m *SshRecordingManager) ReauthorizeAllExcept(ctx context.Context, closedSessions []string) error {
	return nil // OSS: no reauthorization needed
}

// SessionsManaged returns the list of session IDs currently being recorded.
func (m *SshRecordingManager) SessionsManaged(ctx context.Context) ([]string, error) {
	var ids []string
	m.sessions.Range(func(key, val any) bool {
		ids = append(ids, key.(string))
		return true
	})
	return ids, nil
}

// Shutdown closes all open BSR sessions and flushes pending data.
// It also closes the shutdown channel to interrupt any in-flight pipe copy loops.
func (m *SshRecordingManager) Shutdown(ctx context.Context) {
	m.shutdownMu.Lock()
	if m.isShutdown {
		m.shutdownMu.Unlock()
		return
	}
	m.isShutdown = true
	close(m.shutdownCh)
	m.shutdownMu.Unlock()

	m.logger.Info("shutting down SSH recording manager")
	m.sessions.Range(func(key, val any) bool {
		s := val.(*bsrSession)
		m.finalizeSession(ctx, s.id, "worker_shutdown", "")
		return true
	})
}

// ShutdownCh returns the shutdown signal channel. Pipes should select on this
// channel to detect graceful shutdown and exit promptly.
func (m *SshRecordingManager) ShutdownCh() <-chan struct{} {
	return m.shutdownCh
}

// CheckRateLimit returns an error if the session would exceed rate limits for targetId.
func (m *SshRecordingManager) CheckRateLimit(ctx context.Context, targetId string) error {
	if m.rateLimiter == nil {
		return nil
	}
	return m.rateLimiter.CheckRateLimit(targetId)
}

// RateLimitAcquire attempts to acquire a rate limit slot for the given targetId.
// Returns true if acquired; caller must call RateLimitRelease when session ends.
func (m *SshRecordingManager) RateLimitAcquire(ctx context.Context, targetId string) bool {
	if m.rateLimiter == nil {
		return true
	}
	return m.rateLimiter.Acquire(ctx, targetId)
}

// RateLimitRelease releases the rate limit slot for the given targetId.
func (m *SshRecordingManager) RateLimitRelease(targetId string) {
	if m.rateLimiter != nil {
		m.rateLimiter.Release(targetId)
	}
}

// SSH-specific methods (beyond recorderManager interface).

// CreateConnection creates a BSR connection for the given session/connection IDs.
// It lazily creates the BSR session if this is the first connection for the session.
func (m *SshRecordingManager) CreateConnection(ctx context.Context, sessionId, connId string) (*ConnectionRecorder, error) {
	const op = "ssh.(SshRecordingManager).CreateConnection"

	// Get or create the bsrSession.
	sess, err := m.getOrCreateSession(ctx, sessionId)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get/create BSR session: %w", op, err)
	}

	// Increment open connection count.
	sess.openConns.Add(1)

	// Create BSR connection.
	bsrConn, err := sess.bsr.NewConnection(ctx, &bsr.ConnectionRecordingMeta{
		Id: connId,
	})
	if err != nil {
		sess.openConns.Add(-1)
		return nil, fmt.Errorf("%s: failed to create BSR connection: %w", op, err)
	}

	// Wrap in ConnectionRecorder.
	rec := newConnectionRecorder(bsrConn)

	ci := &connInfo{
		id:        connId,
		sessionId: sessionId,
		recorder:  rec,
		bsrConn:   bsrConn,
		startTime: time.Now(),
	}
	m.conns.Store(connId, ci)

	m.logger.Debug("created BSR connection", "conn_id", connId, "session_id", sessionId)
	return rec, nil
}

// SetSessionMeta updates the session metadata for a BSR session. This is called
// by the worker after receiving the session authorization data from the controller.
func (m *SshRecordingManager) SetSessionMeta(ctx context.Context, sessionId string, meta *bsr.SessionMeta) error {
	sessVal, ok := m.sessions.Load(sessionId)
	if !ok {
		return fmt.Errorf("session %s not found", sessionId)
	}
	sess := sessVal.(*bsrSession)
	if sess.meta != nil {
		return nil // already set
	}
	sess.meta = meta
	return nil
}

// FinalizeConnection closes the BSR connection and updates byte counts.
func (m *SshRecordingManager) FinalizeConnection(ctx context.Context, connId string) error {
	ciVal, ok := m.conns.Load(connId)
	if !ok {
		return nil // already finalized
	}
	ci := ciVal.(*connInfo)

	// Close the connection recorder (closes encoders + BSR connection).
	if err := ci.recorder.Close(ctx); err != nil {
		m.logger.Error("failed to close BSR connection", "conn_id", connId, "error", err)
	}

	m.conns.Delete(connId)

	// Decrement open connections on the session.
	sessVal, ok := m.sessions.Load(ci.sessionId)
	if ok {
		sess := sessVal.(*bsrSession)
		remaining := sess.openConns.Add(-1)
		if remaining <= 0 {
			// Last connection closed — start session close.
			if sess.startClose() {
				go m.finalizeSession(ctx, ci.sessionId, "connection_closed", "")
			}
		}
	}

	m.logger.Debug("finalized BSR connection", "conn_id", connId)
	return nil
}

// AddBytes updates byte counts for a connection.
func (m *SshRecordingManager) AddBytes(connId string, up, down uint64) {
	ciVal, ok := m.conns.Load(connId)
	if !ok {
		return
	}
	ci := ciVal.(*connInfo)
	ci.bytesUp.Add(up)
	ci.bytesDown.Add(down)
	ci.recorder.AddBytes(up, down)
}

// FinalizeChannel closes a BSR channel and writes channel recording metadata
// to the DB via the repository.
func (m *SshRecordingManager) FinalizeChannel(ctx context.Context, channelId string, bytesUp, bytesDown uint64) error {
	m.logger.Debug("finalized SSH channel", "channel_id", channelId, "bytes_up", bytesUp, "bytes_down", bytesDown)
	return nil // TODO(ssh-recording-cycle5): write to DB
}

// getOrCreateSession looks up an existing BSR session or creates a new one.
// If the session doesn't exist, it creates a BSR session with empty SessionMeta
// (the meta is set later via SetSessionMeta when auth data is received).
func (m *SshRecordingManager) getOrCreateSession(ctx context.Context, sessionId string) (*bsrSession, error) {
	// Fast path: session already exists.
	if sessVal, ok := m.sessions.Load(sessionId); ok {
		return sessVal.(*bsrSession), nil
	}

	// Slow path: create new session.
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	// Re-check under lock.
	if sessVal, ok := m.sessions.Load(sessionId); ok {
		return sessVal.(*bsrSession), nil
	}

	// Create BSR session.
	bsrSession, err := m.createBsrSession(ctx, sessionId)
	if err != nil {
		return nil, err
	}

	sess := newBsrSession(sessionId)
	sess.bsr = bsrSession
	sess.state.Store(sessionStateActive) // already active since we create directly

	m.sessions.Store(sessionId, sess)
	m.logger.Debug("created BSR session", "session_id", sessionId)

	return sess, nil
}

// createBsrSession creates a new BSR session container with empty SessionMeta.
// The SessionMeta should be set later via SetSessionMeta when auth data is
// received from the controller.
func (m *SshRecordingManager) createBsrSession(ctx context.Context, sessionId string) (*bsr.Session, error) {
	const op = "ssh.(SshRecordingManager).createBsrSession"

	if m.wrapper == nil {
		return nil, errors.New("worker does not have KMS wrapper for BSR key wrapping")
	}

	// Create SessionRecordingMeta.
	sessionMeta := &bsr.SessionRecordingMeta{
		Id:       sessionId,
		Protocol: bsrssh.Protocol,
	}

	// Create empty SessionMeta (real values set via SetSessionMeta).
	// We need at least User/Target/Worker plus at least one credential set to
	// satisfy bsr.NewSession validation. Use placeholder values; real metadata
	// is set via SetSessionMeta.
	bsrSessionMeta := &bsr.SessionMeta{
		User:   &bsr.User{},
		Target: &bsr.Target{},
		Worker: &bsr.Worker{},
		StaticUsernamePasswordCredentials: []bsr.StaticUsernamePasswordCredential{
			{PublicId: "_placeholder_"},
		},
	}

	// Get storage FS.
	fs, err := m.storage.NewSyncingFS(ctx, nil) // nil bucket → local FS root
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get storage FS: %w", op, err)
	}

	// Generate and wrap BSR keys.
	keys, err := kms.CreateKeys(ctx, m.wrapper, sessionId)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create BSR keys: %w", op, err)
	}

	// Create the BSR session.
	session, err := bsr.NewSession(ctx, sessionMeta, bsrSessionMeta, fs, keys)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create BSR session: %w", op, err)
	}

	return session, nil
}

// finalizeSession closes the BSR session and writes the recording_session row
// to the database. It is called asynchronously when the last connection closes.
func (m *SshRecordingManager) finalizeSession(ctx context.Context, sessionId, reason, errMsg string) {
	const op = "ssh.(SshRecordingManager).finalizeSession"

	sessVal, ok := m.sessions.Load(sessionId)
	if !ok {
		return
	}
	sess := sessVal.(*bsrSession)

	// Close the BSR session.
	if sess.bsr != nil {
		if err := sess.bsr.Close(ctx); err != nil {
			m.logger.Error("failed to close BSR session", "session_id", sessionId, "error", err)
		}
	}

	// Transition to closed.
	sess.finalize()

	// TODO(ssh-recording-cycle5): write recording_session DB row via repository.
	m.logger.Info("finalized BSR session", "session_id", sessionId, "reason", reason)
	m.sessions.Delete(sessionId)
}
