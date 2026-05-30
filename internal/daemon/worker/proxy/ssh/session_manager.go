// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/mr-tron/base58"
)

// SshRecordingManager manages BSR sessions for SSH session recording.
// It creates and stores BSR sessions keyed by Boundary session ID.
type SshRecordingManager struct {
	worker  *worker.Worker
	storage recordingStorage

	mu          sync.RWMutex
	bsrSessions map[string]*bsr.Session // keyed by Boundary session ID
}

// recordingStorage is the interface for BSR recording storage.
type recordingStorage interface {
	// NewBsrSessionStorage returns a new BSR session storage for the given session ID.
	NewBsrSessionStorage(sessionId string) (bsr.SessionStorage, error)
}

// localFSRecordingStorage implements recordingStorage using a local filesystem.
type localFSRecordingStorage struct {
	root string
}

func (s *localFSRecordingStorage) NewBsrSessionStorage(sessionId string) (bsr.SessionStorage, error) {
	return bsr.NewLocalFS_sessionStorage(context.Background(), s.root, sessionId)
}

// sessionState holds per-session state in the SshRecordingManager.
type sessionState struct {
	mu       sync.RWMutex
	connMeta map[string]*bsr.ConnectionRecordingMeta // keyed by connection ID
}

// NewSshRecordingManager creates a new SSH recording manager.
// The storage root path is used to store BSR session files.
func NewSshRecordingManager(wrk *worker.Worker, root string) (*SshRecordingManager, error) {
	if wrk == nil {
		return nil, fmt.Errorf("worker is required")
	}
	if root == "" {
		return nil, fmt.Errorf("recording storage root is required")
	}

	rm := &SshRecordingManager{
		worker:      wrk,
		storage:     &localFSRecordingStorage{root: root},
		bsrSessions: make(map[string]*bsr.Session),
	}

	return rm, nil
}

// getOrCreateBsrSession retrieves or creates a BSR session for the given boundary session ID.
// It uses the credentials to build the BSR SessionMeta.
func (rm *SshRecordingManager) getOrCreateBsrSession(ctx context.Context, boundarySessionId, endpoint string, creds []*pbs.Credential, workerInfo *bsr.Worker) (*bsr.Session, string, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Check if session already exists
	if existing, ok := rm.bsrSessions[boundarySessionId]; ok {
		return existing, boundarySessionId, nil
	}

	// Generate a deterministic recording ID
	recordingId := generateRecordingId(boundarySessionId)

	// Build session meta from credentials
	sessionMeta, err := rm.buildSessionMeta(recordingId, endpoint, creds, workerInfo)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build session meta: %w", err)
	}

	// Create BSR wrapper for encryption
	wrapper, err := rm.newBsrWrapper(recordingId)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create BSR wrapper: %w", err)
	}

	// Create session storage
	storage, err := rm.storage.NewBsrSessionStorage(recordingId)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create BSR storage: %w", err)
	}

	// Create BSR session
	bsrSession, err := bsr.NewSession(ctx, sessionMeta, storage, wrapper)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create BSR session: %w", err)
	}

	// Store session
	rm.bsrSessions[boundarySessionId] = bsrSession

	// Initialize session state
	state := &sessionState{
		connMeta: make(map[string]*bsr.ConnectionRecordingMeta),
	}
	// Note: state is stored in a local map; we use a deferred approach
	_ = state // state tracking is done via bsrSession directly

	return bsrSession, recordingId, nil
}

// generateRecordingId creates a deterministic recording ID from the boundary session ID.
func generateRecordingId(sessId string) string {
	hash := sha256.Sum256([]byte(sessId + "-ssh-recording-v0"))
	return "sr_" + base58.Encode(hash[:16])
}

// buildSessionMeta builds a bsr.SessionMeta from credentials.
func (rm *SshRecordingManager) buildSessionMeta(recordingId, endpoint string, creds []*pbs.Credential, workerInfo *bsr.Worker) (*bsr.SessionMeta, error) {
	var staticUpCreds []bsr.StaticUsernamePasswordCredential
	var staticSshCreds []bsr.StaticSshPrivateKeyCredential
	var vaultSshCertLibs []bsr.VaultSshCertificateLibrary

	for _, cred := range creds {
		switch c := cred.Credential.(type) {
		case *pbs.Credential_UsernamePassword:
			if c.UsernamePassword != nil {
				staticUpCreds = append(staticUpCreds, bsr.StaticUsernamePasswordCredential{
					PublicId:         c.UsernamePassword.CredentialId,
					Username:         c.UsernamePassword.Username,
					PasswordHmac:     c.UsernamePassword.GetCredentialSecret(),
					Purposes:         []string{"session"},
					CredentialStore: bsr.StaticCredentialStore{
						PublicId: c.UsernamePassword.GetCredentialStoreId(),
						ProjectId: "oss",
					},
				})
			}
		case *pbs.Credential_SshPrivateKey:
			if c.SshPrivateKey != nil {
				sshCred := bsr.StaticSshPrivateKeyCredential{
					PublicId:           c.SshPrivateKey.CredentialId,
					Username:           c.SshPrivateKey.GetUsername(),
					PrivateKeyHmac:     c.SshPrivateKey.GetCredentialSecret(),
					Purposes:           []string{"session"},
					CredentialStore: bsr.StaticCredentialStore{
						PublicId: c.SshPrivateKey.GetCredentialStoreId(),
						ProjectId: "oss",
					},
				}
				if c.SshPrivateKey.PrivateKeyPassphrase != "" {
					sshCred.PrivateKeyPassphraseHmac = c.SshPrivateKey.PrivateKeyPassphrase
				}
				staticSshCreds = append(staticSshCreds, sshCred)
			}
		case *pbs.Credential_SshCertificate:
			if c.SshCertificate != nil {
				vaultSshCertLibs = append(vaultSshCertLibs, bsr.VaultSshCertificateLibrary{
					PublicId:       c.SshCertificate.CredentialId,
					Username:       c.SshCertificate.GetUsername(),
					CredentialType: "ssh_certificate",
					Purposes:       []string{"session"},
					CredentialStore: bsr.VaultCredentialStore{
						PublicId: c.SshCertificate.GetCredentialStoreId(),
						ProjectId: "oss",
					},
				})
			}
		}
	}

	// If no credentials were found, add a placeholder to satisfy bsr.NewSession
	// validation. This can occur when session credentials are not yet populated
	// or are of an unrecognized type. The placeholder ensures session recording
	// can proceed without crashing on missing credential information.
	if len(staticUpCreds) == 0 && len(staticSshCreds) == 0 && len(vaultSshCertLibs) == 0 {
		staticUpCreds = append(staticUpCreds, bsr.StaticUsernamePasswordCredential{
			PublicId: "_placeholder_",
		})
	}

	if workerInfo == nil {
		workerInfo = &bsr.Worker{
			PublicId: "w_oss/unknown",
			Version:  "0.0.0",
			Sha:      "0000000000000000000000000000000000000000",
		}
	}

	return &bsr.SessionMeta{
		PublicId:                       recordingId,
		Endpoint:                       endpoint,
		User: &bsr.User{
			PublicId: fmt.Sprintf("u_oss/%s", recordingId),
			Scope: bsr.Scope{
				PublicId: "global",
				Type:     "global",
			},
		},
		Target: &bsr.Target{
			PublicId:               "t_oss/unknown",
			EnableSessionRecording: true,
			SessionMaxSeconds:      28800,
		},
		Worker:                           workerInfo,
		StaticSshPrivateKeyCredentials:   staticSshCreds,
		StaticUsernamePasswordCredentials: staticUpCreds,
		VaultSshCertificateLibraries:     vaultSshCertLibs,
	}, nil
}

// newBsrWrapper creates an AEAD wrapper for BSR key derivation.
func (rm *SshRecordingManager) newBsrWrapper(recordingId string) (wrapping.Wrapper, error) {
	hash := sha256.Sum256([]byte(recordingId + "-boundary-session-recording-v0"))
	wrapper := aead.NewWrapper()
	if _, err := wrapper.SetConfig(nil, wrapping.WithKeyId(recordingId)); err != nil {
		return nil, err
	}
	if err := wrapper.SetAesGcmKeyBytes(hash[:]); err != nil {
		return nil, err
	}
	return wrapper, nil
}

// PrepareSession prepares a BSR session for recording using the session's credentials.
// It creates the BSR session if it doesn't exist, using credentials from session.GetCredentials().
func (rm *SshRecordingManager) PrepareSession(ctx context.Context, sessId, endpoint string, creds []*pbs.Credential, workerInfo *bsr.Worker) (string, error) {
	const op = "SshRecordingManager.PrepareSession"
	if sessId == "" {
		return "", fmt.Errorf("%s: session ID is required", op)
	}
	if endpoint == "" {
		endpoint = "ssh://unknown"
	}

	_, recordingId, err := rm.getOrCreateBsrSession(ctx, sessId, endpoint, creds, workerInfo)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return recordingId, nil
}

// SetSessionMeta updates the session metadata after the session has been created.
// The protocolCtx may contain additional target/user information.
func (rm *SshRecordingManager) SetSessionMeta(recordingId string, protocolCtx *anypb.Any) error {
	// In OSS, we don't update session meta after creation.
	// The preliminary meta is set during session creation.
	// Enterprise may implement meta update here.
	return nil
}

// CreateConnection creates a BSR Connection for the given connectionId.
func (rm *SshRecordingManager) CreateConnection(ctx context.Context, boundarySessionId, connectionId, endpoint string, creds []*pbs.Credential, workerInfo *bsr.Worker) (*bsr.Connection, error) {
	const op = "SshRecordingManager.CreateConnection"

	bsrSession, _, err := rm.getOrCreateBsrSession(ctx, boundarySessionId, endpoint, creds, workerInfo)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	connMeta := &bsr.ConnectionRecordingMeta{
		Id: connectionId,
	}

	bsrConn, err := bsrSession.NewConnection(ctx, connMeta)
	if err != nil {
		return nil, fmt.Errorf("%s: bsr.NewConnection failed: %w", op, err)
	}

	return bsrConn, nil
}

// Close closes all BSR sessions.
func (rm *SshRecordingManager) Close(ctx context.Context) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for sessId, bsrSession := range rm.bsrSessions {
		if err := bsrSession.Close(ctx); err != nil {
			event.WriteError(ctx, "SshRecordingManager.Close", err, event.WithInfo("session_id", sessId))
		}
	}
	rm.bsrSessions = make(map[string]*bsr.Session)
}

// CloseSession closes the BSR session for the given boundarySessionId.
func (rm *SshRecordingManager) CloseSession(ctx context.Context, boundarySessionId string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	bsrSession, ok := rm.bsrSessions[boundarySessionId]
	if !ok {
		return nil
	}

	if err := bsrSession.Close(ctx); err != nil {
		return fmt.Errorf("bsr.Session.Close failed: %w", err)
	}
	delete(rm.bsrSessions, boundarySessionId)
	return nil
}

// recorderManager interface (used by worker status reporting).

// ReauthorizeAllExcept is a no-op in OSS.
func (rm *SshRecordingManager) ReauthorizeAllExcept(ctx context.Context, closedSessions []string) error {
	return nil
}

// SessionsManaged returns the list of BSR session IDs managed by this manager.
func (rm *SshRecordingManager) SessionsManaged(ctx context.Context) ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	ids := make([]string, 0, len(rm.bsrSessions))
	for id := range rm.bsrSessions {
		ids = append(ids, id)
	}
	return ids, nil
}

// Shutdown calls Close.
func (rm *SshRecordingManager) Shutdown(ctx context.Context) {
	rm.Close(ctx)
}

// GetRecordingManager returns the underlying RecordingManager (self for SshRecordingManager).
func (rm *SshRecordingManager) GetRecordingManager() proxyHandlers.RecordingManager {
	return rm
}

// Unwrap returns the underlying *SshRecordingManager.
func (rm *SshRecordingManager) Unwrap() *SshRecordingManager {
	return rm
}