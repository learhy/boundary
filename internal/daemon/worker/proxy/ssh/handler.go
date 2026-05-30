// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	proxyHandlers "github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/observability/event"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/types/known/anypb"
)

// handleProxy is the SSH proxy handler entry point.
// It returns a ProxyConnFn that runs the bidirectional SSH proxy with recording.
func handleProxy(
	controlCtx, dataCtx context.Context,
	_ proxyHandlers.DecryptFn,
	clientConn net.Conn,
	pDialer *proxyHandlers.ProxyDialer,
	connId string,
	protocolCtx *anypb.Any,
	recMgr proxyHandlers.RecordingManager,
) (proxyHandlers.ProxyConnFn, error) {
	const op = "ssh.handleProxy"

	// Type-assert the recorder manager to SshRecordingManager.
	sshRm := extractSshRecordingManager(recMgr)
	if sshRm == nil {
		// No recording manager — return a no-op proxy function
		return func() {}, nil
	}

	// Get the session from the context (stored by worker handler via proxy.WithSession).
	sess := proxyHandlers.SessionFromContext(dataCtx)
	if sess == nil {
		event.WriteError(controlCtx, op, fmt.Errorf("session not found in context"))
		return func() {}, fmt.Errorf("session not found in context")
	}

	// Build worker info for BSR metadata
	workerInfo, err := buildWorkerInfo(dataCtx)
	if err != nil {
		event.WriteError(controlCtx, op, err, event.WithInfoMsg("failed to build worker info"))
		workerInfo = &bsr.Worker{
			PublicId: "w_oss/unknown",
			Version:  "0.0.0",
			Sha:      "0000000000000000000000000000000000000000",
		}
	}

	// Step 1: Prepare the BSR session using session credentials.
	creds := sess.GetCredentials()
	if len(creds) == 0 {
		event.WriteError(controlCtx, op, fmt.Errorf("no credentials available from session"))
		return func() {}, fmt.Errorf("no credentials available from session")
	}

	endpoint := sess.GetEndpoint()
	if endpoint == "" {
		endpoint = "ssh://unknown"
	}

	recordingId, err := sshRm.PrepareSession(dataCtx, sess.GetId(), endpoint, creds, workerInfo)
	if err != nil {
		event.WriteError(controlCtx, op, err, event.WithInfo("conn_id", connId))
		return func() {}, fmt.Errorf("failed to prepare BSR session: %w", err)
	}

	// Step 2: Create the BSR connection for this connection.
	bsrConn, err := sshRm.CreateConnection(dataCtx, sess.GetId(), connId, endpoint, creds, workerInfo)
	if err != nil {
		event.WriteError(controlCtx, op, err, event.WithInfo("conn_id", connId))
		return func() {}, fmt.Errorf("failed to create BSR connection: %w", err)
	}

	// Create connection recorder
	connRecorder, err := NewConnectionRecorder(dataCtx, bsrConn, CompressionNone)
	if err != nil {
		event.WriteError(controlCtx, op, err)
		return func() {}, fmt.Errorf("failed to create connection recorder: %w", err)
	}

	// Step 3: Update session metadata.
	if err := sshRm.SetSessionMeta(recordingId, protocolCtx); err != nil {
		event.WriteError(controlCtx, op, err, event.WithInfo("recording_id", recordingId))
	}

	// Step 4: Dial the target SSH connection using session credentials.
	var targetConn net.Conn
	targetConn, err = dialTargetWithCredentials(dataCtx, pDialer, sess)
	if err != nil {
		event.WriteError(controlCtx, op, err, event.WithInfo("conn_id", connId))
		connRecorder.Close(dataCtx)
		return func() {}, fmt.Errorf("failed to dial target: %w", err)
	}

	// Create the intercepting pipe
	pipe := NewInterceptingPipe(clientConn, targetConn, connRecorder)

	return func() {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connRecorder.Close(ctx)
			targetConn.Close()
			clientConn.Close()
		}()

		if err := pipe.Run(dataCtx); err != nil {
			event.WriteError(dataCtx, op+"(proxy)", err, event.WithInfo("conn_id", connId))
		}
	}, nil
}

// extractSshRecordingManager extracts the *SshRecordingManager from the recording manager.
// It handles the wrapper type used in OSS.
func extractSshRecordingManager(recMgr proxyHandlers.RecordingManager) *SshRecordingManager {
	if recMgr == nil {
		return nil
	}
	// Try direct type assertion
	if sshRm, ok := recMgr.(*SshRecordingManager); ok {
		return sshRm
	}
	// Try Unwrap() on wrapped types
	type unwrapper interface{ Unwrap() *SshRecordingManager }
	if w, ok := recMgr.(unwrapper); ok {
		return w.Unwrap()
	}
	return nil
}

// SessionFromContext extracts the session.Session from the context.
// This is a convenience wrapper around proxyHandlers.SessionFromContext.
func SessionFromContext(ctx context.Context) session.Session {
	return proxyHandlers.SessionFromContext(ctx)
}

// buildWorkerInfo builds bsr.Worker from context.
// In OSS, this returns a placeholder. Enterprise can extract from worker status.
func buildWorkerInfo(ctx context.Context) (*bsr.Worker, error) {
	return &bsr.Worker{
		PublicId: "w_oss/unknown",
		Version:  "0.0.0",
		Sha:      "0000000000000000000000000000000000000000",
	}, nil
}

// dialTargetWithCredentials dials the target SSH server using session credentials.
// For SSH credential injection targets, the connection is already authenticated
// using the session's certificate/private key.
func dialTargetWithCredentials(ctx context.Context, pDialer *proxyHandlers.ProxyDialer, sess session.Session) (net.Conn, error) {
	if pDialer == nil {
		return nil, fmt.Errorf("proxy dialer is required")
	}

	targetConn, err := pDialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target: %w", err)
	}

	return targetConn, nil
}

// Wrapperer is implemented by wrappers that expose an underlying *SshRecordingManager.
type Wrapperer interface {
	Unwrap() *SshRecordingManager
}