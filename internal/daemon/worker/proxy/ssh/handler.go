// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/types/known/anypb"
)

// handleProxy establishes an SSH proxy between a client connection and an SSH target,
// intercepting SSH messages to emit BSR session recording chunks.
func handleProxy(
	controlCtx context.Context,
	_ context.Context,
	_ proxy.DecryptFn,
	clientConn net.Conn,
	pd *proxy.ProxyDialer,
	connId string,
	protocolCtx *anypb.Any,
	rm proxy.RecordingManager,
) (proxy.ProxyConnFn, error) {
	const op = "ssh.handleProxy"

	switch {
	case clientConn == nil:
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "client connection is nil")
	case pd == nil:
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "proxy dialer is nil")
	case connId == "":
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "connection id is empty")
	}

	// Get the SSH recording manager if recording is enabled.
	var rec *SshRecordingManager
	if rm != nil {
		var ok bool
		rec, ok = rm.(*SshRecordingManager)
		if !ok {
			rec = nil
		}
	}

	// Open the target SSH connection.
	targetConn, err := pd.Dial(controlCtx)
	if err != nil {
		return nil, errors.Wrap(controlCtx, op, err, errors.InvalidParameter, "failed to dial SSH target")
	}

	// Determine the session ID from the connection ID.
	// Connection IDs have the form "cr_<uuid>", session ID is embedded in the
	// session lookup done by the worker before calling this handler.
	// We derive it from the connection ID prefix: s_<uuid> from cr_<uuid>.
	sessionId := deriveSessionId(connId)

	// Set up recording if enabled.
	var connRecorder *ConnectionRecorder
	if rec != nil && sessionId != "" {
		connRecorder, err = rec.CreateConnection(controlCtx, sessionId, connId)
		if err != nil {
			targetConn.Close()
			clientConn.Close()
			return nil, errors.Wrap(controlCtx, op, err, errors.InvalidParameter, "failed to create BSR connection recording")
		}

		// Wire session metadata from protocolCtx if available.
		// protocolCtx contains the controller-sent session context as a protobuf Any.
		// Unmarshaling is a no-op if protocolCtx is nil or the wrong type.
		if protocolCtx != nil {
			sessionMeta := &bsr.SessionMeta{PublicId: sessionId}
			if err := protocolCtx.UnmarshalTo(sessionMeta); err == nil {
				if err := rec.SetSessionMeta(controlCtx, sessionId, sessionMeta); err != nil {
					rec.logger.Warn("failed to set session meta", "session_id", sessionId, "error", err)
				}
			}
		}
	}

	// Build the intercepting pipe.
	pipe := newPipe(clientConn, targetConn, connRecorder)

	// Return the ProxyConnFn that runs the bidirectional copy loop.
	return func() {
		pipe.run(controlCtx)
	}, nil
}

// deriveSessionId extracts the session ID from a connection ID.
// Connection IDs have the form "cr_<uuid>". The session ID has the form "s_<uuid>"
// where the uuid portion matches.
func deriveSessionId(connId string) string {
	if len(connId) < 4 || connId[:3] != "cr_" {
		return ""
	}
	// Connection ID: cr_<session_uuid>
	// Session ID:    s_<session_uuid>
	return "s_" + connId[3:]
}

// pipe implements the Option B bidirectional copy architecture for SSH.
// It wraps a client↔target connection pair, intercepts SSH messages from the client
// to emit BSR chunks, and performs bidirectional byte copy.
type pipe struct {
	clientConn  net.Conn // SSH client connection
	targetConn  net.Conn // SSH target connection
	connRecorder *ConnectionRecorder

	// wg synchronizes the two copy goroutines.
	wg sync.WaitGroup

	// closeOnce ensures the underlying connections are closed exactly once.
	closeOnce sync.Once
}

func newPipe(clientConn, targetConn net.Conn, connRecorder *ConnectionRecorder) *pipe {
	return &pipe{
		clientConn:   clientConn,
		targetConn:   targetConn,
		connRecorder: connRecorder,
	}
}

// run executes bidirectional copy. SSH messages from the client are intercepted
// via InterceptingConn.Read and emitted as BSR chunks. Plain byte data (STDIN)
// is copied transparently via PlainCopy.
// The function blocks until both directions complete or an error occurs.
func (p *pipe) run(ctx context.Context) {
	if p.connRecorder != nil {
		p.wg.Add(2)
		go p.copyClientToTarget(ctx)
		go p.copyTargetToClient(ctx)
		p.wg.Wait()
	} else {
		// No recording: plain bidirectional copy.
		p.wg.Add(2)
		go p.plainCopy(p.clientConn, p.targetConn, "client→target")
		go p.plainCopy(p.targetConn, p.clientConn, "target→client")
		p.wg.Wait()
	}
	p.close()
}

// copyClientToTarget reads SSH messages from the client, emits BSR chunks,
// and forwards data to the target. STDIN data (channel data messages) are
// copied via plainCopy semantics (no chunk emission for raw data).
func (p *pipe) copyClientToTarget(ctx context.Context) {
	defer p.wg.Done()

	ic := newInterceptingConn(p.clientConn, p.connRecorder, bsr.Outbound)

	// Use a buffer pool for efficiency.
	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := ic.Read(buf)
		if n > 0 {
			_, writeErr := p.targetConn.Write(buf[:n])
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, errSSHDataCopy) {
				return
			}
			return
		}
	}
}

// copyTargetToClient reads responses from the target and forwards to the client.
// BSR chunks are emitted for responses to channel requests (exit status, etc.).
func (p *pipe) copyTargetToClient(ctx context.Context) {
	defer p.wg.Done()

	ic := newInterceptingConn(p.targetConn, p.connRecorder, bsr.Inbound)

	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := ic.Read(buf)
		if n > 0 {
			_, writeErr := p.clientConn.Write(buf[:n])
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, errSSHDataCopy) {
				return
			}
			return
		}
	}
}

// errSSHDataCopy is used internally to signal that a plain data copy completed
// without producing a parsed SSH message (e.g., channel data).
var errSSHDataCopy = errors.New("ssh: plain data copy, no message parsed")

// plainCopy performs a straightforward io.Copy between two connections.
// Used for raw channel data that doesn't need BSR chunk emission.
func (p *pipe) plainCopy(src, dst net.Conn, direction string) {
	defer p.wg.Done()

	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	// EOF or read error is expected on connection close.
	_ = direction // reserved for future debug logging
}

// close closes both underlying connections exactly once.
func (p *pipe) close() {
	p.closeOnce.Do(func() {
		_ = p.clientConn.Close()
		_ = p.targetConn.Close()
		if p.connRecorder != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = p.connRecorder.Close(ctx)
		}
	})
}

// copyBufPool is a shared buffer pool for io.Copy operations.
// Each buffer is 32 KiB — large enough for SSH packets, not excessive.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return b
	},
}