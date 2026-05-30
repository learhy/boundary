// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
)

// InterceptingPipe manages bidirectional data transfer between client and target
// SSH connections while recording BSR chunks. It uses InterceptingConn to
// intercept read/write operations and emit DataChunks.
type InterceptingPipe struct {
	clientConn  *InterceptingConn
	targetConn  *InterceptingConn
	pipeBufSize int
	closeOnce   sync.Once
	closeErr    error
}

// NewInterceptingPipe creates a new InterceptingPipe wrapping the client and target connections.
// Both connections are wrapped in InterceptingConn to record BSR DataChunks.
func NewInterceptingPipe(clientConn, targetConn net.Conn, rec *ConnectionRecorder) *InterceptingPipe {
	return &InterceptingPipe{
		clientConn:  NewInterceptingConn(clientConn, bsr.DirectionFromClient, rec),
		targetConn:  NewInterceptingConn(targetConn, bsr.DirectionFromTarget, rec),
		pipeBufSize: 32 * 1024,
	}
}

// Run starts the bidirectional copy. It blocks until both directions complete
// or the context is cancelled. Errors from either direction are collected and
// returned once both have completed.
func (p *InterceptingPipe) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Client → Target
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, p.pipeBufSize)
		n, err := io.CopyBuffer(p.targetConn, p.clientConn, buf)
		_ = n
		errCh <- err
	}()

	// Target → Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, p.pipeBufSize)
		n, err := io.CopyBuffer(p.clientConn, p.targetConn, buf)
		_ = n
		errCh <- err
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		p.Close()
		return ctx.Err()
	case <-done:
		// Collect errors from both directions
		var errs []error
		for i := 0; i < 2; i++ {
			select {
			case err := <-errCh:
				if err != nil && err != io.EOF {
					errs = append(errs, err)
				}
			default:
			}
		}
		if len(errs) > 0 {
			return errs[0]
		}
		return nil
	}
}

// Close gracefully closes both connections.
func (p *InterceptingPipe) Close() {
	p.closeOnce.Do(func() {
		if p.clientConn != nil {
			p.clientConn.Close()
		}
		if p.targetConn != nil {
			p.targetConn.Close()
		}
	})
}

// InterceptingConn wraps a net.Conn and emits BSR DataChunks for all
// data read from or written to the underlying connection.
type InterceptingConn struct {
	net.Conn
	dir  bsr.Direction
	rec  *ConnectionRecorder
	mu   sync.Mutex
}

// NewInterceptingConn wraps a net.Conn with BSR recording.
// All data read from or written to the returned conn is recorded as DataChunks.
func NewInterceptingConn(conn net.Conn, dir bsr.Direction, rec *ConnectionRecorder) *InterceptingConn {
	return &InterceptingConn{
		Conn: conn,
		dir:  dir,
		rec:  rec,
	}
}

// Read intercepts data read from the underlying connection and records it as a BSR DataChunk.
func (c *InterceptingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.rec != nil {
		data := make([]byte, n)
		copy(data, b[:n])
		c.emitDataChunk(data)
	}
	return n, err
}

// Write intercepts data written to the underlying connection and records it as a BSR DataChunk.
func (c *InterceptingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.rec != nil {
		data := make([]byte, n)
		copy(data, b[:n])
		c.emitDataChunk(data)
	}
	return n, err
}

// Close closes the underlying connection.
func (c *InterceptingConn) Close() error {
	return c.Conn.Close()
}

// emitDataChunk creates and writes a BSR DataChunk for the given data.
func (c *InterceptingConn) emitDataChunk(data []byte) {
	if c.rec == nil || len(data) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ts := bsr.NewTimestamp(time.Now())
	chunk, err := ssh.NewDataChunk(context.Background(), c.dir, ts, data)
	if err != nil {
		return
	}

	_ = c.rec.WriteMessage(context.Background(), c.dir, chunk)
}