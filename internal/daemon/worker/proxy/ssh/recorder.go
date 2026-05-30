// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
	proxyHandlers "github.com/hashicorp/boundary/internal/daemon/worker/proxy"
)

// Compression is the compression type for BSR chunk encoding.
type Compression int

const (
	CompressionNone Compression = iota
	CompressionZstd
)

// writerState holds the writer and encoder for a given direction.
type writerState struct {
	writer io.WriteCloser
	enc    *bsr.ChunkEncoder
}

// ConnectionRecorder records SSH connection data to the BSR.
type ConnectionRecorder struct {
	bsrConn *bsr.Connection
	mu      sync.RWMutex
	msgWriters map[bsr.Direction]*writerState
}

// NewConnectionRecorder creates a new ConnectionRecorder for the given BSR connection.
func NewConnectionRecorder(ctx context.Context, bsrConn *bsr.Connection, compress Compression) (*ConnectionRecorder, error) {
	if bsrConn == nil {
		return nil, fmt.Errorf("bsr connection is required")
	}

	cr := &ConnectionRecorder{
		bsrConn:     bsrConn,
		msgWriters:  make(map[bsr.Direction]*writerState),
	}

	// Create writers for both directions
	for _, dir := range []bsr.Direction{bsr.Inbound, bsr.Outbound} {
		w, err := bsrConn.NewMessagesWriter(ctx, dir)
		if err != nil {
			cr.Close(ctx)
			return nil, fmt.Errorf("failed to create messages writer for %s: %w", dir, err)
		}

		enc, err := bsr.NewChunkEncoder(ctx, w, bsr.Compression(compress), bsr.NoEncryption)
		if err != nil {
			cr.Close(ctx)
			return nil, fmt.Errorf("failed to create chunk encoder: %w", err)
		}
		cr.msgWriters[dir] = &writerState{
			writer: w,
			enc:    enc,
		}
	}

	return cr, nil
}

// WriteMessage writes a connection-level message chunk to the BSR.
func (cr *ConnectionRecorder) WriteMessage(ctx context.Context, dir bsr.Direction, chunk bsr.Chunk) error {
	cr.mu.RLock()
	state, ok := cr.msgWriters[dir]
	cr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no writer for direction %s", dir)
	}
	_, err := state.enc.Encode(ctx, chunk)
	return err
}

// WriteDataChunk writes a DataChunk to the BSR for the given direction.
func (cr *ConnectionRecorder) WriteDataChunk(ctx context.Context, dir bsr.Direction, data []byte) error {
	cr.mu.RLock()
	state, ok := cr.msgWriters[dir]
	cr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no writer for direction %s", dir)
	}

	ts := bsr.NewTimestamp(time.Now())
	chunk, err := ssh.NewDataChunk(ctx, dir, ts, data)
	if err != nil {
		return fmt.Errorf("failed to create data chunk: %w", err)
	}

	_, err = state.enc.Encode(ctx, chunk)
	return err
}

// Close closes the connection recorder and all underlying writers.
func (cr *ConnectionRecorder) Close(ctx context.Context) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for dir, state := range cr.msgWriters {
		if state.writer != nil {
			if err := state.writer.Close(ctx); err != nil {
				// Log but don't fail
				_ = fmt.Errorf("closing writer for %s: %w", dir, err)
			}
		}
	}
	cr.msgWriters = make(map[bsr.Direction]*writerState)

	if cr.bsrConn != nil {
		if err := cr.bsrConn.Close(ctx); err != nil {
			_ = fmt.Errorf("closing bsr connection: %w", err)
		}
		cr.bsrConn = nil
	}
}

// ChannelRecorder records SSH channel data to the BSR.
// It wraps a BSR Channel and provides typed write methods for channel chunks.
type ChannelRecorder struct {
	bsrCh   *bsr.Channel
	mu      sync.RWMutex
	dataWriters map[bsr.Direction]*writerState
	reqWriters  map[bsr.Direction]*bsr.ChunkEncoder
}

// NewChannelRecorder creates a new ChannelRecorder for the given BSR channel.
func NewChannelRecorder(ctx context.Context, bsrCh *bsr.Channel, compress Compression) (*ChannelRecorder, error) {
	if bsrCh == nil {
		return nil, fmt.Errorf("bsr channel is required")
	}

	cr := &ChannelRecorder{
		bsrCh:        bsrCh,
		dataWriters: make(map[bsr.Direction]*writerState),
		reqWriters:  make(map[bsr.Direction]*bsr.ChunkEncoder),
	}

	// Create data writers for both directions
	for _, dir := range []bsr.Direction{bsr.Inbound, bsr.Outbound} {
		w, err := bsrCh.NewMessagesWriter(ctx, dir)
		if err != nil {
			cr.Close(ctx)
			return nil, fmt.Errorf("failed to create messages writer for %s: %w", dir, err)
		}
		enc, err := bsr.NewChunkEncoder(ctx, w, bsr.Compression(compress), bsr.NoEncryption)
		if err != nil {
			cr.Close(ctx)
			return nil, fmt.Errorf("failed to create data chunk encoder: %w", err)
		}
		cr.dataWriters[dir] = &writerState{
			writer: w,
			enc:    enc,
		}

		// Create separate request writer
		reqEnc, err := bsr.NewChunkEncoder(ctx, w, bsr.Compression(compress), bsr.NoEncryption)
		if err != nil {
			cr.Close(ctx)
			return nil, fmt.Errorf("failed to create request chunk encoder: %w", err)
		}
		cr.reqWriters[dir] = reqEnc
	}

	return cr, nil
}

// WriteData writes a DataChunk to the BSR for the given direction.
func (cr *ChannelRecorder) WriteData(ctx context.Context, dir bsr.Direction, data []byte) error {
	cr.mu.RLock()
	state, ok := cr.dataWriters[dir]
	cr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no data writer for direction %s", dir)
	}

	ts := bsr.NewTimestamp(time.Now())
	chunk, err := ssh.NewDataChunk(ctx, dir, ts, data)
	if err != nil {
		return fmt.Errorf("failed to create data chunk: %w", err)
	}

	_, err = state.enc.Encode(ctx, chunk)
	return err
}

// WriteRequest writes a request chunk to the BSR for the given direction.
func (cr *ChannelRecorder) WriteRequest(ctx context.Context, dir bsr.Direction, chunk bsr.Chunk) error {
	cr.mu.RLock()
	enc, ok := cr.reqWriters[dir]
	cr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no request writer for direction %s", dir)
	}
	_, err := enc.Encode(ctx, chunk)
	return err
}

// WriteChannelMeta writes a channel metadata chunk to the BSR.
func (cr *ChannelRecorder) WriteChannelMeta(ctx context.Context, dir bsr.Direction, chunk bsr.Chunk) error {
	cr.mu.RLock()
	state, ok := cr.dataWriters[dir]
	cr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no data writer for direction %s", dir)
	}
	_, err := state.enc.Encode(ctx, chunk)
	return err
}

// Close closes the channel recorder.
func (cr *ChannelRecorder) Close(ctx context.Context) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for _, state := range cr.dataWriters {
		if state.writer != nil {
			state.writer.Close(ctx)
		}
	}
	cr.dataWriters = make(map[bsr.Direction]*writerState)
	cr.reqWriters = make(map[bsr.Direction]*bsr.ChunkEncoder)

	if cr.bsrCh != nil {
		cr.bsrCh = nil
	}
}

// ProxyConnFn is called after the call to ConnectConnection on the cluster.
// ProxyConnFn blocks until the specific request that is being proxied is finished.
type ProxyConnFn = proxyHandlers.ProxyConnFn