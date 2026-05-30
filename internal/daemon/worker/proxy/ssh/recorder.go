// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
)

// ConnectionRecorder wraps a BSR Connection and provides thread-safe methods
// for emitting SSH data chunks in both directions. It manages the underlying
// BSR writers and tracks byte counts.
type ConnectionRecorder struct {
	conn      *bsr.Connection
	ts        *bsr.Timestamp
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64

	// encoders are created lazily on first chunk emission.
	encUp   *bsr.ChunkEncoder
	encDown *bsr.ChunkEncoder
	encMu   sync.Mutex // protects encoder initialization
}

// newConnectionRecorder wraps an existing BSR connection for recording.
func newConnectionRecorder(conn *bsr.Connection) *ConnectionRecorder {
	return &ConnectionRecorder{
		conn: conn,
		ts:   bsr.NewTimestamp(time.Now()),
	}
}

// EmitDataChunk writes a raw SSH data chunk (channel data, extended data, or
// raw message bytes) to the appropriate BSR messages writer. It is safe for
// concurrent calls. Data is encoded with gzip compression.
func (cr *ConnectionRecorder) EmitDataChunk(dir bsr.Direction, data []byte) error {
	if cr.conn == nil || len(data) == 0 {
		return nil
	}

	// Lazily initialize the chunk encoder for this direction.
	if err := cr.ensureEncoder(dir); err != nil {
		return err
	}

	// Create the BSR chunk.
	chunk, err := ssh.NewDataChunk(context.Background(), dir, cr.ts, data)
	if err != nil {
		return err
	}

	// Encode and write.
	var enc *bsr.ChunkEncoder
	switch dir {
	case bsr.Outbound:
		enc = cr.encUp
	case bsr.Inbound:
		enc = cr.encDown
	}
	if enc == nil {
		return nil
	}

	_, err = enc.Encode(context.Background(), chunk)
	if err != nil {
		return err
	}

	// Update byte counts.
	switch dir {
	case bsr.Outbound:
		cr.bytesUp.Add(uint64(len(data)))
	case bsr.Inbound:
		cr.bytesDown.Add(uint64(len(data)))
	}

	return nil
}

// ensureEncoder lazily creates the ChunkEncoder for the given direction.
func (cr *ConnectionRecorder) ensureEncoder(dir bsr.Direction) error {
	cr.encMu.Lock()
	defer cr.encMu.Unlock()

	switch dir {
	case bsr.Outbound:
		if cr.encUp != nil {
			return nil
		}
		w, err := cr.conn.NewMessagesWriter(context.Background(), bsr.Outbound)
		if err != nil {
			return err
		}
		cr.encUp, err = bsr.NewChunkEncoder(context.Background(), w, bsr.GzipCompression, bsr.NoEncryption)
		return err

	case bsr.Inbound:
		if cr.encDown != nil {
			return nil
		}
		w, err := cr.conn.NewMessagesWriter(context.Background(), bsr.Inbound)
		if err != nil {
			return err
		}
		cr.encDown, err = bsr.NewChunkEncoder(context.Background(), w, bsr.GzipCompression, bsr.NoEncryption)
		return err
	}

	return nil
}

// Close finalizes the connection recording: closes encoders and the BSR connection.
func (cr *ConnectionRecorder) Close(ctx context.Context) error {
	var errs []error

	if cr.encUp != nil {
		if err := cr.encUp.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if cr.encDown != nil {
		if err := cr.encDown.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if cr.conn != nil {
		if err := cr.conn.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// BytesUp returns the total bytes sent from client to target.
func (cr *ConnectionRecorder) BytesUp() uint64 {
	return cr.bytesUp.Load()
}

// BytesDown returns the total bytes sent from target to client.
func (cr *ConnectionRecorder) BytesDown() uint64 {
	return cr.bytesDown.Load()
}

// AddBytes atomically adds to the byte counters.
func (cr *ConnectionRecorder) AddBytes(up, down uint64) {
	cr.bytesUp.Add(up)
	cr.bytesDown.Add(down)
}