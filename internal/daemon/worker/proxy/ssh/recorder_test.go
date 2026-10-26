// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConnectionRecorder_NilConn(t *testing.T) {
	rec := newConnectionRecorder(nil)
	assert.NotNil(t, rec)
	assert.Nil(t, rec.conn)
}

func TestConnectionRecorder_NewRecorder(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	bsrConn, err := mgr.CreateConnection(ctx, "s_rec_test", "cr_rec_test")
	require.NoError(t, err)
	require.NotNil(t, bsrConn)

	assert.Equal(t, uint64(0), bsrConn.BytesUp())
	assert.Equal(t, uint64(0), bsrConn.BytesDown())
}

func TestConnectionRecorder_EmitDataChunk(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_emit", "cr_emit")
	require.NoError(t, err)

	// Emit outbound data.
	err = rec.EmitDataChunk(bsr.Outbound, []byte("hello from client"))
	require.NoError(t, err)
	assert.Equal(t, uint64(16), rec.BytesUp())
	assert.Equal(t, uint64(0), rec.BytesDown())

	// Emit inbound data.
	err = rec.EmitDataChunk(bsr.Inbound, []byte("hello from server"))
	require.NoError(t, err)
	assert.Equal(t, uint64(16), rec.BytesUp())
	assert.Equal(t, uint64(16), rec.BytesDown())
}

func TestConnectionRecorder_EmitEmptyDataIsNoop(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_noop", "cr_noop")
	require.NoError(t, err)

	err = rec.EmitDataChunk(bsr.Outbound, nil)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), rec.BytesUp())

	err = rec.EmitDataChunk(bsr.Outbound, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), rec.BytesUp())
}

func TestConnectionRecorder_Close(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_close", "cr_close")
	require.NoError(t, err)

	// Emit some data to create encoders.
	err = rec.EmitDataChunk(bsr.Outbound, []byte("test data"))
	require.NoError(t, err)

	// Close the recorder.
	err = rec.Close(ctx)
	assert.NoError(t, err)
}

func TestConnectionRecorder_CloseWithoutEmit(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_close_noemit", "cr_close_noemit")
	require.NoError(t, err)

	// Close without ever emitting data — should still work (no encoders to close).
	err = rec.Close(ctx)
	assert.NoError(t, err)
}

func TestConnectionRecorder_AddBytes(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_bytes_rec", "cr_bytes_rec")
	require.NoError(t, err)

	rec.AddBytes(100, 200)
	assert.Equal(t, uint64(100), rec.BytesUp())
	assert.Equal(t, uint64(200), rec.BytesDown())

	rec.AddBytes(50, 75)
	assert.Equal(t, uint64(150), rec.BytesUp())
	assert.Equal(t, uint64(275), rec.BytesDown())
}

func TestConnectionRecorder_ConcurrentEmitDataChunk(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_concur_rec", "cr_concur_rec")
	require.NoError(t, err)

	const numGoroutines = 10
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := rec.EmitDataChunk(bsr.Outbound, []byte("concurrent data"))
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	// Each goroutine emitted 16 bytes.
	assert.Equal(t, uint64(16*numGoroutines), rec.BytesUp())
}

func TestConnectionRecorder_ConcurrentEmitBothDirections(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_concur_both", "cr_concur_both")
	require.NoError(t, err)

	const numGoroutines = 20
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			dir := bsr.Outbound
			if idx%2 == 0 {
				dir = bsr.Inbound
			}
			_ = rec.EmitDataChunk(dir, []byte("concurrent data both directions"))
		}(i)
	}
	wg.Wait()

	// 10 outbound, 10 inbound, each 32 bytes.
	assert.Equal(t, uint64(10*32), rec.BytesUp())
	assert.Equal(t, uint64(10*32), rec.BytesDown())
}

func TestConnectionRecorder_ConcurrentCloseAndEmit(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	rec, err := mgr.CreateConnection(ctx, "s_concur_close", "cr_concur_close")
	require.NoError(t, err)

	var wg sync.WaitGroup

	// Emit data in one goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_ = rec.EmitDataChunk(bsr.Outbound, []byte("data before close"))
		}
	}()

	// Close in another.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = rec.Close(ctx)
	}()

	wg.Wait()
	// Should not panic or hang.
}
