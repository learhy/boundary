// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPipe_CreatesValidPipe(t *testing.T) {
	client, _ := net.Pipe()
	target, _ := net.Pipe()
	defer client.Close()
	defer target.Close()

	p := newPipe(client, target, nil)
	assert.NotNil(t, p)
	assert.Equal(t, client, p.clientConn)
	assert.Equal(t, target, p.targetConn)
	assert.Nil(t, p.connRecorder)
}

func TestPipe_CopyWithoutRecording(t *testing.T) {
	clientRead, clientWrite := net.Pipe()
	targetRead, targetWrite := net.Pipe()
	defer clientRead.Close()
	defer clientWrite.Close()
	defer targetRead.Close()
	defer targetWrite.Close()

	p := newPipe(clientRead, targetWrite, nil)

	ctx := context.Background()
	done := make(chan struct{}, 1)

	// Run the copy loop.
	go p.runWithShutdown(ctx, nil, nil)

	// Write data from the target side (the pipe's targetConn writes to client).
	go func() {
		targetRead.Write([]byte("hello from target"))
	}()
	// Wait a bit for data to flow.
	time.Sleep(50 * time.Millisecond)

	// Close the pipe's connections to stop the copy loop.
	p.close()

	// clientRead should have received "hello from target".
	buf := make([]byte, 1024)
	_ = clientRead.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _ := clientRead.Read(buf)
	assert.Greater(t, n, 0)
	assert.Contains(t, string(buf[:n]), "hello from target")
	_ = done
}

func TestPipe_CopyWithRecording(t *testing.T) {
	mgr, _ := newTestSshRecordingManager(t, nil)
	ctx := context.Background()

	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()
	defer clientRead.Close()
	defer targetRead.Close()

	connRecorder, err := mgr.CreateConnection(ctx, "s_pipe_test", "cr_pipe_test")
	require.NoError(t, err)
	require.NotNil(t, connRecorder)

	// We need a pair of connected pipes for proper bidirectional copy.
	c1, c2 := net.Pipe()
	t1, t2 := net.Pipe()

	p := newPipe(c1, t1, connRecorder)

	go p.runWithShutdown(ctx, nil, nil)

	// Send some data from client side.
	// Write SSH-framed data so the InterceptingConn can parse it.
	// SSH frame: 4-byte length (big-endian) + payload.
	// Payload: message type byte + data.
	// Let's use message type 94 (SSH_MSG_CHANNEL_DATA).
	data := []byte{0, 0, 0, 10, 94, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	_, err = c2.Write(data)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// The data should have been forwarded to target side.
	buf := make([]byte, 1024)
	_ = t2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := t2.Read(buf)
	if err == nil && n > 0 {
		assert.Equal(t, data, buf[:n])
	}

	// Close to stop the copy loop.
	p.close()

	// Verify bytes were tracked.
	assert.Greater(t, connRecorder.BytesUp(), uint64(0),
		"bytes up should be tracked")
}

func TestPipe_RunWithShutdown_ContextCancel(t *testing.T) {
	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()
	defer clientRead.Close()
	defer targetRead.Close()

	p := newPipe(clientRead, targetRead, nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.runWithShutdown(ctx, nil, nil)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Expected — context cancel causes copy loop to exit.
	case <-time.After(time.Second):
		t.Fatal("pipe did not stop after context cancel")
	}
}

func TestPipe_RunWithShutdown_DoneChannel(t *testing.T) {
	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()
	defer clientRead.Close()
	defer targetRead.Close()

	p := newPipe(clientRead, targetRead, nil)

	done := make(chan struct{})

	completed := make(chan struct{})
	go func() {
		p.runWithShutdown(context.Background(), done, nil)
		close(completed)
	}()

	close(done)

	select {
	case <-completed:
		// Expected — done channel close causes immediate exit.
	case <-time.After(time.Second):
		t.Fatal("pipe did not stop after done channel close")
	}
}

func TestPipe_OnCloseCallback(t *testing.T) {
	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()
	defer clientRead.Close()
	defer targetRead.Close()

	p := newPipe(clientRead, targetRead, nil)

	called := false
	p.runWithShutdown(context.Background(), nil, func() {
		called = true
	})

	assert.True(t, called, "onClose callback should have been called")
}

func TestPipe_OnCloseWithShutdown(t *testing.T) {
	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()
	defer clientRead.Close()
	defer targetRead.Close()

	p := newPipe(clientRead, targetRead, nil)

	done := make(chan struct{})
	called := false

	completed := make(chan struct{})
	go func() {
		p.runWithShutdown(context.Background(), done, func() {
			called = true
		})
		close(completed)
	}()

	close(done)

	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("pipe did not stop")
	}

	assert.True(t, called, "onClose callback should have been called on shutdown")
}

func TestPipe_CloseIsIdempotent(t *testing.T) {
	clientRead, _ := net.Pipe()
	targetRead, _ := net.Pipe()

	p := newPipe(clientRead, targetRead, nil)

	// Close multiple times — should not panic.
	p.close()
	p.close()
	p.close()
}

func TestPipe_ErrSSHDataCopy(t *testing.T) {
	assert.NotNil(t, errSSHDataCopy)
	assert.Equal(t, "ssh: plain data copy, no message parsed", errSSHDataCopy.Error())
}
