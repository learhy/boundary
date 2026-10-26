// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestHandleProxy_NilClientConn(t *testing.T) {
	ctx := context.Background()
	fn, err := handleProxy(ctx, ctx, nil, nil, &proxy.ProxyDialer{}, "cr_test123", nil, nil)
	assert.Error(t, err)
	assert.Nil(t, fn)
	assert.Contains(t, err.Error(), "client connection is nil")
}

func TestHandleProxy_NilDialer(t *testing.T) {
	ctx := context.Background()
	fn, err := handleProxy(ctx, ctx, nil, &mockConn{}, nil, "cr_test123", nil, nil)
	assert.Error(t, err)
	assert.Nil(t, fn)
	assert.Contains(t, err.Error(), "proxy dialer is nil")
}

func TestHandleProxy_EmptyConnId(t *testing.T) {
	ctx := context.Background()
	fn, err := handleProxy(ctx, ctx, nil, &mockConn{}, &proxy.ProxyDialer{}, "", nil, nil)
	assert.Error(t, err)
	assert.Nil(t, fn)
	assert.Contains(t, err.Error(), "connection id is empty")
}

func TestHandleProxy_RateLimitExceeded(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	// Create a recording manager with very strict rate limiting (max 0).
	cfg := &SshRateLimitConfig{MaxConcurrentSessions: 1, MaxPerTarget: 1}
	rec := NewSshRecordingManager("/tmp/test", nil, nil, cfg, logger)

	// Acquire the only slot.
	rec.RateLimitAcquire(ctx, "s_test")

	fn, err := handleProxy(ctx, ctx, nil, &mockConn{}, &proxy.ProxyDialer{}, "cr_test123", nil, rec)
	assert.Error(t, err)
	assert.Nil(t, fn)
	assert.Contains(t, err.Error(), "ssh session rate limit exceeded")
}

func TestHandleProxy_DialFailureReleasesRateLimit(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()
	cfg := &SshRateLimitConfig{MaxConcurrentSessions: 1, MaxPerTarget: 1}
	rec := NewSshRecordingManager("/tmp/test", nil, nil, cfg, logger)

	// Create a dialer that will fail on Dial.
	pd, err := proxy.NewProxyDialer(ctx, func(...proxy.Option) (net.Conn, error) {
		return nil, assert.AnError
	})
	require.NoError(t, err)

	fn, err := handleProxy(ctx, ctx, nil, &mockConn{}, pd, "cr_test123", nil, rec)
	assert.Error(t, err)
	assert.Nil(t, fn)

	// Rate limit should have been released by the failed handleProxy.
	assert.True(t, rec.RateLimitAcquire(ctx, "s_test"),
		"rate limit should be acquirable after dial failure")
}

func TestHandleProxy_NoRecordingManagerReturnsValidFn(t *testing.T) {
	ctx := context.Background()

	client := &mockConn{}

	pd, err := proxy.NewProxyDialer(ctx, func(...proxy.Option) (net.Conn, error) {
		return &mockConn{}, nil
	})
	require.NoError(t, err)

	fn, err := handleProxy(ctx, ctx, nil, client, pd, "cr_test123", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, fn)

	// The returned fn should be callable.
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy function did not complete within timeout")
	}
}

func TestHandleProxy_WithRecordingManager(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	// Create a recording manager with a proper wrapper for BSR session creation.
	recordingsDir := t.TempDir()
	rootWrapper := aead.NewWrapper()
	_, err := rootWrapper.SetConfig(ctx, wrapping.WithKeyId("test-root-key"))
	require.NoError(t, err)
	err = rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)
	recordingStorage, err := storage.NewOssRecordingStorage(ctx, recordingsDir)
	require.NoError(t, err)
	rec := NewSshRecordingManager(recordingsDir, rootWrapper, recordingStorage, nil, logger)

	client := &mockConn{}

	pd, err := proxy.NewProxyDialer(ctx, func(...proxy.Option) (net.Conn, error) {
		return &mockConn{}, nil
	})
	require.NoError(t, err)

	fn, err := handleProxy(ctx, ctx, nil, client, pd, "cr_test123", nil, rec)
	assert.NoError(t, err)
	assert.NotNil(t, fn)

	// The returned fn should be callable.
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy function did not complete within timeout")
	}
}

func TestHandleProxy_WithProtocolCtx(t *testing.T) {
	ctx := context.Background()
	logger := hclog.NewNullLogger()

	// Create a recording manager with a proper wrapper for BSR session creation.
	recordingsDir := t.TempDir()
	rootWrapper := aead.NewWrapper()
	_, err := rootWrapper.SetConfig(ctx, wrapping.WithKeyId("test-root-key"))
	require.NoError(t, err)
	err = rootWrapper.SetAesGcmKeyBytes([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)
	recordingStorage, err := storage.NewOssRecordingStorage(ctx, recordingsDir)
	require.NoError(t, err)
	rec := NewSshRecordingManager(recordingsDir, rootWrapper, recordingStorage, nil, logger)

	client := &mockConn{}

	pd, err := proxy.NewProxyDialer(ctx, func(...proxy.Option) (net.Conn, error) {
		return &mockConn{}, nil
	})
	require.NoError(t, err)

	protocolCtx, err := anypb.New(&anypb.Any{})
	require.NoError(t, err)

	fn, err := handleProxy(ctx, ctx, nil, client, pd, "cr_test123", protocolCtx, rec)
	assert.NoError(t, err)
	assert.NotNil(t, fn)

	// Verify the session meta was set.
	sessions, err := rec.SessionsManaged(ctx)
	require.NoError(t, err)
	assert.Contains(t, sessions, "s_test123")

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()

	client.Write([]byte("test data"))
	client.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy function did not complete within timeout")
	}
}

// mockConn implements net.Conn for testing.
type mockConn struct {
	net.Conn
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}

// GetIp and GetPort implement the portAndIpGetter interface so that
// ProxyDialer.Dial() accepts mockConn.
func (m *mockConn) GetIp() string {
	return "127.0.0.1"
}

func (m *mockConn) GetPort() uint32 {
	return 22
}
