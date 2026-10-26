// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// debugLog writes to /tmp/boundary-debug.log if that env var is set or the
// file is writable. Used for tracing the type-URL dispatcher flow.
func debugLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	f, err := os.OpenFile("/tmp/boundary-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(msg)
		_ = f.Sync()
		_ = f.Close()
	}
	// Also write to stderr so it shows up in the dev log
	fmt.Fprintf(os.Stderr, "[DEBUG] %s", msg)
}

var (
	TcpHandlerName = "tcp"

	// handlers is the map of registered handlers
	handlers sync.Map

	// ErrUnknownProtocol specifies the provided protocol has no registered handler
	ErrUnknownProtocol = errors.New("proxy: handler not found for protocol")

	// ErrProtocolAlreadyRegistered specifies the provided protocol has already been registered
	ErrProtocolAlreadyRegistered = errors.New("proxy: protocol already registered")

	// GetHandler returns the handler registered for the provided worker and
	// protocolContext. If a protocol cannot be determined or the protocol is
	// not registered nil, ErrUnknownProtocol is returned.
	GetHandler = typeUrlDispatcher
)

// typeUrlToHandler maps full type URL suffixes (package.MessageName) to handler keys.
// This is consulted before the generic handlers map so protocol-specific handlers
// take precedence over the TCP fallback.
var typeUrlToHandler = map[string]string{
	// controller.storage.v1.BucketContext is the protocol context sent by the
	// controller for all session connections. When the target has a storage
	// bucket configured (including for session recording), the controller sends
	// this context and the worker uses it to resolve the correct handler.
	// Handlers register themselves here by calling RegisterHandlerForTypeUrl.
	//
	// Protocol-specific contexts (e.g. SshProtocolContext for SSH targets with
	// session recording) should also be registered here by their respective
	// handler packages so that typeUrlDispatcher can route correctly.
}

// RegisterHandlerForTypeUrl registers a handler key for a specific type URL suffix.
// It is called by protocol-specific packages in their init() to associate their
// proto message type with the handler key they registered via RegisterHandler.
func RegisterHandlerForTypeUrl(typeUrlSuffix, handlerKey string) {
	typeUrlToHandler[typeUrlSuffix] = handlerKey
}

// typeUrlDispatcher resolves protocol handlers by examining the type URL of
// the protocol context. It first looks up the type URL suffix in typeUrlToHandler
// to find a registered handler key; if found, it returns that handler. If no
// match is found, it falls back to the TCP handler for backwards compatibility
// with pre-session-recording deployments.
func typeUrlDispatcher(workerId string, protocolCtx proto.Message) (Handler, error) {
	debugLog(">>> typeUrlDispatcher called workerId=%s protocolCtx=%T\n", workerId, protocolCtx)
	if protocolCtx == nil {
		debugLog(">>> protocolCtx is nil, falling back to TCP\n")
		// No protocol context: fall back to TCP (legacy behaviour)
		return getTcpHandler()
	}

	// Unwrap google.protobuf.Any to access the inner message's descriptor.
	// The controller sends protocol contexts wrapped in Any, so the raw
	// proto.Message we receive is *anypb.Any whose descriptor is the Any
	// type itself, not the inner message type. We need to extract the
	// type URL suffix (the part after the last slash) and look it up.
	if anyMsg, ok := protocolCtx.(*anypb.Any); ok {
		typeUrl := anyMsg.GetTypeUrl()
		debugLog("typeUrlDispatcher got Any with typeUrl=%q, value-len=%d\n", typeUrl, len(anyMsg.GetValue()))
		// Strip the "type.googleapis.com/" prefix to get the inner type name
		if i := strings.LastIndex(typeUrl, "/"); i >= 0 {
			typeUrl = typeUrl[i+1:]
		}
		debugLog("stripped typeUrl=%q, map=%v\n", typeUrl, typeUrlToHandler)
		if key, ok := typeUrlToHandler[typeUrl]; ok {
			handler, ok := handlers.Load(key)
			if !ok {
				return nil, ErrUnknownProtocol
			}
			return handler.(Handler), nil
		}
		// Inner type not recognized: fall through to TCP
		return getTcpHandler()
	}

	// Bare proto.Message path (not wrapped in Any): inspect the descriptor
	// directly. This is the case for tests that construct the inner type
	// directly.
	typeUrl := protocolCtx.ProtoReflect().Descriptor().FullName()
	key, ok := typeUrlToHandler[string(typeUrl)]
	if ok {
		handler, ok := handlers.Load(key)
		if !ok {
			return nil, ErrUnknownProtocol
		}
		return handler.(Handler), nil
	}

	// No type-url match: fall back to TCP for backwards compatibility
	return getTcpHandler()
}

// getTcpHandler is a helper that returns the registered TCP handler.
func getTcpHandler() (Handler, error) {
	handler, ok := handlers.Load(TcpHandlerName)
	if !ok {
		return nil, ErrUnknownProtocol
	}
	return handler.(Handler), nil
}

// tcpOnly is a GetHandler implementation that always returns the registered
// TCP handler, ignoring any protocol context. It is used by tests to verify
// the TCP-fallback path of the dispatcher in isolation.
func tcpOnly(_ string, _ proto.Message) (Handler, error) {
	debugLog("!!! tcpOnly called (this means dispatcher fell through)\n")
	return getTcpHandler()
}

// RecordingManager allows a handler for a protocol that supports recording.
type RecordingManager any

// DecryptFn decrypts the provided bytes into a proto.Message
type DecryptFn func(ctx context.Context, from []byte, to proto.Message) error

// ProxyConnFn is called after the call to ConnectConnection on the cluster.
// ProxyConnFn blocks until the specific request that is being proxied is finished
type ProxyConnFn func()

// Handler is the type that all proxies need to implement to be called by the worker
// when a new client connection is created.  If there is an error ProxyConnFn must
// be nil. If there is no error ProxyConnFn must be set.  When Handler has
// returned, it is expected that the initial connection to the endpoint has been
// established.
type Handler func(controlCtx context.Context, dataCtx context.Context, df DecryptFn, c net.Conn, pd *ProxyDialer, connId string, pb *anypb.Any, rm RecordingManager) (ProxyConnFn, error)

func RegisterHandler(protocol string, handler Handler) error {
	_, loaded := handlers.LoadOrStore(protocol, handler)
	if loaded {
		return ErrProtocolAlreadyRegistered
	}
	return nil
}


