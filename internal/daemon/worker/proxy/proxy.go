// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

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
func typeUrlDispatcher(_ string, protocolCtx proto.Message) (Handler, error) {
	if protocolCtx == nil {
		// No protocol context: fall back to TCP (legacy behaviour)
		return getTcpHandler()
	}

	typeUrl := protocolCtx.ProtoReflect().Descriptor().FullName()
	key, ok := typeUrlToHandler[string(typeUrl)]
	if ok {
		handler, ok := handlers.Load(key)
		if !ok {
			// Handler key registered but handler not yet loaded (init order)
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


