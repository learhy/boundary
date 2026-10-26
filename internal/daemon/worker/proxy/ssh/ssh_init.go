// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
)

func init() {
	if err := proxy.RegisterHandler(Protocol, handleProxy); err != nil {
		panic(err)
	}
	// Register the SshProtocolContext type URL so the type-URL dispatcher
	// routes connections to this handler when the controller sends an
	// SSH protocol context (used for SSH session recording).
	proxy.RegisterHandlerForTypeUrl("worker.proxy.v1.SshProtocolContext", Protocol)
}

// Protocol is the protocol string used to register the SSH handler.
const Protocol = "ssh"