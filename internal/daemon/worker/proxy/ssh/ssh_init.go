// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	proxyHandlers "github.com/hashicorp/boundary/internal/daemon/worker/proxy"
)

func init() {
	// Register the SSH proxy handler for the "ssh" protocol scheme.
	proxyHandlers.RegisterHandler("ssh", handleProxy)
}