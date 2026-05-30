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
}

// Protocol is the protocol string used to register the SSH handler.
const Protocol = "ssh"