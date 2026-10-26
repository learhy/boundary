// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package ssh provides a Target subtype for an SSH Target.
//
// In OSS, the SSH target reuses the underlying target_tcp database table
// (analogous to the targettest package): SSH target attributes are
// functionally equivalent to TCP target attributes, so a separate physical
// table would be wasteful. The Subtype is "ssh" (prefix "tssh") but the
// TableName points at "target_tcp".
//
// Importing this package will register the ssh subtype with the target
// package and allow the target.Repository to support ssh.Targets.
package ssh

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

const (
	// Subtype is the target subtype for SSH.
	Subtype = subtypes.Subtype("ssh")
)

// Target is an SSH-flavored target.Target. It embeds *tcp.Target so
// that the underlying target_tcp table is reused, the storage layer
// is shared, and all inherited methods (Address, HostSources,
// CredentialSources, VetForWrite, Oplog) are available.
type Target struct {
	*tcp.Target
}

// GetType returns the SSH subtype. This overrides the embedded
// tcp.Target.GetType so the repository routes to the SSH registry
// entry (hooks, prefix) instead of the TCP one.
func (t *Target) GetType() subtypes.Subtype {
	return Subtype
}

// SetPublicId accepts SSH public IDs (prefix tssh_) and stores the
// original ID on the underlying target. The store column is text and
// not validated against the TCP prefix because the SSH target aliases
// the target_tcp table.
func (t *Target) SetPublicId(ctx context.Context, publicId string) error {
	const op = "ssh.(Target).SetPublicId"
	if !strings.HasPrefix(publicId, TargetPrefix+"_") {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", publicId, TargetPrefix))
	}
	t.Target.PublicId = publicId
	return nil
}

// Clone preserves the SSH wrapper around the cloned TCP target.
func (t *Target) Clone() target.Target {
	cl := t.Target.Clone()
	return &Target{Target: cl.(*tcp.Target)}
}

// TableName returns the tablename override (target_tcp). This is a
// re-declaration of the inherited tcp.Target.TableName so gorm sees a
// method on the outmost *ssh.Target rather than the embedded pointer.
func (t *Target) TableName() string {
	return "target_tcp"
}

// SetTableName is a no-op for the SSH target (the table is fixed at
// target_tcp). It exists to satisfy the ReplayableMessage interface.
func (t *Target) SetTableName(string) {}

// Oplog overrides the embedded tcp.Target.Oplog so the resource-type
// string is "ssh target" instead of "tcp target" in audit logs.
func (t *Target) Oplog(op oplog.OpType) oplog.Metadata {
	md := t.Target.Oplog(op)
	md["resource-type"] = []string{"ssh target"}
	return md
}
