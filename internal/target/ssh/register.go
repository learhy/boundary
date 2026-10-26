// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"math"
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/target/tcp/store"
)

type targetHooks struct{}

func init() {
	target.Register(Subtype, targetHooks{}, TargetPrefix)
}

const (
	// TargetPrefix is the prefix for public ids of a ssh.Target.
	TargetPrefix = "tssh"
)

// NewTarget creates a new in-memory ssh target. It delegates the actual
// construction to the registered tcp hook (via target.New) and wraps the
// result so the SSH and TCP subtypes share the same physical storage
// layout (target_tcp table).
func (h targetHooks) NewTarget(ctx context.Context, projectId string, opt ...target.Option) (target.Target, error) {
	const op = "ssh.NewTarget"
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	t, err := target.New(ctx, tcp.Subtype, projectId, opt...)
	if err != nil {
		return nil, err
	}
	return &Target{Target: t.(*tcp.Target)}, nil
}

// AllocTarget allocates a new empty ssh target backed by a tcp.Target.
// It always returns a non-nil *Target; the embedded *tcp.Target is also
// non-nil so gorm can call TableName on it safely.
func (h targetHooks) AllocTarget() target.Target {
	return &Target{
		Target: &tcp.Target{
			Target: &store.Target{},
		},
	}
}

// Vet validates that the given target.Target is a ssh.Target and that it
// has a Target store.
func (h targetHooks) Vet(ctx context.Context, t target.Target) error {
	const op = "ssh.vet"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a ssh.Target")
	}

	if tt == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}

	if tt.Target == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}
	if tt.GetDefaultPort() == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target default port")
	}
	if tt.GetDefaultPort() > math.MaxUint16 {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid default port number")
	}
	if tt.GetDefaultClientPort() > math.MaxUint16 {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid default client port number")
	}
	return nil
}

// VetForUpdate validates that the given target.Target is a ssh.Target,
// and that it has a Target store and that it isn't attempting to clear or
// set to zero the default port.
func (h targetHooks) VetForUpdate(ctx context.Context, t target.Target, paths []string) error {
	const op = "ssh.vetForUpdate"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a ssh.Target")
	}

	switch {
	case tt == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	case tt.Target == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}

	for _, f := range paths {
		if strings.EqualFold("defaultport", f) {
			if tt.GetDefaultPort() == 0 {
				return errors.New(ctx, errors.InvalidParameter, op, "clearing or setting default port to zero")
			}
			if tt.GetDefaultPort() > math.MaxUint16 {
				return errors.New(ctx, errors.InvalidParameter, op, "invalid default port number")
			}
		}
		if strings.EqualFold("defaultclientport", f) {
			if tt.GetDefaultClientPort() > math.MaxUint16 {
				return errors.New(ctx, errors.InvalidParameter, op, "invalid default client port number")
			}
		}
	}

	return nil
}

// VetCredentialSources checks that all the provided credential sources have a CredentialPurpose
// of BrokeredPurpose. Any other CredentialPurpose will result in an error.
func (h targetHooks) VetCredentialSources(ctx context.Context, libs []*target.CredentialLibrary, creds []*target.StaticCredential) error {
	const op = "ssh.VetCredentialSources"

	for _, c := range libs {
		if c.GetCredentialPurpose() != string(credential.BrokeredPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, "ssh.Target only supports brokered credentials")
		}
	}
	for _, c := range creds {
		if c.GetCredentialPurpose() != string(credential.BrokeredPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, "ssh.Target only supports brokered credentials")
		}
	}
	return nil
}
