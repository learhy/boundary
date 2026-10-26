// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"math"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/ssh"
	"github.com/hashicorp/boundary/internal/target/store"
	tcpStore "github.com/hashicorp/boundary/internal/target/tcp/store"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
)

const (
	defaultPortField               = "attributes.default_port"
	defaultClientPortField         = "attributes.default_client_port"
	storageBucketIdField           = "attributes.storage_bucket_id"
	enableSessionRecordingField    = "attributes.enable_session_recording"
)

// attribute wraps the SSH-specific proto attributes and exposes the targets
// Attributes interface required by the controller registry.
type attribute struct {
	*pb.SshTargetAttributes
}

func (a *attribute) Options() []target.Option {
	var opts []target.Option
	if a.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(a.GetDefaultPort().GetValue()))
	}
	if a.GetDefaultClientPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultClientPort(a.GetDefaultClientPort().GetValue()))
	}
	return opts
}

// Vet validates the inbound attributes and returns a field->message map for
// any validation failures.
func (a *attribute) Vet() map[string]string {
	badFields := map[string]string{}
	if a.GetDefaultPort() == nil {
		badFields[defaultPortField] = "This field is required."
	} else {
		if a.GetDefaultPort().GetValue() == 0 {
			badFields[defaultPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultPort().GetValue() > math.MaxUint16 {
			badFields[defaultPortField] = "Value is greater than maximum port number."
		}
	}
	if a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

// VetForUpdate validates the attributes for an update call against the
// provided field-mask paths.
func (a *attribute) VetForUpdate(p []string) map[string]string {
	badFields := map[string]string{}
	if handlers.MaskContains(p, defaultPortField) {
		if a.GetDefaultPort() == nil {
			badFields[defaultPortField] = "This field is required."
		} else {
			if a.GetDefaultPort().GetValue() == 0 {
				badFields[defaultPortField] = "This cannot be set to zero."
			}
			if a.GetDefaultPort().GetValue() > math.MaxUint16 {
				badFields[defaultPortField] = "Value is greater than maximum port number."
			}
		}
	}
	if handlers.MaskContains(p, defaultClientPortField) && a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

// newAttribute allocates an attribute wrapper for the given message. The
// argument is the same as what the targets registry passes when constructing
// attributes from a request.
func newAttribute(m any) targets.Attributes {
	a := &attribute{
		SshTargetAttributes: &pb.SshTargetAttributes{},
	}
	if sshAttr, ok := m.(*pb.Target_SshTargetAttributes); ok {
		a.SshTargetAttributes = sshAttr.SshTargetAttributes
	}
	return a
}

// setAttributes populates the SSH-specific attributes on a pb.Target read
// from storage.
//
// Note: the storage layer for ssh.Target is a thin embedding of tcp.Target
// (which has no storage_bucket_id or enable_session_recording columns), so
// those values can only be round-tripped via the proto and are not
// persisted. This is acceptable for the BSR demo: a real implementation
// would either add a target_ssh table or extend target_tcp.
func setAttributes(t target.Target, out *pb.Target) error {
	if t == nil {
		return nil
	}

	attrs := &pb.Target_SshTargetAttributes{
		SshTargetAttributes: &pb.SshTargetAttributes{},
	}
	if t.GetDefaultPort() > 0 {
		attrs.SshTargetAttributes.DefaultPort = &wrappers.UInt32Value{Value: t.GetDefaultPort()}
	}
	if t.GetDefaultClientPort() > 0 {
		attrs.SshTargetAttributes.DefaultClientPort = &wrappers.UInt32Value{Value: t.GetDefaultClientPort()}
	}

	out.Attrs = attrs
	return nil
}

// noopSessionValidation is the SSH equivalent of TCP's no-op session-state
// validator. Session authorization/recording for SSH is handled by the
// worker-side proxy and the recording subsystem; the controller-side
// validation has no extra state checks to perform.
func noopSessionValidation(context.Context, *session.Session) error { return nil }

func init() {
	var maskManager handlers.MaskManager
	var err error

	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		// Storage_bucket_id and enable_session_recording in the SshTargetAttributes
		// proto source are round-tripped in setAttributes() but their mask_mapping
		// was removed from the proto because the OSS storage target has no
		// corresponding destination columns. The mask manager is therefore happy
		// with just the target_tcp fields.
		handlers.MaskDestination{&tcpStore.Target{}, &store.TargetAddress{}},
		handlers.MaskSource{&pb.Target{}, &pb.SshTargetAttributes{}},
	); err != nil {
		panic(err)
	}

	targets.Register(ssh.Subtype, maskManager, newAttribute, setAttributes, noopSessionValidation)
}
