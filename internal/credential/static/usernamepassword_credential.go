// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

var _ credential.Static = (*UsernamePasswordCredential)(nil)
var _ credential.UsernamePassword = (*UsernamePasswordCredential)(nil)
var _ credential.Credential = (*UsernamePasswordCredential)(nil)

// A UsernamePasswordCredential contains the credential with a username and password.
// It is owned by a credential store.
type UsernamePasswordCredential struct {
	*store.UsernamePasswordCredential
	tableName string `gorm:"-"`
}

// NewUsernamePasswordCredential creates a new in memory static Credential containing a
// username, password, and optional domain that is assigned to storeId.
// Name, description, and domain are the only valid options. All other options are ignored.
func NewUsernamePasswordCredential(
	storeId string,
	username string,
	password credential.Password,
	opt ...Option,
) (*UsernamePasswordCredential, error) {
	opts := getOpts(opt...)
	l := &UsernamePasswordCredential{
		UsernamePasswordCredential: &store.UsernamePasswordCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Username:    username,
			Password:    []byte(password),
			Domain:      opts.withDomain,
		},
	}
	return l, nil
}

func allocUsernamePasswordCredential() *UsernamePasswordCredential {
	return &UsernamePasswordCredential{
		UsernamePasswordCredential: &store.UsernamePasswordCredential{},
	}
}

func (c *UsernamePasswordCredential) clone() *UsernamePasswordCredential {
	cp := proto.Clone(c.UsernamePasswordCredential)
	return &UsernamePasswordCredential{
		UsernamePasswordCredential: cp.(*store.UsernamePasswordCredential),
	}
}

// TableName returns the table name.
func (c *UsernamePasswordCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_username_password_credential"
}

// SetTableName sets the table name.
func (c *UsernamePasswordCredential) SetTableName(n string) {
	c.tableName = n
}

func (c *UsernamePasswordCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-username-password"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

// Username returns the username for this credential.
func (c *UsernamePasswordCredential) Username() string {
	return c.UsernamePasswordCredential.Username
}

// Password returns the password for this credential.
func (c *UsernamePasswordCredential) Password() credential.Password {
	return credential.Password(c.Password)
}

// Domain returns the Active Directory domain for this credential.
// For AD-joined targets: "CORP" or "corp.example.com".
// For local accounts: "".
func (c *UsernamePasswordCredential) Domain() string {
	return c.UsernamePasswordCredential.Domain
}

// Secret returns the password as the secret data.
func (c *UsernamePasswordCredential) Secret() credential.SecretData {
	return c.Password()
}

func (c *UsernamePasswordCredential) hmacPassword(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordCredential).hmacPassword"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.Password, cipher, []byte(c.StoreId), nil, crypto.WithEd25519())
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.PasswordHmac = []byte(hm)
	return nil
}

func (c *UsernamePasswordCredential) hmacDomain(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordCredential).hmacDomain"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, []byte(c.Domain), cipher, []byte(c.StoreId), nil, crypto.WithEd25519())
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.DomainHmac = []byte(hm)
	return nil
}

func (c *UsernamePasswordCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordCredential).encrypt"
	if len(c.Password) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no password defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.UsernamePasswordCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	if err := c.hmacPassword(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := c.hmacDomain(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (c *UsernamePasswordCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.UsernamePasswordCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}