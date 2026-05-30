// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pgres "github.com/hashicorp/boundary/internal/bsr/gen/postgres/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"google.golang.org/protobuf/proto"
)

// AuthChunk contains authentication method and outcome.
type AuthChunk struct {
	*bsr.BaseChunk
	*pgres.AuthChunk
}

// MarshalData serializes an AuthChunk
func (c *AuthChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(AuthChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.AuthChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewAuthChunk constructs an AuthChunk
func NewAuthChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	method string,
	success bool,
	errMsg string,
) (*AuthChunk, error) {
	const op = "postgres.NewAuthChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, AuthChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &AuthChunk{
		BaseChunk: baseChunk,
		AuthChunk: &pgres.AuthChunk{
			Method:  method,
			Success: success,
			Error:   errMsg,
		},
	}, nil
}