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

// BindResponseChunk contains the backend's response to a Bind message.
type BindResponseChunk struct {
	*bsr.BaseChunk
	*pgres.BindResponseChunk
}

// MarshalData serializes a BindResponseChunk
func (c *BindResponseChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(BindResponseChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.BindResponseChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewBindResponseChunk constructs a BindResponseChunk
func NewBindResponseChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	success bool,
	errMsg string,
) (*BindResponseChunk, error) {
	const op = "postgres.NewBindResponseChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, BindResponseChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &BindResponseChunk{
		BaseChunk: baseChunk,
		BindResponseChunk: &pgres.BindResponseChunk{
			Success: success,
			Error:   errMsg,
		},
	}, nil
}