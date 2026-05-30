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

// DoneChunk indicates normal session termination.
type DoneChunk struct {
	*bsr.BaseChunk
	*pgres.DoneChunk
}

// MarshalData serializes a DoneChunk
func (c *DoneChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(DoneChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.DoneChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewDoneChunk constructs a DoneChunk
func NewDoneChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	reason string,
) (*DoneChunk, error) {
	const op = "postgres.NewDoneChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, DoneChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &DoneChunk{
		BaseChunk: baseChunk,
		DoneChunk: &pgres.DoneChunk{
			Reason: reason,
		},
	}, nil
}