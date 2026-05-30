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

// SyncChunk indicates a Sync message, ending an implicit transaction block.
type SyncChunk struct {
	*bsr.BaseChunk
	*pgres.SyncChunk
}

// MarshalData serializes a SyncChunk
func (c *SyncChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(SyncChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.SyncChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewSyncChunk constructs a SyncChunk
func NewSyncChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
) (*SyncChunk, error) {
	const op = "postgres.NewSyncChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, SyncChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &SyncChunk{
		BaseChunk: baseChunk,
		SyncChunk: &pgres.SyncChunk{},
	}, nil
}