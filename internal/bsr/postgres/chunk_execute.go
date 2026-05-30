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

// ExecuteChunk contains an Execute message specifying which portal to run.
type ExecuteChunk struct {
	*bsr.BaseChunk
	*pgres.ExecuteChunk
}

// MarshalData serializes an ExecuteChunk
func (c *ExecuteChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(ExecuteChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.ExecuteChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewExecuteChunk constructs an ExecuteChunk
func NewExecuteChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	portalName string,
	maxRows uint32,
) (*ExecuteChunk, error) {
	const op = "postgres.NewExecuteChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ExecuteChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &ExecuteChunk{
		BaseChunk: baseChunk,
		ExecuteChunk: &pgres.ExecuteChunk{
			PortalName: portalName,
			MaxRows:    maxRows,
		},
	}, nil
}