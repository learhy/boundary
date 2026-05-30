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

// QueryChunk contains a simple SQL query from a Query message.
type QueryChunk struct {
	*bsr.BaseChunk
	*pgres.QueryChunk
}

// MarshalData serializes a QueryChunk
func (c *QueryChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(QueryChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.QueryChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewQueryChunk constructs a QueryChunk
func NewQueryChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	query, database string,
) (*QueryChunk, error) {
	const op = "postgres.NewQueryChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, QueryChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &QueryChunk{
		BaseChunk: baseChunk,
		QueryChunk: &pgres.QueryChunk{
			Query:   query,
			Database: database,
		},
	}, nil
}