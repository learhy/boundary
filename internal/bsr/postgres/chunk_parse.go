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

// ParseChunk contains a Parse message with SQL and statement name.
type ParseChunk struct {
	*bsr.BaseChunk
	*pgres.ParseChunk
}

// MarshalData serializes a ParseChunk
func (c *ParseChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(ParseChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.ParseChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewParseChunk constructs a ParseChunk
func NewParseChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	statementName, query, database string,
) (*ParseChunk, error) {
	const op = "postgres.NewParseChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ParseChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &ParseChunk{
		BaseChunk: baseChunk,
		ParseChunk: &pgres.ParseChunk{
			StatementName: statementName,
			Query:         query,
			Database:      database,
		},
	}, nil
}