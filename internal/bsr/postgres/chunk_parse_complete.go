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

// ParseCompleteChunk indicates a Parse message was successfully processed.
type ParseCompleteChunk struct {
	*bsr.BaseChunk
	*pgres.ParseCompleteChunk
}

// MarshalData serializes a ParseCompleteChunk
func (c *ParseCompleteChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(ParseCompleteChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.ParseCompleteChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewParseCompleteChunk constructs a ParseCompleteChunk
func NewParseCompleteChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
) (*ParseCompleteChunk, error) {
	const op = "postgres.NewParseCompleteChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ParseCompleteChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &ParseCompleteChunk{
		BaseChunk:         baseChunk,
		ParseCompleteChunk: &pgres.ParseCompleteChunk{},
	}, nil
}