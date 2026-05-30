// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
)

// DataChunk contains raw byte data for unparsed or non-auditable messages.
type DataChunk struct {
	*bsr.BaseChunk
	Data []byte
}

// NewDataChunk constructs a DataChunk
func NewDataChunk(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, data []byte) (*DataChunk, error) {
	const op = "postgres.NewDataChunk"

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, DataChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &DataChunk{
		BaseChunk: baseChunk,
		Data:      data,
	}, nil
}

// MarshalData returns the data for a DataChunk
func (c *DataChunk) MarshalData(_ context.Context) ([]byte, error) {
	return c.Data, nil
}