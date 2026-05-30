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

// ExecuteResponseChunk contains the backend's response to an Execute message.
type ExecuteResponseChunk struct {
	*bsr.BaseChunk
	*pgres.ExecuteResponseChunk
}

// MarshalData serializes an ExecuteResponseChunk
func (c *ExecuteResponseChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(ExecuteResponseChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.ExecuteResponseChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewExecuteResponseChunk constructs an ExecuteResponseChunk
func NewExecuteResponseChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	rowsAffected int64,
	isError bool,
	errMsg string,
) (*ExecuteResponseChunk, error) {
	const op = "postgres.NewExecuteResponseChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ExecuteResponseChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &ExecuteResponseChunk{
		BaseChunk: baseChunk,
		ExecuteResponseChunk: &pgres.ExecuteResponseChunk{
			RowsAffected: rowsAffected,
			Error:        isError,
			ErrorMessage: errMsg,
		},
	}, nil
}