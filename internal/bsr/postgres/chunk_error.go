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

// ErrorChunk contains a PostgreSQL ErrorResponse.
type ErrorChunk struct {
	*bsr.BaseChunk
	*pgres.ErrorChunk
}

// MarshalData serializes an ErrorChunk
func (c *ErrorChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(ErrorChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.ErrorChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewErrorChunk constructs an ErrorChunk
func NewErrorChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	severity, code, message, detail, hint string,
) (*ErrorChunk, error) {
	const op = "postgres.NewErrorChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ErrorChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &ErrorChunk{
		BaseChunk: baseChunk,
		ErrorChunk: &pgres.ErrorChunk{
			Severity: severity,
			Code:     code,
			Message:  message,
			Detail:   detail,
			Hint:     hint,
		},
	}, nil
}