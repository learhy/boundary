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

// StartupChunk contains sanitized startup message parameters.
type StartupChunk struct {
	*bsr.BaseChunk
	*pgres.StartupChunk
}

// MarshalData serializes a StartupChunk
func (c *StartupChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(StartupChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.StartupChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewStartupChunk constructs a StartupChunk
func NewStartupChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	user, database string,
	options map[string]string,
) (*StartupChunk, error) {
	const op = "postgres.NewStartupChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, StartupChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &StartupChunk{
		BaseChunk: baseChunk,
		StartupChunk: &pgres.StartupChunk{
			User:     user,
			Database: database,
			Options:  options,
		},
	}, nil
}