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

// BindChunk contains a Bind message with resolved SQL and parameter values.
type BindChunk struct {
	*bsr.BaseChunk
	*pgres.BindChunk
}

// MarshalData serializes a BindChunk
func (c *BindChunk) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "postgres.(BindChunk).MarshalData"

	dataBytes, err := proto.Marshal(c.BindChunk)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewBindChunk constructs a BindChunk
func NewBindChunk(
	ctx context.Context,
	d bsr.Direction,
	t *bsr.Timestamp,
	statementName, portalName, query string,
	paramValues [][]byte,
	paramTypes []uint32,
	database string,
) (*BindChunk, error) {
	const op = "postgres.NewBindChunk"

	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, BindChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &BindChunk{
		BaseChunk: baseChunk,
		BindChunk: &pgres.BindChunk{
			StatementName: statementName,
			PortalName:    portalName,
			Query:         query,
			ParamValues:   paramValues,
			ParamTypes:    paramTypes,
			Database:      database,
		},
	}, nil
}