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

func init() {
	for _, ct := range []bsr.ChunkType{
		DataChunkType,
		StartupChunkType,
		AuthChunkType,
		QueryChunkType,
		ParseChunkType,
		BindChunkType,
		BindResponseChunkType,
		ExecuteChunkType,
		ExecuteResponseChunkType,
		ParseCompleteChunkType,
		SyncChunkType,
		ErrorChunkType,
		DoneChunkType,
	} {
		if err := bsr.RegisterChunkType(Protocol, ct, DecodeChunk); err != nil {
			panic(err)
		}
	}
}

const (
	// Protocol is used to identify chunks that are recorded from PostgreSQL.
	Protocol bsr.Protocol = "PGSQ"
)

// Chunk type constants
const (
	DataChunkType           bsr.ChunkType = "DATA"
	StartupChunkType        bsr.ChunkType = "STRD"
	AuthChunkType           bsr.ChunkType = "AUTH"
	QueryChunkType          bsr.ChunkType = "QRY"
	ParseChunkType          bsr.ChunkType = "PARSE"
	BindChunkType           bsr.ChunkType = "BIND"
	BindResponseChunkType   bsr.ChunkType = "BNDR"
	ExecuteChunkType        bsr.ChunkType = "EXEC"
	ExecuteResponseChunkType bsr.ChunkType = "EXCR"
	ParseCompleteChunkType  bsr.ChunkType = "PARSC"
	SyncChunkType           bsr.ChunkType = "SYNC"
	ErrorChunkType          bsr.ChunkType = "ERRR"
	DoneChunkType           bsr.ChunkType = "DONE"
)

// DecodeChunk will decode any known PostgreSQL Chunk type.
// If the chunk type is not a postgres chunk type, an error is returned.
func DecodeChunk(_ context.Context, bc *bsr.BaseChunk, data []byte) (bsr.Chunk, error) {
	const op = "postgres.DecodeChunk"

	if is.Nil(bc) {
		return nil, fmt.Errorf("%s: nil base chunk: %w", op, bsr.ErrInvalidParameter)
	}

	if bc.Protocol != Protocol {
		return nil, fmt.Errorf("%s: invalid protocol %s", op, bc.Protocol)
	}

	switch bc.Type {
	case DataChunkType:
		return &DataChunk{
			BaseChunk: bc,
			Data:      data,
		}, nil
	case StartupChunkType:
		mm := &pgres.StartupChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &StartupChunk{
			BaseChunk:    bc,
			StartupChunk: mm,
		}, nil
	case AuthChunkType:
		mm := &pgres.AuthChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &AuthChunk{
			BaseChunk:  bc,
			AuthChunk:  mm,
		}, nil
	case QueryChunkType:
		mm := &pgres.QueryChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &QueryChunk{
			BaseChunk:  bc,
			QueryChunk: mm,
		}, nil
	case ParseChunkType:
		mm := &pgres.ParseChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ParseChunk{
			BaseChunk:  bc,
			ParseChunk: mm,
		}, nil
	case BindChunkType:
		mm := &pgres.BindChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &BindChunk{
			BaseChunk:  bc,
			BindChunk:  mm,
		}, nil
	case BindResponseChunkType:
		mm := &pgres.BindResponseChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &BindResponseChunk{
			BaseChunk:         bc,
			BindResponseChunk: mm,
		}, nil
	case ExecuteChunkType:
		mm := &pgres.ExecuteChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExecuteChunk{
			BaseChunk:     bc,
			ExecuteChunk:  mm,
		}, nil
	case ExecuteResponseChunkType:
		mm := &pgres.ExecuteResponseChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExecuteResponseChunk{
			BaseChunk:             bc,
			ExecuteResponseChunk:  mm,
		}, nil
	case ParseCompleteChunkType:
		mm := &pgres.ParseCompleteChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ParseCompleteChunk{
			BaseChunk:         bc,
			ParseCompleteChunk: mm,
		}, nil
	case SyncChunkType:
		mm := &pgres.SyncChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &SyncChunk{
			BaseChunk: bc,
			SyncChunk: mm,
		}, nil
	case ErrorChunkType:
		mm := &pgres.ErrorChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ErrorChunk{
			BaseChunk:   bc,
			ErrorChunk:  mm,
		}, nil
	case DoneChunkType:
		mm := &pgres.DoneChunk{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &DoneChunk{
			BaseChunk:  bc,
			DoneChunk:  mm,
		}, nil

	default:
		return nil, fmt.Errorf("%s: unsupported chunk type %s", op, bc.Type)
	}
}