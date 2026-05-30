// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/require"
)

func Test_NewDataChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name      string
		direction bsr.Direction
		time      *bsr.Timestamp
		data      []byte
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "nil timestamp",
			direction: bsr.Inbound,
			data:      []byte("hello"),
			expErr:    true,
			expErrMsg: "postgres.NewDataChunk: timestamp cannot be nil: invalid parameter",
		},
		{
			name:      "empty direction",
			time:      now,
			data:      []byte("hello"),
			expErr:    true,
			expErrMsg: "postgres.NewDataChunk: invalid direction: invalid parameter",
		},
		{
			name:      "nil data",
			direction: bsr.Inbound,
			time:      now,
			data:      nil,
			expErr:    false,
		},
		{
			name:      "empty data",
			direction: bsr.Inbound,
			time:      now,
			data:      []byte{},
			expErr:    false,
		},
		{
			name:      "inbound",
			direction: bsr.Inbound,
			time:      now,
			data:      []byte("select 1"),
			expErr:    false,
		},
		{
			name:      "outbound",
			direction: bsr.Outbound,
			time:      now,
			data:      []byte("authentication ok"),
			expErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc, err := NewDataChunk(ctx, tt.direction, tt.time, tt.data)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, dc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, dc)
			require.Equal(t, Protocol, dc.BaseChunk.Protocol)
			require.Equal(t, DataChunkType, dc.BaseChunk.Type)
			require.Equal(t, tt.direction, dc.BaseChunk.Direction)
			require.Equal(t, tt.data, dc.Data)
		})
	}
}

func Test_DataChunk_MarshalData(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "simple bytes",
			data: []byte("select * from users"),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0xff},
		},
		{
			name: "large data",
			data: make([]byte, 4096),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc, err := NewDataChunk(ctx, bsr.Inbound, now, tt.data)
			require.NoError(t, err)

			got, err := dc.MarshalData(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.data, got)
		})
	}
}