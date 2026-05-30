// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	pgres "github.com/hashicorp/boundary/internal/bsr/gen/postgres/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_NewStartupChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name      string
		direction bsr.Direction
		time      *bsr.Timestamp
		user      string
		database  string
		options   map[string]string
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "nil timestamp",
			direction: bsr.Inbound,
			user:      "testuser",
			database:  "testdb",
			options:   nil,
			expErr:    true,
			expErrMsg: "postgres.NewStartupChunk: timestamp cannot be nil: invalid parameter",
		},
		{
			name:     "empty direction",
			time:     now,
			user:     "testuser",
			database: "testdb",
			options:  nil,
			expErr:   true,
			expErrMsg: "postgres.NewStartupChunk: invalid direction: invalid parameter",
		},
		{
			name:      "valid minimal",
			direction: bsr.Inbound,
			time:      now,
			user:      "testuser",
			database:  "testdb",
			options:   nil,
			expErr:    false,
		},
		{
			name:      "valid with options",
			direction: bsr.Inbound,
			time:      now,
			user:      "testuser",
			database:  "testdb",
			options: map[string]string{
				"application_name": "boundary-worker",
				"client_encoding":  "UTF8",
			},
			expErr: false,
		},
		{
			name:      "outbound direction",
			direction: bsr.Outbound,
			time:      now,
			user:      "testuser",
			database:  "testdb",
			options:   nil,
			expErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := NewStartupChunk(ctx, tt.direction, tt.time, tt.user, tt.database, tt.options)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, sc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, sc)
			require.Equal(t, Protocol, sc.BaseChunk.Protocol)
			require.Equal(t, StartupChunkType, sc.BaseChunk.Type)
			require.Equal(t, tt.direction, sc.BaseChunk.Direction)
			require.Equal(t, tt.user, sc.StartupChunk.User)
			require.Equal(t, tt.database, sc.StartupChunk.Database)
			if tt.options == nil {
				require.Nil(t, sc.StartupChunk.Options)
			} else {
				require.Equal(t, tt.options, sc.StartupChunk.Options)
			}
		})
	}
}

func Test_StartupChunk_MarshalData(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name     string
		user     string
		database string
		options  map[string]string
	}{
		{
			name:     "simple",
			user:     "admin",
			database: "postgres",
			options:  nil,
		},
		{
			name:     "with options",
			user:     "app_user",
			database: "production_db",
			options: map[string]string{
				"application_name": "boundary-recorder",
				"client_encoding":  "UTF8",
				"datestyle":        "ISO, MDY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := NewStartupChunk(ctx, bsr.Inbound, now, tt.user, tt.database, tt.options)
			require.NoError(t, err)

			data, err := sc.MarshalData(ctx)
			require.NoError(t, err)

			msg := &pgres.StartupChunk{}
			err = proto.Unmarshal(data, msg)
			require.NoError(t, err)
			require.Equal(t, tt.user, msg.User)
			require.Equal(t, tt.database, msg.Database)
			if tt.options == nil {
				require.Nil(t, msg.Options)
			} else {
				require.Equal(t, tt.options, msg.Options)
			}
		})
	}
}

func Test_StartupChunk_MarshalData_empty_user(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	sc, err := NewStartupChunk(ctx, bsr.Inbound, now, "", "testdb", nil)
	require.NoError(t, err)
	require.NotNil(t, sc)

	data, err := sc.MarshalData(ctx)
	require.NoError(t, err)

	msg := &pgres.StartupChunk{}
	err = proto.Unmarshal(data, msg)
	require.NoError(t, err)
	require.Equal(t, "", msg.User)
	require.Equal(t, "testdb", msg.Database)
}

func Test_StartupChunk_MarshalData_empty_database(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	sc, err := NewStartupChunk(ctx, bsr.Inbound, now, "testuser", "", nil)
	require.NoError(t, err)
	require.NotNil(t, sc)

	data, err := sc.MarshalData(ctx)
	require.NoError(t, err)

	msg := &pgres.StartupChunk{}
	err = proto.Unmarshal(data, msg)
	require.NoError(t, err)
	require.Equal(t, "testuser", msg.User)
	require.Equal(t, "", msg.Database)
}

func Test_StartupChunk_MarshalData_empty_options(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	sc, err := NewStartupChunk(ctx, bsr.Inbound, now, "testuser", "testdb", map[string]string{})
	require.NoError(t, err)
	require.NotNil(t, sc)

	data, err := sc.MarshalData(ctx)
	require.NoError(t, err)

	msg := &pgres.StartupChunk{}
	err = proto.Unmarshal(data, msg)
	require.NoError(t, err)
	require.NotNil(t, msg.Options)
	require.Empty(t, msg.Options)
}