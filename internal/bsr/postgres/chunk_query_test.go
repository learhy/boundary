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

func Test_NewQueryChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name      string
		direction bsr.Direction
		time      *bsr.Timestamp
		query     string
		database  string
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "nil timestamp",
			direction: bsr.Inbound,
			query:     "select 1",
			database:  "testdb",
			expErr:    true,
			expErrMsg: "postgres.NewQueryChunk: timestamp cannot be nil: invalid parameter",
		},
		{
			name:     "empty direction",
			time:     now,
			query:    "select 1",
			database: "testdb",
			expErr:   true,
			expErrMsg: "postgres.NewQueryChunk: invalid direction: invalid parameter",
		},
		{
			name:      "valid simple query",
			direction: bsr.Inbound,
			time:      now,
			query:     "select 1",
			database:  "testdb",
			expErr:    false,
		},
		{
			name:      "valid complex query",
			direction: bsr.Inbound,
			time:      now,
			query:     "select id, name from users where active = true order by created_at desc limit 100",
			database:  "production",
			expErr:    false,
		},
		{
			name:      "empty query string",
			direction: bsr.Inbound,
			time:      now,
			query:     "",
			database:  "testdb",
			expErr:    false,
		},
		{
			name:      "empty database",
			direction: bsr.Inbound,
			time:      now,
			query:     "select 1",
			database:  "",
			expErr:    false,
		},
		{
			name:      "outbound",
			direction: bsr.Outbound,
			time:      now,
			query:     "select 1",
			database:  "testdb",
			expErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qc, err := NewQueryChunk(ctx, tt.direction, tt.time, tt.query, tt.database)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, qc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, qc)
			require.Equal(t, Protocol, qc.BaseChunk.Protocol)
			require.Equal(t, QueryChunkType, qc.BaseChunk.Type)
			require.Equal(t, tt.direction, qc.BaseChunk.Direction)
			require.Equal(t, tt.query, qc.QueryChunk.Query)
			require.Equal(t, tt.database, qc.QueryChunk.Database)
		})
	}
}

func Test_QueryChunk_MarshalData(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name     string
		query    string
		database string
	}{
		{
			name:     "simple select",
			query:    "SELECT 1",
			database: "postgres",
		},
		{
			name:     "insert statement",
			query:    "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')",
			database: "app_db",
		},
		{
			name:     "update statement",
			query:    "UPDATE accounts SET balance = balance + 100 WHERE id = 5",
			database: "finance_db",
		},
		{
			name:     "delete statement",
			query:    "DELETE FROM sessions WHERE expired_at < now()",
			database: "app_db",
		},
		{
			name:     "transaction",
			query:    "BEGIN; SELECT 1; COMMIT",
			database: "postgres",
		},
		{
			name:     "ddl statement",
			query:    "CREATE TABLE IF NOT EXISTS events (id serial primary key, name text not null)",
			database: "postgres",
		},
		{
			name:     "empty query",
			query:    "",
			database: "postgres",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qc, err := NewQueryChunk(ctx, bsr.Inbound, now, tt.query, tt.database)
			require.NoError(t, err)

			data, err := qc.MarshalData(ctx)
			require.NoError(t, err)

			msg := &pgres.QueryChunk{}
			err = proto.Unmarshal(data, msg)
			require.NoError(t, err)
			require.Equal(t, tt.query, msg.Query)
			require.Equal(t, tt.database, msg.Database)
		})
	}
}

func Test_QueryChunk_protocol(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	qc, err := NewQueryChunk(ctx, bsr.Inbound, now, "select 1", "testdb")
	require.NoError(t, err)
	require.NotNil(t, qc)
	require.Equal(t, Protocol, qc.BaseChunk.Protocol)
	require.Equal(t, QueryChunkType, qc.BaseChunk.Type)
	require.Equal(t, bsr.Inbound, qc.BaseChunk.Direction)
}

func Test_QueryChunk_roundtrip(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	origQuery := "SELECT id, name, email FROM users WHERE active = true LIMIT 50 OFFSET 10"
	origDb := "production_users_db"

	qc, err := NewQueryChunk(ctx, bsr.Outbound, now, origQuery, origDb)
	require.NoError(t, err)

	data, err := qc.MarshalData(ctx)
	require.NoError(t, err)

	msg := &pgres.QueryChunk{}
	err = proto.Unmarshal(data, msg)
	require.NoError(t, err)
	require.Equal(t, origQuery, msg.Query)
	require.Equal(t, origDb, msg.Database)
}