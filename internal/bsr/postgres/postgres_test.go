// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/postgres"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestProtocol(t *testing.T) {
	require.Equal(t, bsr.Protocol("PGSQ"), postgres.Protocol)
}

func TestChunkTypeConstants(t *testing.T) {
	require.Equal(t, bsr.ChunkType("DATA"), postgres.DataChunkType)
	require.Equal(t, bsr.ChunkType("STRD"), postgres.StartupChunkType)
	require.Equal(t, bsr.ChunkType("AUTH"), postgres.AuthChunkType)
	require.Equal(t, bsr.ChunkType("QRY"), postgres.QueryChunkType)
	require.Equal(t, bsr.ChunkType("PARSE"), postgres.ParseChunkType)
	require.Equal(t, bsr.ChunkType("BIND"), postgres.BindChunkType)
	require.Equal(t, bsr.ChunkType("BNDR"), postgres.BindResponseChunkType)
	require.Equal(t, bsr.ChunkType("EXEC"), postgres.ExecuteChunkType)
	require.Equal(t, bsr.ChunkType("EXCR"), postgres.ExecuteResponseChunkType)
	require.Equal(t, bsr.ChunkType("PARSC"), postgres.ParseCompleteChunkType)
	require.Equal(t, bsr.ChunkType("SYNC"), postgres.SyncChunkType)
	require.Equal(t, bsr.ChunkType("ERRR"), postgres.ErrorChunkType)
	require.Equal(t, bsr.ChunkType("DONE"), postgres.DoneChunkType)
}

func TestNewDataChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid", func(t *testing.T) {
		c, err := postgres.NewDataChunk(ctx, bsr.Inbound, now, []byte("raw bytes"))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, postgres.Protocol, c.Protocol)
		require.Equal(t, postgres.DataChunkType, c.Type)
		require.Equal(t, []byte("raw bytes"), c.Data)
	})

	t.Run("nil timestamp", func(t *testing.T) {
		c, err := postgres.NewDataChunk(ctx, bsr.Inbound, nil, []byte("data"))
		require.Error(t, err)
		require.EqualError(t, err, "postgres.NewDataChunk: timestamp cannot be nil: invalid parameter")
		require.Nil(t, c)
	})

	t.Run("nil data is ok", func(t *testing.T) {
		c, err := postgres.NewDataChunk(ctx, bsr.Inbound, now, nil)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Nil(t, c.Data)
	})
}

func TestNewStartupChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid with options", func(t *testing.T) {
		c, err := postgres.NewStartupChunk(ctx, bsr.Inbound, now, "alice", "mydb", map[string]string{
			"application_name": "psql",
			"client_encoding":  "UTF8",
		})
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "alice", c.StartupChunk.User)
		require.Equal(t, "mydb", c.StartupChunk.Database)
		require.Equal(t, "psql", c.StartupChunk.Options["application_name"])

		data, err := c.MarshalData(ctx)
		require.NoError(t, err)
		m := &postgres.StartupChunk{}
		require.NoError(t, proto.Unmarshal(data, m))
		require.Equal(t, "alice", m.User)
	})

	t.Run("empty direction", func(t *testing.T) {
		c, err := postgres.NewStartupChunk(ctx, bsr.UnknownDirection, now, "alice", "mydb", nil)
		require.Error(t, err)
		require.EqualError(t, err, "postgres.NewStartupChunk: invalid direction: invalid parameter")
		require.Nil(t, c)
	})

	t.Run("nil timestamp", func(t *testing.T) {
		c, err := postgres.NewStartupChunk(ctx, bsr.Inbound, nil, "alice", "mydb", nil)
		require.Error(t, err)
		require.EqualError(t, err, "postgres.NewStartupChunk: timestamp cannot be nil: invalid parameter")
		require.Nil(t, c)
	})
}

func TestNewAuthChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("success", func(t *testing.T) {
		c, err := postgres.NewAuthChunk(ctx, bsr.Inbound, now, "scram-sha-256", true, "")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "scram-sha-256", c.AuthChunk.Method)
		require.True(t, c.AuthChunk.Success)
		require.Empty(t, c.AuthChunk.Error)
	})

	t.Run("failure", func(t *testing.T) {
		c, err := postgres.NewAuthChunk(ctx, bsr.Inbound, now, "md5", false, "password authentication failed")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "md5", c.AuthChunk.Method)
		require.False(t, c.AuthChunk.Success)
		require.Equal(t, "password authentication failed", c.AuthChunk.Error)
	})
}

func TestNewQueryChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid", func(t *testing.T) {
		c, err := postgres.NewQueryChunk(ctx, bsr.Inbound, now, "SELECT 1", "testdb")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "SELECT 1", c.QueryChunk.Query)
		require.Equal(t, "testdb", c.QueryChunk.Database)
	})
}

func TestNewParseChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid", func(t *testing.T) {
		c, err := postgres.NewParseChunk(ctx, bsr.Inbound, now, "my_stmt", "SELECT $1::int", "mydb")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "my_stmt", c.ParseChunk.StatementName)
		require.Equal(t, "SELECT $1::int", c.ParseChunk.Query)
		require.Equal(t, "mydb", c.ParseChunk.Database)
	})
}

func TestNewBindChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid with params", func(t *testing.T) {
		c, err := postgres.NewBindChunk(ctx, bsr.Inbound, now,
			"my_stmt", "my_portal", "SELECT $1::int",
			[][]byte{[]byte("42")}, []uint32{23},
			"mydb")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "my_stmt", c.BindChunk.StatementName)
		require.Equal(t, "my_portal", c.BindChunk.PortalName)
		require.Equal(t, "SELECT $1::int", c.BindChunk.Query)
		require.Len(t, c.BindChunk.ParamValues, 1)
		require.Equal(t, []byte("42"), c.BindChunk.ParamValues[0])
		require.Equal(t, []uint32{23}, c.BindChunk.ParamTypes)
		require.Equal(t, "mydb", c.BindChunk.Database)
	})

	t.Run("no params", func(t *testing.T) {
		c, err := postgres.NewBindChunk(ctx, bsr.Inbound, now,
			"stmt1", "", "SELECT 1", nil, nil, "mydb")
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestNewBindResponseChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("success", func(t *testing.T) {
		c, err := postgres.NewBindResponseChunk(ctx, bsr.Outbound, now, true, "")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.True(t, c.BindResponseChunk.Success)
		require.Empty(t, c.BindResponseChunk.Error)
	})

	t.Run("failure", func(t *testing.T) {
		c, err := postgres.NewBindResponseChunk(ctx, bsr.Outbound, now, false, "prepared statement \"my_stmt\" does not exist")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.False(t, c.BindResponseChunk.Success)
		require.Equal(t, "prepared statement \"my_stmt\" does not exist", c.BindResponseChunk.Error)
	})
}

func TestNewExecuteChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid", func(t *testing.T) {
		c, err := postgres.NewExecuteChunk(ctx, bsr.Inbound, now, "my_portal", 0)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "my_portal", c.ExecuteChunk.PortalName)
		require.Equal(t, uint32(0), c.ExecuteChunk.MaxRows)
	})

	t.Run("max rows", func(t *testing.T) {
		c, err := postgres.NewExecuteChunk(ctx, bsr.Inbound, now, "portal", 100)
		require.NoError(t, err)
		require.Equal(t, uint32(100), c.ExecuteChunk.MaxRows)
	})
}

func TestNewExecuteResponseChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("success rows affected", func(t *testing.T) {
		c, err := postgres.NewExecuteResponseChunk(ctx, bsr.Outbound, now, 5, false, "")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, int64(5), c.ExecuteResponseChunk.RowsAffected)
		require.False(t, c.ExecuteResponseChunk.Error)
	})

	t.Run("error", func(t *testing.T) {
		c, err := postgres.NewExecuteResponseChunk(ctx, bsr.Outbound, now, 0, true, "division by zero")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, int64(0), c.ExecuteResponseChunk.RowsAffected)
		require.True(t, c.ExecuteResponseChunk.Error)
		require.Equal(t, "division by zero", c.ExecuteResponseChunk.ErrorMessage)
	})
}

func TestNewParseCompleteChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid outbound", func(t *testing.T) {
		c, err := postgres.NewParseCompleteChunk(ctx, bsr.Outbound, now)
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestNewSyncChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid inbound", func(t *testing.T) {
		c, err := postgres.NewSyncChunk(ctx, bsr.Inbound, now)
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("nil timestamp", func(t *testing.T) {
		c, err := postgres.NewSyncChunk(ctx, bsr.Inbound, nil)
		require.Error(t, err)
		require.Nil(t, c)
	})
}

func TestNewErrorChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("valid full", func(t *testing.T) {
		c, err := postgres.NewErrorChunk(ctx, bsr.Outbound, now,
			"ERROR", "42P01", "relation \"users\" does not exist",
			"Table \"users\" does not exist.", "Create the table first.")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "ERROR", c.ErrorChunk.Severity)
		require.Equal(t, "42P01", c.ErrorChunk.Code)
		require.Equal(t, "relation \"users\" does not exist", c.ErrorChunk.Message)
		require.Equal(t, "Table \"users\" does not exist.", c.ErrorChunk.Detail)
		require.Equal(t, "Create the table first.", c.ErrorChunk.Hint)
	})

	t.Run("empty optional fields", func(t *testing.T) {
		c, err := postgres.NewErrorChunk(ctx, bsr.Outbound, now, "WARNING", "000", "notice", "", "")
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestNewDoneChunk(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	t.Run("normal", func(t *testing.T) {
		c, err := postgres.NewDoneChunk(ctx, bsr.Inbound, now, "normal")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, "normal", c.DoneChunk.Reason)
	})

	t.Run("client disconnect", func(t *testing.T) {
		c, err := postgres.NewDoneChunk(ctx, bsr.Inbound, now, "client_disconnect")
		require.NoError(t, err)
		require.Equal(t, "client_disconnect", c.DoneChunk.Reason)
	})

	t.Run("nil timestamp", func(t *testing.T) {
		c, err := postgres.NewDoneChunk(ctx, bsr.Inbound, nil, "normal")
		require.Error(t, err)
		require.Nil(t, c)
	})
}

func TestValidDatabaseQueryType(t *testing.T) {
	require.True(t, postgres.ValidDatabaseQueryType(postgres.QueryTypeSimple))
	require.True(t, postgres.ValidDatabaseQueryType(postgres.QueryTypeExtended))
	require.False(t, postgres.ValidDatabaseQueryType(postgres.DatabaseQueryType("junk")))
}

func TestValidSessionTerminationReason(t *testing.T) {
	require.True(t, postgres.ValidSessionTerminationReason(postgres.TerminationNormal))
	require.True(t, postgres.ValidSessionTerminationReason(postgres.TerminationClientDisconnect))
	require.True(t, postgres.ValidSessionTerminationReason(postgres.TerminationServerDisconnect))
	require.True(t, postgres.ValidSessionTerminationReason(postgres.TerminationTimeout))
	require.False(t, postgres.ValidSessionTerminationReason(postgres.SessionTerminationReason("junk")))
}

func TestValidAuthMethod(t *testing.T) {
	require.True(t, postgres.ValidAuthMethod(postgres.AuthMethodUnspecified))
	require.True(t, postgres.ValidAuthMethod(postgres.AuthMethodCleartext))
	require.True(t, postgres.ValidAuthMethod(postgres.AuthMethodMD5))
	require.True(t, postgres.ValidAuthMethod(postgres.AuthMethodSCRAMSHA256))
	require.False(t, postgres.ValidAuthMethod(postgres.AuthMethod("kerberos")))
}