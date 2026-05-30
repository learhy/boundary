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

func TestDecodeChunk(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		bc      *bsr.BaseChunk
		encoded []byte
		want    interface{}
	}{
		{
			name: "DataChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     DataChunkType,
			},
			encoded: []byte("raw postgres wire bytes"),
			want: &DataChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     DataChunkType,
				},
				Data: []byte("raw postgres wire bytes"),
			},
		},
		{
			name: "StartupChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     StartupChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.StartupChunk{
					User:     "testuser",
					Database: "testdb",
					Options: map[string]string{
						"application_name": "boundary-recorder",
					},
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &StartupChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     StartupChunkType,
				},
				StartupChunk: &pgres.StartupChunk{
					User:     "testuser",
					Database: "testdb",
					Options: map[string]string{
						"application_name": "boundary-recorder",
					},
				},
			},
		},
		{
			name: "AuthChunkType success",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     AuthChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.AuthChunk{
					Method:  "scram-sha-256",
					Success: true,
					Error:   "",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &AuthChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     AuthChunkType,
				},
				AuthChunk: &pgres.AuthChunk{
					Method:  "scram-sha-256",
					Success: true,
					Error:   "",
				},
			},
		},
		{
			name: "AuthChunkType failure",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     AuthChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.AuthChunk{
					Method:  "md5",
					Success: false,
					Error:   "password authentication failed",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &AuthChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     AuthChunkType,
				},
				AuthChunk: &pgres.AuthChunk{
					Method:  "md5",
					Success: false,
					Error:   "password authentication failed",
				},
			},
		},
		{
			name: "QueryChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     QueryChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.QueryChunk{
					Query:   "SELECT id, name FROM users WHERE active = true",
					Database: "production_db",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &QueryChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     QueryChunkType,
				},
				QueryChunk: &pgres.QueryChunk{
					Query:   "SELECT id, name FROM users WHERE active = true",
					Database: "production_db",
				},
			},
		},
		{
			name: "ParseChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ParseChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ParseChunk{
					StatementName: "get_user_by_id",
					Query:         "SELECT * FROM users WHERE id = $1",
					Database:      "app_db",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ParseChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ParseChunkType,
				},
				ParseChunk: &pgres.ParseChunk{
					StatementName: "get_user_by_id",
					Query:         "SELECT * FROM users WHERE id = $1",
					Database:      "app_db",
				},
			},
		},
		{
			name: "BindChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     BindChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.BindChunk{
					StatementName: "get_user_by_id",
					PortalName:    "",
					Query:         "SELECT * FROM users WHERE id = $1",
					ParamValues:   [][]byte{[]byte("42")},
					ParamTypes:    []uint32{23},
					Database:      "app_db",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &BindChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     BindChunkType,
				},
				BindChunk: &pgres.BindChunk{
					StatementName: "get_user_by_id",
					PortalName:    "",
					Query:         "SELECT * FROM users WHERE id = $1",
					ParamValues:   [][]byte{[]byte("42")},
					ParamTypes:    []uint32{23},
					Database:      "app_db",
				},
			},
		},
		{
			name: "BindResponseChunkType success",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     BindResponseChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.BindResponseChunk{
					Success: true,
					Error:   "",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &BindResponseChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     BindResponseChunkType,
				},
				BindResponseChunk: &pgres.BindResponseChunk{
					Success: true,
					Error:   "",
				},
			},
		},
		{
			name: "ExecuteChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ExecuteChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ExecuteChunk{
					PortalName: "portal_1",
					MaxRows:    100,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ExecuteChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ExecuteChunkType,
				},
				ExecuteChunk: &pgres.ExecuteChunk{
					PortalName: "portal_1",
					MaxRows:    100,
				},
			},
		},
		{
			name: "ExecuteResponseChunkType rows affected",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ExecuteResponseChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ExecuteResponseChunk{
					RowsAffected: 15,
					Error:        false,
					ErrorMessage: "",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ExecuteResponseChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ExecuteResponseChunkType,
				},
				ExecuteResponseChunk: &pgres.ExecuteResponseChunk{
					RowsAffected: 15,
					Error:        false,
					ErrorMessage: "",
				},
			},
		},
		{
			name: "ExecuteResponseChunkType error",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ExecuteResponseChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ExecuteResponseChunk{
					RowsAffected: 0,
					Error:        true,
					ErrorMessage: "division by zero",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ExecuteResponseChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ExecuteResponseChunkType,
				},
				ExecuteResponseChunk: &pgres.ExecuteResponseChunk{
					RowsAffected: 0,
					Error:        true,
					ErrorMessage: "division by zero",
				},
			},
		},
		{
			name: "ParseCompleteChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ParseCompleteChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ParseCompleteChunk{}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ParseCompleteChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ParseCompleteChunkType,
				},
				ParseCompleteChunk: &pgres.ParseCompleteChunk{},
			},
		},
		{
			name: "SyncChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     SyncChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.SyncChunk{}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &SyncChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     SyncChunkType,
				},
				SyncChunk: &pgres.SyncChunk{},
			},
		},
		{
			name: "ErrorChunkType",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     ErrorChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.ErrorChunk{
					Severity: "ERROR",
					Code:     "23505",
					Message:  "duplicate key value violates unique constraint",
					Detail:   "Key (id)=(1) already exists.",
					Hint:     "Use UPDATE to modify existing records.",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &ErrorChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     ErrorChunkType,
				},
				ErrorChunk: &pgres.ErrorChunk{
					Severity: "ERROR",
					Code:     "23505",
					Message:  "duplicate key value violates unique constraint",
					Detail:   "Key (id)=(1) already exists.",
					Hint:     "Use UPDATE to modify existing records.",
				},
			},
		},
		{
			name: "DoneChunkType normal",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     DoneChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.DoneChunk{
					Reason: "normal",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &DoneChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     DoneChunkType,
				},
				DoneChunk: &pgres.DoneChunk{
					Reason: "normal",
				},
			},
		},
		{
			name: "DoneChunkType client disconnect",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     DoneChunkType,
			},
			encoded: func() []byte {
				msg := &pgres.DoneChunk{
					Reason: "client_disconnect",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			want: &DoneChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: Protocol,
					Type:     DoneChunkType,
				},
				DoneChunk: &pgres.DoneChunk{
					Reason: "client_disconnect",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeChunk(ctx, tc.bc, tc.encoded)
			require.NoError(t, err)
			require.NotNil(t, got)

			switch want := tc.want.(type) {
			case *DataChunk:
				gotDC := got.(*DataChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotDC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotDC.BaseChunk.Type)
				require.Equal(t, want.Data, gotDC.Data)
			case *StartupChunk:
				gotSC := got.(*StartupChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotSC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotSC.BaseChunk.Type)
				require.Equal(t, want.StartupChunk.User, gotSC.StartupChunk.User)
				require.Equal(t, want.StartupChunk.Database, gotSC.StartupChunk.Database)
				require.Equal(t, want.StartupChunk.Options, gotSC.StartupChunk.Options)
			case *AuthChunk:
				gotAC := got.(*AuthChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotAC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotAC.BaseChunk.Type)
				require.Equal(t, want.AuthChunk.Method, gotAC.AuthChunk.Method)
				require.Equal(t, want.AuthChunk.Success, gotAC.AuthChunk.Success)
				require.Equal(t, want.AuthChunk.Error, gotAC.AuthChunk.Error)
			case *QueryChunk:
				gotQC := got.(*QueryChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotQC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotQC.BaseChunk.Type)
				require.Equal(t, want.QueryChunk.Query, gotQC.QueryChunk.Query)
				require.Equal(t, want.QueryChunk.Database, gotQC.QueryChunk.Database)
			case *ParseChunk:
				gotPC := got.(*ParseChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotPC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotPC.BaseChunk.Type)
				require.Equal(t, want.ParseChunk.StatementName, gotPC.ParseChunk.StatementName)
				require.Equal(t, want.ParseChunk.Query, gotPC.ParseChunk.Query)
				require.Equal(t, want.ParseChunk.Database, gotPC.ParseChunk.Database)
			case *BindChunk:
				gotBC := got.(*BindChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotBC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotBC.BaseChunk.Type)
				require.Equal(t, want.BindChunk.StatementName, gotBC.BindChunk.StatementName)
				require.Equal(t, want.BindChunk.PortalName, gotBC.BindChunk.PortalName)
				require.Equal(t, want.BindChunk.Database, gotBC.BindChunk.Database)
				require.Equal(t, want.BindChunk.ParamValues, gotBC.BindChunk.ParamValues)
				require.Equal(t, want.BindChunk.ParamTypes, gotBC.BindChunk.ParamTypes)
			case *BindResponseChunk:
				gotBRC := got.(*BindResponseChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotBRC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotBRC.BaseChunk.Type)
				require.Equal(t, want.BindResponseChunk.Success, gotBRC.BindResponseChunk.Success)
				require.Equal(t, want.BindResponseChunk.Error, gotBRC.BindResponseChunk.Error)
			case *ExecuteChunk:
				gotEC := got.(*ExecuteChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotEC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotEC.BaseChunk.Type)
				require.Equal(t, want.ExecuteChunk.PortalName, gotEC.ExecuteChunk.PortalName)
				require.Equal(t, want.ExecuteChunk.MaxRows, gotEC.ExecuteChunk.MaxRows)
			case *ExecuteResponseChunk:
				gotERC := got.(*ExecuteResponseChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotERC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotERC.BaseChunk.Type)
				require.Equal(t, want.ExecuteResponseChunk.RowsAffected, gotERC.ExecuteResponseChunk.RowsAffected)
				require.Equal(t, want.ExecuteResponseChunk.Error, gotERC.ExecuteResponseChunk.Error)
				require.Equal(t, want.ExecuteResponseChunk.ErrorMessage, gotERC.ExecuteResponseChunk.ErrorMessage)
			case *ParseCompleteChunk:
				gotPCC := got.(*ParseCompleteChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotPCC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotPCC.BaseChunk.Type)
			case *SyncChunk:
				gotSC := got.(*SyncChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotSC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotSC.BaseChunk.Type)
			case *ErrorChunk:
				gotEC := got.(*ErrorChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotEC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotEC.BaseChunk.Type)
				require.Equal(t, want.ErrorChunk.Severity, gotEC.ErrorChunk.Severity)
				require.Equal(t, want.ErrorChunk.Code, gotEC.ErrorChunk.Code)
				require.Equal(t, want.ErrorChunk.Message, gotEC.ErrorChunk.Message)
				require.Equal(t, want.ErrorChunk.Detail, gotEC.ErrorChunk.Detail)
				require.Equal(t, want.ErrorChunk.Hint, gotEC.ErrorChunk.Hint)
			case *DoneChunk:
				gotDC := got.(*DoneChunk)
				require.Equal(t, want.BaseChunk.Protocol, gotDC.BaseChunk.Protocol)
				require.Equal(t, want.BaseChunk.Type, gotDC.BaseChunk.Type)
				require.Equal(t, want.DoneChunk.Reason, gotDC.DoneChunk.Reason)
			}
		})
	}
}

func TestDecodeChunk_Error(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	tests := []struct {
		name      string
		bc        *bsr.BaseChunk
		encoded   []byte
		expErrMsg string
	}{
		{
			name:      "nil base chunk",
			bc:        nil,
			encoded:   nil,
			expErrMsg: "postgres.DecodeChunk: nil base chunk: invalid parameter",
		},
		{
			name: "wrong protocol",
			bc: &bsr.BaseChunk{
				Protocol: "WRONG",
				Type:     DataChunkType,
				Timestamp: now,
			},
			encoded:   []byte("data"),
			expErrMsg: "postgres.DecodeChunk: invalid protocol WRONG",
		},
		{
			name: "unsupported chunk type",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     "UNKN",
				Timestamp: now,
			},
			encoded:   []byte("data"),
			expErrMsg: "postgres.DecodeChunk: unsupported chunk type UNKN",
		},
		{
			name: "invalid protobuf data for startup",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     StartupChunkType,
				Timestamp: now,
			},
			encoded:   []byte("not valid protobuf"),
			expErrMsg: "postgres.DecodeChunk: proto:",
		},
		{
			name: "invalid protobuf data for query",
			bc: &bsr.BaseChunk{
				Protocol: Protocol,
				Type:     QueryChunkType,
				Timestamp: now,
			},
			encoded:   []byte("not valid protobuf"),
			expErrMsg: "postgres.DecodeChunk: proto:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeChunk(ctx, tt.bc, tt.encoded)
			require.Error(t, err)
			if tt.expErrMsg != "" {
				if len(tt.expErrMsg) > 0 && tt.expErrMsg[len(tt.expErrMsg)-1] == ':' {
					// Partial match for "proto:" error messages
					require.Contains(t, err.Error(), tt.expErrMsg)
				} else {
					require.EqualError(t, err, tt.expErrMsg)
				}
			}
		})
	}
}

func TestDecodeChunk_DataChunk_empty(t *testing.T) {
	ctx := context.Background()

	bc := &bsr.BaseChunk{
		Protocol: Protocol,
		Type:     DataChunkType,
	}
	chunk, err := DecodeChunk(ctx, bc, nil)
	require.NoError(t, err)
	require.NotNil(t, chunk)

	dc, ok := chunk.(*DataChunk)
	require.True(t, ok)
	require.Nil(t, dc.Data)
}

func TestDecodeChunk_DataChunk_zero_length_data(t *testing.T) {
	ctx := context.Background()

	bc := &bsr.BaseChunk{
		Protocol: Protocol,
		Type:     DataChunkType,
	}
	chunk, err := DecodeChunk(ctx, bc, []byte{})
	require.NoError(t, err)
	require.NotNil(t, chunk)

	dc, ok := chunk.(*DataChunk)
	require.True(t, ok)
	require.Empty(t, dc.Data)
}