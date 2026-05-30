// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidDatabaseQueryType(t *testing.T) {
	tests := []struct {
		name   string
		qtype  DatabaseQueryType
		expect bool
	}{
		{
			name:   "simple",
			qtype:  QueryTypeSimple,
			expect: true,
		},
		{
			name:   "extended",
			qtype:  QueryTypeExtended,
			expect: true,
		},
		{
			name:   "empty string",
			qtype:  "",
			expect: false,
		},
		{
			name:   "unknown value",
			qtype:  "prepared",
			expect: false,
		},
		{
			name:   "arbitrary string",
			qtype:  "SELECT",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidDatabaseQueryType(tt.qtype)
			require.Equal(t, tt.expect, got)
		})
	}
}

func TestQueryTypeConstants(t *testing.T) {
	require.Equal(t, DatabaseQueryType("simple"), QueryTypeSimple)
	require.Equal(t, DatabaseQueryType("extended"), QueryTypeExtended)
}

func TestValidSessionTerminationReason(t *testing.T) {
	tests := []struct {
		name   string
		reason SessionTerminationReason
		expect bool
	}{
		{
			name:   "normal",
			reason: TerminationNormal,
			expect: true,
		},
		{
			name:   "client disconnect",
			reason: TerminationClientDisconnect,
			expect: true,
		},
		{
			name:   "server disconnect",
			reason: TerminationServerDisconnect,
			expect: true,
		},
		{
			name:   "timeout",
			reason: TerminationTimeout,
			expect: true,
		},
		{
			name:   "empty string",
			reason: "",
			expect: false,
		},
		{
			name:   "unknown value",
			reason: "network_error",
			expect: false,
		},
		{
			name:   "lowercase",
			reason: "normal",
			expect: false,
		},
		{
			name:   "arbitrary",
			reason: "unexpected_close",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidSessionTerminationReason(tt.reason)
			require.Equal(t, tt.expect, got)
		})
	}
}

func TestSessionTerminationReasonConstants(t *testing.T) {
	require.Equal(t, SessionTerminationReason("normal"), TerminationNormal)
	require.Equal(t, SessionTerminationReason("client_disconnect"), TerminationClientDisconnect)
	require.Equal(t, SessionTerminationReason("server_disconnect"), TerminationServerDisconnect)
	require.Equal(t, SessionTerminationReason("timeout"), TerminationTimeout)
}

func TestValidAuthMethod(t *testing.T) {
	tests := []struct {
		name   string
		method AuthMethod
		expect bool
	}{
		{
			name:   "unspecified",
			method: AuthMethodUnspecified,
			expect: true,
		},
		{
			name:   "cleartext",
			method: AuthMethodCleartext,
			expect: true,
		},
		{
			name:   "md5",
			method: AuthMethodMD5,
			expect: true,
		},
		{
			name:   "scram-sha-256",
			method: AuthMethodSCRAMSHA256,
			expect: true,
		},
		{
			name:   "empty string",
			method: "",
			expect: false,
		},
		{
			name:   "unknown value",
			method: "gssapi",
			expect: false,
		},
		{
			name:   "uppercase",
			method: "CLEARTEXT",
			expect: false,
		},
		{
			name:   "arbitrary string",
			method: "kerberos",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidAuthMethod(tt.method)
			require.Equal(t, tt.expect, got)
		})
	}
}

func TestAuthMethodConstants(t *testing.T) {
	require.Equal(t, AuthMethod("unspecified"), AuthMethodUnspecified)
	require.Equal(t, AuthMethod("cleartext"), AuthMethodCleartext)
	require.Equal(t, AuthMethod("md5"), AuthMethodMD5)
	require.Equal(t, AuthMethod("scram-sha-256"), AuthMethodSCRAMSHA256)
}

func TestSessionTerminationReason_string_representation(t *testing.T) {
	require.Equal(t, "normal", string(TerminationNormal))
	require.Equal(t, "client_disconnect", string(TerminationClientDisconnect))
	require.Equal(t, "server_disconnect", string(TerminationServerDisconnect))
	require.Equal(t, "timeout", string(TerminationTimeout))
}

func TestDatabaseQueryType_string_representation(t *testing.T) {
	require.Equal(t, "simple", string(QueryTypeSimple))
	require.Equal(t, "extended", string(QueryTypeExtended))
}

func TestAuthMethod_string_representation(t *testing.T) {
	require.Equal(t, "unspecified", string(AuthMethodUnspecified))
	require.Equal(t, "cleartext", string(AuthMethodCleartext))
	require.Equal(t, "md5", string(AuthMethodMD5))
	require.Equal(t, "scram-sha-256", string(AuthMethodSCRAMSHA256))
}

func TestAllTerminationReasonsAreValid(t *testing.T) {
	// Ensures that all defined constants pass validation
	reasons := []SessionTerminationReason{
		TerminationNormal,
		TerminationClientDisconnect,
		TerminationServerDisconnect,
		TerminationTimeout,
	}
	for _, r := range reasons {
		require.True(t, ValidSessionTerminationReason(r), "expected %q to be valid", r)
	}
}

func TestAllAuthMethodsAreValid(t *testing.T) {
	// Ensures that all defined constants pass validation
	methods := []AuthMethod{
		AuthMethodUnspecified,
		AuthMethodCleartext,
		AuthMethodMD5,
		AuthMethodSCRAMSHA256,
	}
	for _, m := range methods {
		require.True(t, ValidAuthMethod(m), "expected %q to be valid", m)
	}
}

func TestAllQueryTypesAreValid(t *testing.T) {
	// Ensures that all defined constants pass validation
	types := []DatabaseQueryType{
		QueryTypeSimple,
		QueryTypeExtended,
	}
	for _, q := range types {
		require.True(t, ValidDatabaseQueryType(q), "expected %q to be valid", q)
	}
}

func TestDatabaseQueryType_is_string_based(t *testing.T) {
	// Verify that DatabaseQueryType is a string type
	var q DatabaseQueryType = QueryTypeSimple
	require.Equal(t, "simple", q)

	q = QueryTypeExtended
	require.Equal(t, "extended", q)
}

func TestSessionTerminationReason_is_string_based(t *testing.T) {
	// Verify that SessionTerminationReason is a string type
	var r SessionTerminationReason = TerminationNormal
	require.Equal(t, "normal", r)

	r = TerminationTimeout
	require.Equal(t, "timeout", r)
}

func TestAuthMethod_is_string_based(t *testing.T) {
	// Verify that AuthMethod is a string type
	var m AuthMethod = AuthMethodMD5
	require.Equal(t, "md5", m)

	m = AuthMethodSCRAMSHA256
	require.Equal(t, "scram-sha-256", m)
}