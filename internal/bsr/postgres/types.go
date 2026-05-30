// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

// DatabaseQueryType identifies the PostgreSQL query path used.
// Extended query uses Parse+Bind+Execute; simple query uses Query.
type DatabaseQueryType string

// DatabaseQueryTypes
const (
	// QueryTypeSimple indicates a simple Query message with raw SQL.
	QueryTypeSimple DatabaseQueryType = "simple"

	// QueryTypeExtended indicates extended query with Parse+Bind+Execute.
	QueryTypeExtended DatabaseQueryType = "extended"
)

// ValidDatabaseQueryType checks if a given DatabaseQueryType is valid.
func ValidDatabaseQueryType(d DatabaseQueryType) bool {
	switch d {
	case QueryTypeSimple, QueryTypeExtended:
		return true
	}
	return false
}

// SessionTerminationReason describes how the session ended.
type SessionTerminationReason string

// Session termination reasons.
const (
	TerminationNormal           SessionTerminationReason = "normal"
	TerminationClientDisconnect SessionTerminationReason = "client_disconnect"
	TerminationServerDisconnect SessionTerminationReason = "server_disconnect"
	TerminationTimeout          SessionTerminationReason = "timeout"
)

// ValidSessionTerminationReason checks if a given SessionTerminationReason is valid.
func ValidSessionTerminationReason(d SessionTerminationReason) bool {
	switch d {
	case TerminationNormal, TerminationClientDisconnect,
		TerminationServerDisconnect, TerminationTimeout:
		return true
	}
	return false
}

// AuthMethod identifies the PostgreSQL authentication mechanism.
type AuthMethod string

// AuthMethods
const (
	AuthMethodUnspecified AuthMethod = "unspecified"
	AuthMethodCleartext   AuthMethod = "cleartext"
	AuthMethodMD5         AuthMethod = "md5"
	AuthMethodSCRAMSHA256 AuthMethod = "scram-sha-256"
)

// ValidAuthMethod checks if a given AuthMethod is valid.
func ValidAuthMethod(d AuthMethod) bool {
	switch d {
	case AuthMethodUnspecified, AuthMethodCleartext,
		AuthMethodMD5, AuthMethodSCRAMSHA256:
		return true
	}
	return false
}