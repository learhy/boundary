// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRdpFlags_DefaultExec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		style          string
		goos           string
		wantExec       string
		wantStyleSaved string
	}{
		{
			name:           "empty style linux defaults to xfreerdp",
			style:          "",
			goos:           "linux",
			wantExec:       "xfreerdp",
			wantStyleSaved: "xfreerdp",
		},
		{
			name:           "empty style windows defaults to mstsc",
			style:          "",
			goos:           "windows",
			wantExec:       "mstsc.exe",
			wantStyleSaved: "mstsc.exe",
		},
		{
			name:           "empty style darwin defaults to open",
			style:          "",
			goos:           "darwin",
			wantExec:       "open",
			wantStyleSaved: "open",
		},
		{
			name:           "explicit xfreerdp",
			style:          "xfreerdp",
			goos:           "linux",
			wantExec:       "xfreerdp",
			wantStyleSaved: "xfreerdp",
		},
		{
			name:           "explicit mstsc normalized",
			style:          "mstsc",
			goos:           "linux",
			wantExec:       "mstsc.exe",
			wantStyleSaved: "mstsc.exe",
		},
		{
			name:           "explicit open",
			style:          "open",
			goos:           "darwin",
			wantExec:       "open",
			wantStyleSaved: "open",
		},
		{
			name:           "style is case insensitive",
			style:          "XFREERDP",
			goos:           "linux",
			wantExec:       "xfreerdp",
			wantStyleSaved: "xfreerdp",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &rdpFlags{flagRdpStyle: tc.style}
			got := r.defaultExec()
			assert.Equal(t, tc.wantExec, got, "defaultExec() mismatch")
		})
	}
}

// mockCmd is a minimal stand-in for *base.Command used in buildArgs tests.
// It only exposes the fields和方法 that buildArgsWithEndpoint actually uses.
type mockCmd struct {
	cleanupFuncs []func() error
}

func (m *mockCmd) registerCleanup(f func() error) {
	m.cleanupFuncs = append(m.cleanupFuncs, f)
}

// credCmd is the interface that buildArgsWithEndpoint uses to register cleanup.
// It mirrors the minimal interface of *base.Command needed for rdpFlags.buildArgs.
type credCmd interface {
	registerCleanup(f func() error)
}

// cmdWrapper wraps a mockCmd to implement the credCmd interface.
type cmdWrapper struct{ m *mockCmd }

func (w *cmdWrapper) registerCleanup(f func() error) { w.m.registerCleanup(f) }

func TestRdpFlags_BuildArgs_XFreeRDP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		style         string
		endpoint      string
		addr          string
		creds         credentials
		wantArgs      []string
		wantConsumed  bool
		wantErr       bool
	}{
		{
			name:     "xfreerdp with username and password",
			style:    "xfreerdp",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("alice", "secret123")),
			wantArgs: []string{"/v:rdp.example.com", "/u:alice", "/p:secret123"},
		},
		{
			name:     "xfreerdp with username only",
			style:    "xfreerdp",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("alice", "")),
			wantArgs: []string{"/v:rdp.example.com", "/u:alice"},
		},
		{
			name:     "xfreerdp with password only",
			style:    "xfreerdp",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("", "secret123")),
			wantArgs: []string{"/v:rdp.example.com", "/p:secret123"},
		},
		{
			name:     "xfreerdp no credentials",
			style:    "xfreerdp",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    credentials{},
			wantArgs: []string{"/v:rdp.example.com"},
		},
		{
			name:     "xfreerdp falls back to addr when endpoint empty",
			style:    "xfreerdp",
			endpoint: "",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("alice", "secret123")),
			wantArgs: []string{"/v:127.0.0.1:50000", "/u:alice", "/p:secret123"},
		},
		{
			name:     "xfreerdp with IP endpoint",
			style:    "xfreerdp",
			endpoint: "10.0.0.5",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("bob", "pass456")),
			wantArgs: []string{"/v:10.0.0.5", "/u:bob", "/p:pass456"},
		},
		{
			name:     "xfreerdp with port in endpoint",
			style:    "xfreerdp",
			endpoint: "rdp.example.com:3389",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("charlie", "pw")),
			wantArgs: []string{"/v:rdp.example.com:3389", "/u:charlie", "/p:pw"},
		},
		{
			name:     "xfreerdp consumes first credential",
			style:    "xfreerdp",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds: manyCreds(
				usernamePasswordCred("alice", "secret123"),
				usernamePasswordCred("bob", "ignored"),
			),
			wantArgs: []string{"/v:rdp.example.com", "/u:alice", "/p:secret123"},
			// Only first credential consumed; second remains.
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &rdpFlags{flagRdpStyle: tc.style}
			mockC := &mockCmd{}
			args, retCreds, err := r.buildArgsWithEndpoint(
				&cmdWrapper{m: mockC},
				"50000", "127.0.0.1", tc.addr, tc.endpoint, tc.creds,
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantArgs, args)
			if tc.wantConsumed && len(retCreds.usernamePassword) > 0 {
				assert.True(t, retCreds.usernamePassword[0].consumed, "first credential should be marked consumed")
			}
		})
	}
}

// cmdWrapperForBuildArgs wraps a mockCmd for use with buildArgsWithEndpoint.
// It captures the registered cleanup functions for verification.
type cmdWrapperForBuildArgs struct {
	mock *mockCmd
}

// registerCleanup implements the minimal Command interface for buildArgsWithEndpoint.
func (w *cmdWrapperForBuildArgs) registerCleanup(f func() error) {
	w.mock.registerCleanup(f)
}

func TestRdpFlags_BuildArgs_Mstsc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		endpoint          string
		addr              string
		creds             credentials
		wantArgs          []string
		wantCleanupCalled bool
		wantErr           bool
	}{
		{
			name:     "mstsc with username and password",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("alice", "secret123")),
			wantArgs: []string{"/v", "rdp.example.com"},
			// cleanup registered; verified via cleanupFuncs count.
		},
		{
			name:     "mstsc username only",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("alice", "")),
			wantArgs: []string{"/v", "rdp.example.com"},
		},
		{
			name:     "mstsc no credentials",
			endpoint: "rdp.example.com",
			addr:     "127.0.0.1:50000",
			creds:    credentials{},
			wantArgs: []string{"/v", "rdp.example.com"},
			// No cleanup registered when no creds.
		},
		{
			name:     "mstsc falls back to addr when endpoint empty",
			endpoint: "",
			addr:     "127.0.0.1:50000",
			creds:    manyCreds(usernamePasswordCred("bob", "pw")),
			wantArgs: []string{"/v", "127.0.0.1:50000"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &rdpFlags{flagRdpStyle: "mstsc.exe"}
			mockC := &mockCmd{}
			args, retCreds, err := r.buildArgsWithEndpoint(
				&cmdWrapperForBuildArgs{mock: mockC},
				"50000", "127.0.0.1", tc.addr, tc.endpoint, tc.creds,
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantArgs, args)
			if tc.wantCleanupCalled {
				assert.NotEmpty(t, mockC.cleanupFuncs, "cleanup function should be registered")
			}
		})
	}
}

func TestRdpFlags_BuildArgs_Open(t *testing.T) {
	t.Parallel()

	r := &rdpFlags{flagRdpStyle: "open"}
	mockC := &mockCmd{}
	args, _, err := r.buildArgsWithEndpoint(
		&cmdWrapperForBuildArgs{mock: mockC},
		"50000", "127.0.0.1", "127.0.0.1:50000", "", credentials{},
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"-n", "-W", "rdp://full%20address=s:127.0.0.1:50000"}, args)
	// open style does not register cleanup (no cmdkey involved).
	assert.Empty(t, mockC.cleanupFuncs)
}

func TestRdpFlags_BuildArgs_UnknownStyle(t *testing.T) {
	t.Parallel()

	r := &rdpFlags{flagRdpStyle: "not-a-client"}
	_, _, err := r.buildArgsWithEndpoint(
		&cmdWrapperForBuildArgs{mock: &mockCmd{}},
		"50000", "127.0.0.1", "127.0.0.1:50000", "", credentials{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown RDP style")
	assert.Contains(t, err.Error(), "not-a-client")
}

// usernamePasswordCred constructs a usernamePassword credential struct for tests.
func usernamePasswordCred(username, password string) usernamePassword {
	cred := targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: "username_password",
		},
		Credential: map[string]any{},
	}
	if username != "" {
		cred.Credential["username"] = username
	}
	if password != "" {
		cred.Credential["password"] = password
	}
	return usernamePassword{
		Username: username,
		Password: password,
		raw:      &cred,
	}
}

// manyCreds wraps one or more usernamePassword structs into a credentials value.
func manyCreds(up ...usernamePassword) credentials {
	return credentials{usernamePassword: up}
}