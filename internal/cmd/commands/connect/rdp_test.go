// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"runtime"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// defaultExec tests
// ---------------------------------------------------------------------------

func TestRdpFlags_DefaultExec_Empty(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })

	tests := []struct {
		name     string
		goos     string
		style    string
		expected string
	}{
		{"linux empty → xfreerdp", "linux", "", "xfreerdp"},
		{"darwin empty → open", "darwin", "", "open"},
		{"windows empty → mstsc.exe", "windows", "", "mstsc.exe"},
		{"freebsd empty → xfreerdp", "freebsd", "", "xfreerdp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.GOOS = tt.goos
			r := &rdpFlags{flagRdpStyle: tt.style}
			got := r.defaultExec()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRdpFlags_DefaultExec_Explicit(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })

	tests := []struct {
		name     string
		goos     string
		style    string
		expected string
	}{
		{"darwin xfreerdp", "darwin", "xfreerdp", "xfreerdp"},
		{"darwin mstsc → mstsc", "darwin", "mstsc", "mstsc"},
		{"darwin open", "darwin", "open", "open"},
		{"linux XFREErdp (case)", "linux", "XFREErdp", "xfreerdp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.GOOS = tt.goos
			r := &rdpFlags{flagRdpStyle: tt.style}
			got := r.defaultExec()
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// buildArgsWithEndpoint tests — xfreerdp
// ---------------------------------------------------------------------------

func TestRdpFlags_BuildArgs_XfreeRdp_NoCreds(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "xfreerdp"}
	c := &cmdWrapper{
		sessionAuthzData: &sessionAuthzData{endpoint: "tcp://127.0.0.1:3389"},
	}
	addr := "127.0.0.1:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, credentials{})
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:127.0.0.1:3389"}, args)
	assert.Empty(t, retCreds.usernamePassword)
}

func TestRdpFlags_BuildArgs_XfreeRdp_WithUsernamePassword(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "xfreerdp"}
	creds := credentials{
		usernamePassword: []usernamePassword{
			{
				Username: "admin",
				Password: "secret123",
				raw:      &targets.SessionCredential{},
			},
		},
	}
	c := &cmdWrapper{
		sessionAuthzData: &sessionAuthzData{endpoint: "tcp://127.0.0.1:3389"},
	}
	addr := "192.168.1.10:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "192.168.1.10", addr, creds)
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:192.168.1.10:3389", "/u:admin", "/p:secret123"}, args)
	// Credential should be consumed so it doesn't print to user
	assert.True(t, retCreds.usernamePassword[0].usernamePasswordConsumed())
}

func TestRdpFlags_BuildArgs_XfreeRdp_UsernameOnly(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "xfreerdp"}
	creds := credentials{
		usernamePassword: []usernamePassword{
			{Username: "admin", raw: &targets.SessionCredential{}},
		},
	}
	c := &cmdWrapper{sessionAuthzData: &sessionAuthzData{}}
	addr := "127.0.0.1:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, creds)
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:127.0.0.1:3389", "/u:admin"}, args)
	// No /p: because password is absent — not consumed
	assert.False(t, retCreds.usernamePassword[0].usernamePasswordConsumed())
}

func TestRdpFlags_BuildArgs_XfreeRdp_PasswordOnly(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "xfreerdp"}
	creds := credentials{
		usernamePassword: []usernamePassword{
			{Password: "secret123", raw: &targets.SessionCredential{}},
		},
	}
	c := &cmdWrapper{sessionAuthzData: &sessionAuthzData{}}
	addr := "127.0.0.1:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, creds)
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:127.0.0.1:3389", "/p:secret123"}, args)
	// consumed (username is empty but password is present, still consume to avoid leaking)
	assert.True(t, retCreds.usernamePassword[0].usernamePasswordConsumed())
}

// ---------------------------------------------------------------------------
// buildArgsWithEndpoint tests — mstsc
// ---------------------------------------------------------------------------

func TestRdpFlags_BuildArgs_Mstsc_NoCreds(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })
	runtime.GOOS = "windows"

	r := &rdpFlags{flagRdpStyle: "mstsc"}
	c := &cmdWrapper{
		sessionAuthzData: &sessionAuthzData{endpoint: "tcp://127.0.0.1:3389"},
		cleanupFuncs:     []func() error{},
	}
	addr := "127.0.0.1:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, credentials{})
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:127.0.0.1:3389"}, args)
	assert.Empty(t, retCreds.usernamePassword)
}

func TestRdpFlags_BuildArgs_Mstsc_WithCreds(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })
	runtime.GOOS = "windows"

	r := &rdpFlags{flagRdpStyle: "mstsc"}
	creds := credentials{
		usernamePassword: []usernamePassword{
			{
				Username: "DOMAIN\\admin",
				Password: "P@ssw0rd!",
				raw:      &targets.SessionCredential{},
			},
		},
	}
	c := &cmdWrapper{
		sessionAuthzData: &sessionAuthzData{endpoint: "tcp://192.168.1.10:3389"},
		cleanupFuncs:     []func() error{},
	}
	addr := "192.168.1.10:3389"
	args, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "192.168.1.10", addr, creds)
	require.NoError(t, err)
	assert.Equal(t, []string{"/v:192.168.1.10:3389"}, args)
	// Credential consumed so it won't print to user
	assert.True(t, retCreds.usernamePassword[0].usernamePasswordConsumed())
}

func TestRdpFlags_BuildArgs_Mstsc_OnNonWindows(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })
	runtime.GOOS = "linux"

	r := &rdpFlags{flagRdpStyle: "mstsc"}
	c := &cmdWrapper{sessionAuthzData: &sessionAuthzData{}}
	addr := "127.0.0.1:3389"
	_, _, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, credentials{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only available on Windows")
}

func TestRdpFlags_BuildArgs_Mstsc_UsernameOnlyNoCmdkey(t *testing.T) {
	origGoos := runtime.GOOS
	t.Cleanup(func() { runtime.GOOS = origGoos })
	runtime.GOOS = "windows"

	r := &rdpFlags{flagRdpStyle: "mstsc"}
	creds := credentials{
		usernamePassword: []usernamePassword{
			{Username: "admin", raw: &targets.SessionCredential{}}, // no password
		},
	}
	c := &cmdWrapper{
		sessionAuthzData: &sessionAuthzData{},
		cleanupFuncs:     []func() error{},
	}
	addr := "127.0.0.1:3389"
	_, retCreds, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, creds)
	require.NoError(t, err)
	// No cmdkey stored because password is absent — not consumed
	assert.False(t, retCreds.usernamePassword[0].usernamePasswordConsumed())
}

// ---------------------------------------------------------------------------
// buildArgsWithEndpoint tests — open (rdp:// URL)
// ---------------------------------------------------------------------------

func TestRdpFlags_BuildArgs_Open(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "open"}
	c := &cmdWrapper{sessionAuthzData: &sessionAuthzData{}}
	addr := "127.0.0.1:3389"
	args, _, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, credentials{})
	require.NoError(t, err)
	// open -n -W rdp://full%20address=s:<addr>
	assert.Equal(t, []string{"-n", "-W", "rdp://full%20address=s:127.0.0.1:3389"}, args)
}

// ---------------------------------------------------------------------------
// buildArgsWithEndpoint tests — unknown style
// ---------------------------------------------------------------------------

func TestRdpFlags_BuildArgs_UnknownStyle(t *testing.T) {
	r := &rdpFlags{flagRdpStyle: "rdesktop"}
	c := &cmdWrapper{sessionAuthzData: &sessionAuthzData{}}
	addr := "127.0.0.1:3389"
	_, _, err := r.buildArgsWithEndpoint(c, "3389", "127.0.0.1", addr, credentials{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown RDP style")
}