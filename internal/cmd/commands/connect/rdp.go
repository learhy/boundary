// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	rdpSynopsis = "Authorize a session against a target and invoke an RDP client to connect"
)

// sessionAuthzData holds the subset of session authorization data needed by the RDP handler.
type sessionAuthzData struct {
	endpoint string
	typ      string
	hostId   string
	targetId string
}

// rdpCommandProvider abstracts *Command for buildArgsWithEndpoint so tests can
// provide a cmdWrapper without depending on unexported Command fields.
type rdpCommandProvider interface {
	getSessionAuthzData() *sessionAuthzData
	getCleanupFuncs() *[]func() error
}

// cmdWrapper is the test-side implementation of rdpCommandProvider.
type cmdWrapper struct {
	sessionAuthzData *sessionAuthzData
	cleanupFuncs     []func() error
}

func (w *cmdWrapper) getSessionAuthzData() *sessionAuthzData { return w.sessionAuthzData }
func (w *cmdWrapper) getCleanupFuncs() *[]func() error       { return &w.cleanupFuncs }

func rdpOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("RDP Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagRdpStyle,
		EnvVar:     "BOUNDARY_CONNECT_RDP_STYLE",
		Completion: complete.PredictSet("xfreerdp", "mstsc", "open"),
		Usage:      `Specifies how the CLI will attempt to invoke an RDP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "xfreerdp" (Linux default), "mstsc" (Windows default, launches the Windows client), and "open" (macOS default, launches via an rdp:// URL).`,
	})
}

type rdpFlags struct {
	flagRdpStyle string
}

func (r *rdpFlags) defaultExec() string {
	r.flagRdpStyle = strings.ToLower(r.flagRdpStyle)
	switch r.flagRdpStyle {
	case "":
		switch runtime.GOOS {
		case "windows":
			r.flagRdpStyle = "mstsc"
		case "darwin":
			r.flagRdpStyle = "open"
		default:
			// xfreerdp is the standard open-source RDP client on Linux
			r.flagRdpStyle = "xfreerdp"
		}
	case "mstsc":
		if runtime.GOOS == "windows" {
			r.flagRdpStyle = "mstsc.exe"
		}
	}
	if r.flagRdpStyle == "mstsc" && runtime.GOOS == "windows" {
		r.flagRdpStyle = "mstsc.exe"
	}
	return r.flagRdpStyle
}

// buildArgsWithEndpoint builds the RDP client arguments with credential injection.
// It accepts rdpCommandProvider so both real *Command and test cmdWrapper satisfy it.
func (r *rdpFlags) buildArgsWithEndpoint(c rdpCommandProvider, port, ip, addr string, creds credentials) ([]string, credentials, error) {
	retCreds := creds

	// Resolve endpoint for potential future use (e.g. target-specific heuristics)
	endpoint := ""
	if c.getSessionAuthzData() != nil {
		endpoint = c.getSessionAuthzData().endpoint
	}

	style := r.flagRdpStyle
	if style == "mstsc" && runtime.GOOS == "windows" {
		style = "mstsc.exe"
	}

	switch style {
	case "xfreerdp":
		return r.buildArgsXfreeRdp(c, port, ip, addr, retCreds, endpoint)
	case "mstsc.exe":
		return r.buildArgsMstsc(c, port, ip, addr, retCreds, endpoint)
	case "open":
		return r.buildArgsOpen(port, ip, addr)
	default:
		// Also handle "mstsc" on non-Windows platforms gracefully
		if r.flagRdpStyle == "mstsc" && runtime.GOOS != "windows" {
			return nil, retCreds, errors.New(`"mstsc" style is only available on Windows`)
		}
		return nil, retCreds, fmt.Errorf("unknown RDP style: %q", r.flagRdpStyle)
	}
}

// buildArgsXfreeRdp builds xfreerdp arguments with credential injection.
// xfreerdp accepts /u:<user> /p:<password> /v:<host> directly on its command line.
func (r *rdpFlags) buildArgsXfreeRdp(c rdpCommandProvider, port, ip, addr string, creds credentials, endpoint string) ([]string, credentials, error) {
	var args []string

	// xfreerdp /v:<address> — address is host:port or just host
	args = append(args, "/v:"+addr)

	// Consume username/password credentials when available
	var username, password string
	if len(creds.usernamePassword) > 0 {
		// For now just grab the first username password credential brokered
		// Mark credential as consumed so it is not printed to user
		creds.usernamePassword[0].consumed = true
		username = creds.usernamePassword[0].Username
		password = creds.usernamePassword[0].Password
	}

	if username != "" {
		args = append(args, "/u:"+username)
	}
	if password != "" {
		args = append(args, "/p:"+password)
	}

	return args, creds, nil
}

// buildArgsMstsc builds mstsc.exe arguments with credential injection.
// Windows mstsc does not accept credentials on the command line.
// Instead, we use 'cmdkey' to store credentials in the Windows Credential Manager
// before launching mstsc targeting the host via /v:.
func (r *rdpFlags) buildArgsMstsc(c rdpCommandProvider, port, ip, addr string, creds credentials, endpoint string) ([]string, credentials, error) {
	var args []string

	// mstsc.exe /v:<address>
	args = append(args, "/v:"+addr)

	// Consume username/password credentials when available
	var username, password string
	if len(creds.usernamePassword) > 0 {
		creds.usernamePassword[0].consumed = true
		username = creds.usernamePassword[0].Username
		password = creds.usernamePassword[0].Password
	}

	if username != "" && password != "" {
		// cmdkey /generic:<target> /user:<username> /pass:<password>
		// Target is the host address; Windows uses this to match RDP sessions.
		cmdkeyCmd := exec.Command("cmdkey", "/generic:"+addr, "/user:"+username, "/pass:"+password)
		if err := cmdkeyCmd.Run(); err != nil {
			return nil, creds, fmt.Errorf("failed to store credentials via cmdkey: %w", err)
		}
		// Register cleanup to purge the stored credential when the session ends.
		// This is best-effort — the credential may linger if the process is killed.
		if cleanupFuncs := c.getCleanupFuncs(); cleanupFuncs != nil {
			*cleanupFuncs = append(*cleanupFuncs, func() error {
				purgeCmd := exec.Command("cmdkey", "/delete:"+addr)
				_ = purgeCmd.Run() // best-effort
				return nil
			})
		}
	}

	return args, creds, nil
}

// buildArgsOpen builds arguments for launching via rdp:// URL (macOS default).
// Credential injection is not supported via the URL scheme — user will be prompted.
func (r *rdpFlags) buildArgsOpen(port, ip, addr string) ([]string, credentials, error) {
	// open -n opens in a new window, -W waits for the app to exit
	// rdp:// URL: rdp://full%20address=s:<host>
	args := []string{"-n", "-W", fmt.Sprintf("rdp://full%%20address=s:%s", addr)}
	return args, credentials{}, nil
}

// buildArgs is the public-facing method called from connect.go handleExec.
// It adapts the *Command receiver to the rdpCommandProvider interface.
func (r *rdpFlags) buildArgs(c *Command, port, ip, addr string, creds credentials) ([]string, credentials, error) {
	var authzData *sessionAuthzData
	if c.sessionAuthzData != nil {
		authzData = &sessionAuthzData{
			endpoint: c.sessionAuthzData.GetEndpoint(),
			typ:      c.sessionAuthzData.GetType(),
			hostId:   c.sessionAuthzData.GetHostId(),
			targetId: c.sessionAuthzData.GetTargetId(),
		}
	}
	wrapper := &cmdWrapper{
		sessionAuthzData: authzData,
		cleanupFuncs:     c.cleanupFuncs,
	}
	return r.buildArgsWithEndpoint(wrapper, port, ip, addr, creds)
}