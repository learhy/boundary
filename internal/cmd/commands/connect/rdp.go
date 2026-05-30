// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
	execexe "os/exec"
)

const (
	rdpSynopsis = "Authorize a session against a target and invoke an RDP client to connect"
)

func rdpOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("RDP Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagRdpStyle,
		EnvVar:     "BOUNDARY_CONNECT_RDP_STYLE",
		Completion: complete.PredictSet("mstsc", "open", "xfreerdp"),
		Usage:      `Specifies how the CLI will attempt to invoke an RDP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "mstsc" (default on Windows), "open" (default on Mac), and "xfreerdp" (default on Linux).`,
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
			r.flagRdpStyle = "xfreerdp"
		}
	}
	if r.flagRdpStyle == "mstsc" {
		r.flagRdpStyle = "mstsc.exe"
	}
	return r.flagRdpStyle
}

// buildArgs consumes a single UsernamePassword credential (if present) and
// returns the args required to launch the RDP client.  endpoint is the RDP
// target address from session authorization (e.g. "rdp.example.com:3389") and
// is used for xfreerdp /v: argument and Windows cmdkey /generic: target.
//
// Linux / xfreerdp: credentials are passed via /u:<user> and /p:<password> CLI
// arguments.  This is visible in process listings; NLA enforcement on the RDP
// target limits the exposure window.
//
// Windows / mstsc.exe: credentials are registered with cmdkey.exe in the Windows
// Credential Manager target before launching mstsc.  A cleanup hook is registered
// to delete the cmdkey entry after the session ends.
//
// macOS / open: launches via rdp:// URL; the OS prompts for credentials if needed.
// No credential injection from CLI args.
func (r *rdpFlags) buildArgs(c *Command, port, ip, addr string, creds credentials) ([]string, credentials, error) {
	return r.buildArgsWithEndpoint(c, port, ip, addr, "", creds)
}

// buildArgsWithEndpoint is like buildArgs but accepts an explicit RDP target
// endpoint for styles that need it (xfreerdp, mstsc).  When endpoint is empty,
// the addr parameter is used as a fallback.
func (r *rdpFlags) buildArgsWithEndpoint(c *Command, port, ip, addr string, endpoint string, creds credentials) ([]string, credentials, error) {
	var args []string
	retCreds := creds

	// Use endpoint if provided, otherwise fall back to addr (proxied local address).
	// addr is the local proxy listener; endpoint is the actual RDP target host.
	if endpoint == "" {
		endpoint = addr
	}

	switch r.flagRdpStyle {
	case "xfreerdp":
		args = append(args, "/v:"+endpoint)

		if len(creds.usernamePassword) > 0 {
			cred := creds.usernamePassword[0]
			cred.consumed = true
			retCreds.usernamePassword[0] = cred

			if cred.Username != "" {
				args = append(args, "/u:"+cred.Username)
			}
			// Pass password directly on the xfreerdp CLI — the design acknowledges
			// this is visible in process listings (see design doc §Security).
			if cred.Password != "" {
				args = append(args, "/p:"+cred.Password)
			}
		}

	case "mstsc.exe":
		// Register credentials with cmdkey before launching mstsc.
		// cmdkey persists entries in Windows Credential Manager (TargetCredential).
		// mstsc automatically looks up the matching target entry.
		if len(creds.usernamePassword) > 0 {
			cred := creds.usernamePassword[0]
			cred.consumed = true
			retCreds.usernamePassword[0] = cred

			var cmdkeyUser, cmdkeyPass string
			if cred.Username != "" {
				cmdkeyUser = cred.Username
			}
			if cred.Password != "" {
				cmdkeyPass = cred.Password
			}

			// Pre-launch cmdkey to register the credential before mstsc starts.
			// cmdkey is a built-in of cmd.exe; invoke via cmd /c.
			// cmdkey syntax: cmdkey.exe /generic:<target> /user:<user> /pass:<pass>
			cmdkeyParts := []string{"cmdkey.exe", "/generic:" + endpoint}
			if cmdkeyUser != "" {
				cmdkeyParts = append(cmdkeyParts, "/user:"+cmdkeyUser)
			}
			if cmdkeyPass != "" {
				cmdkeyParts = append(cmdkeyParts, "/pass:"+cmdkeyPass)
			}
			// We ignore errors — if cmdkey fails (e.g. no Credential Manager access),
			// mstsc will fall back to prompting the user interactively.
			cmdkeyCmd := []string{"/c", "cmdkey.exe"}
			cmdkeyCmd = append(cmdkeyCmd, cmdkeyParts[1:]...)
			_ = execexe.Command("cmd.exe", cmdkeyCmd...).Run()

			// Register cleanup to delete the cmdkey entry after the session ends,
			// preventing long-term credential persistence on the workstation.
			cleanupEndpoint := endpoint
			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				// Ignore errors — the entry may have already been removed or never
				// created if cmdkey failed above or if mstsc was never reached.
				_ = execexe.Command("cmd.exe", "/c", "cmdkey.exe", "/delete:"+cleanupEndpoint).Run()
				return nil
			})
		}

		args = append(args, "/v", endpoint)

	case "open":
		// macOS: open -n -W rdp://... launches via URL.  The OS prompts for
		// credentials if NLA is required.  No CLI-level credential injection.
		args = append(args, "-n", "-W", fmt.Sprintf("rdp://full%saddress=s:%s", "%20", addr))

	default:
		return nil, credentials{}, fmt.Errorf("unknown RDP style: %q", r.flagRdpStyle)
	}

	return args, retCreds, nil
}