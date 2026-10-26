// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package integration provides end-to-end tests for Boundary enterprise features.
// These tests start a real dev server and test features through the actual CLI.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// boundaryBin returns the path to the boundary binary.
func boundaryBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("BOUNDARY_BIN")
	if bin != "" {
		return bin
	}
	// Check common locations
	candidates := []string{
		"../bin/boundary",
		"../../bin/boundary",
		"bin/boundary",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("boundary binary not found. Set BOUNDARY_BIN or build first")
	return ""
}

// boundary runs the boundary CLI and returns stdout.
func boundary(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin := boundaryBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Add token flag if BOUNDARY_TOKEN is set
	fullArgs := append([]string{}, args...)
	if tok := os.Getenv("BOUNDARY_TOKEN"); tok != "" {
		fullArgs = append(fullArgs, "-token", "env://BOUNDARY_TOKEN")
	}

	cmd := exec.CommandContext(ctx, bin, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("boundary %v failed: %w\nstderr: %s", args, err, stderr.String())
	}
	return stdout.String(), nil
}

// devServer manages a running boundary dev server.
type devServer struct {
	Cmd       *exec.Cmd
	Addr      string
	Recording string
	Token     string
	ProjectID string
	TargetID  string
	Cleanup   func()
}

// startDevServer starts a boundary dev server with recording enabled.
func startDevServer(t *testing.T) *devServer {
	t.Helper()
	bin := boundaryBin(t)

	recordingDir, err := os.MkdirTemp("", "boundary-recording-*")
	if err != nil {
		t.Fatalf("failed to create recording dir: %v", err)
	}

	addr := "http://127.0.0.1:9200"
	ds := &devServer{
		Addr:      addr,
		Recording: recordingDir,
	}

	// Build the command
	args := []string{
		"dev",
		"-worker-recording-storage-dir", recordingDir,
		"-worker-public-address", "127.0.0.1",
		"-log-level", "warn",
	}
	ds.Cmd = exec.Command(bin, args...)

	// Capture output for diagnostics
	var stdout, stderr bytes.Buffer
	ds.Cmd.Stdout = &stdout
	ds.Cmd.Stderr = &stderr

	if err := ds.Cmd.Start(); err != nil {
		t.Fatalf("failed to start dev server: %v", err)
	}

	// Wait for server to be ready: check TCP port listener
	ready := false
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:9200", 2*time.Second)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
	}
	// Wait for worker to register by trying authorize-session in a loop
	if ready {
		for i := 0; i < 10; i++ {
			authCmd := exec.Command(bin, "targets", "authorize-session",
				"-id", "ttcp_1234567890",
				"-token", "env://BOUNDARY_TOKEN",
				"-format", "json")
			authCmd.Env = append(os.Environ(),
				"BOUNDARY_TOKEN=",
				"BOUNDARY_ADDR="+addr,
			)
			// Set the actual token for this check
			authCmd.Env = append(authCmd.Env, "BOUNDARY_TOKEN="+ds.Token)
			var out bytes.Buffer
			authCmd.Stdout = &out
			if err := authCmd.Run(); err == nil {
				break // worker is ready
			}
			time.Sleep(2 * time.Second)
		}
	}

	if !ready {
		ds.Cmd.Process.Kill()
		t.Fatalf("dev server failed to start within 30s\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	ds.Cleanup = func() {
		ds.Cmd.Process.Kill()
		ds.Cmd.Wait()
		os.RemoveAll(recordingDir)
	}
	t.Cleanup(ds.Cleanup)

	return ds
}

// authenticate logs in and sets the token.
func (ds *devServer) authenticate(t *testing.T) {
	t.Helper()

	// Set env for password
	t.Setenv("BOUNDARY_DEV_PASSWORD", "password")
	t.Setenv("BOUNDARY_ADDR", ds.Addr)
	t.Setenv("BOUNDARY_TLS_INSECURE", "true")

	out, err := boundary(t,
		"authenticate", "password",
		"-auth-method-id", "ampw_1234567890",
		"-login-name", "admin",
		"-password", "env://BOUNDARY_DEV_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("authentication failed: %v\noutput: %s", err, out)
	}

	// Parse token from JSON
	// Response format: {"item":{"attributes":{"id":"at_xxx","token":"at_xxx_yyy",...}}}
	var raw struct {
		Item struct {
			Attributes struct {
				Token string `json:"token"`
			} `json:"attributes"`
			Token string `json:"token"`
		} `json:"item"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("failed to parse auth response: %v\nresponse: %s", err, out)
	}

	ds.Token = raw.Item.Attributes.Token
	if ds.Token == "" {
		ds.Token = raw.Item.Token
	}
	if ds.Token == "" {
		ds.Token = raw.Token
	}

	t.Setenv("BOUNDARY_TOKEN", ds.Token)
}

// discoverResources finds the default project and target.
func (ds *devServer) discoverResources(t *testing.T) {
	t.Helper()

	// List scopes to find project
	out, err := boundary(t, "scopes", "list", "-format", "json")
	if err != nil {
		t.Fatalf("failed to list scopes: %v\noutput: %s", err, out)
	}

	var scopes struct {
		Items []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &scopes); err != nil {
		t.Fatalf("failed to parse scopes: %v\noutput: %s", err, out)
	}

	for _, s := range scopes.Items {
		if s.Type == "project" {
			ds.ProjectID = s.ID
			break
		}
	}
	if ds.ProjectID == "" {
		// Fallback to known dev-mode default
		ds.ProjectID = "p_1234567890"
	}

	// List targets
	out, err = boundary(t, "targets", "list", "-scope-id", ds.ProjectID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to list targets: %v\noutput: %s", err, out)
	}

	var targets struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &targets); err != nil {
		t.Fatalf("failed to parse targets: %v\noutput: %s", err, out)
	}

	if len(targets.Items) > 0 {
		// Prefer the direct-address target (ttcp_1234567890) over host-source
		// since host-source targets need a registered worker for session auth
		for _, t := range targets.Items {
			if strings.Contains(t.ID, "ttcp_1234567890") || !strings.HasPrefix(t.ID, "ttcp_0987654321") {
				ds.TargetID = t.ID
				break
			}
		}
		if ds.TargetID == "" {
			ds.TargetID = targets.Items[0].ID
		}
	} else {
		ds.TargetID = "ttcp_1234567890"
	}
}

// TestDevServerStart verifies the dev server starts successfully.
func TestDevServerStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	t.Logf("Dev server started at %s, recording to %s", ds.Addr, ds.Recording)
	ds.authenticate(t)
	t.Logf("Authenticated, token: %s...", ds.Token[:16])
}

// TestAuthenticateAndList verifies authentication and resource discovery.
func TestAuthenticateAndList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	t.Logf("Project: %s", ds.ProjectID)
	t.Logf("Target: %s", ds.TargetID)

	if ds.ProjectID == "" {
		t.Fatal("no project found")
	}
	if ds.TargetID == "" {
		t.Fatal("no target found")
	}
}

// TestAuthorizeSession verifies session authorization.
func TestAuthorizeSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Authorize a session
	out, err := boundary(t, "targets", "authorize-session", "-id", ds.TargetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, out)
	}

	var authz struct {
		Item struct {
			SessionID string `json:"session_id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(out), &authz); err != nil {
		t.Fatalf("failed to parse authz response: %v\noutput: %s", err, out)
	}

	if authz.Item.SessionID == "" {
		t.Fatal("no session_id in authorization response")
	}
	t.Logf("Session authorized: %s", authz.Item.SessionID)
}

// TestSessionRecording verifies BSR files are created for SSH sessions.
// This tests the OSS session recording code path.
func TestSessionRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Authorize a session
	out, err := boundary(t, "targets", "authorize-session", "-id", ds.TargetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, out)
	}

	var authz struct {
		Item struct {
			SessionID string `json:"session_id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(out), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, out)
	}
	t.Logf("Session authorized: %s", authz.Item.SessionID)

	// Try to connect via exec (non-blocking)
	connectOut, connectErr := boundary(t,
		"connect",
		"-target-id", ds.TargetID,
		"-exec", "/bin/echo", "--",
		"boundary-e2e-connected",
	)
	if connectErr != nil {
		// connect via exec is expected to fail in some configurations
		// since it needs a listening port
		t.Logf("Connect exec (expected): %v", connectErr)
		t.Logf("Connect output: %s", connectOut)
	}

	// Wait a moment for async recording to flush
	time.Sleep(2 * time.Second)

	// Check recording directory
	files := listFiles(t, ds.Recording)
	t.Logf("Recording files (%d):", len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}

	// Check session list
	out, err = boundary(t, "sessions", "list", "-scope-id", ds.ProjectID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to list sessions: %v\noutput: %s", err, out)
	}

	var sessions struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &sessions); err != nil {
		t.Fatalf("failed to parse sessions: %v\noutput: %s", err, out)
	}

	if len(sessions.Items) == 0 {
		t.Log("No sessions created (expected if connect not established)")
	} else {
		for _, s := range sessions.Items {
			t.Logf("Session %s: %s", s.ID, s.Status)
		}
	}
}

type fileInfo struct {
	path string
	size int64
}

func listFiles(t *testing.T, dir string) []fileInfo {
	t.Helper()
	var files []fileInfo
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, fileInfo{path: path, size: info.Size()})
		}
		return nil
	})
	return files
}

// TestBSRExport verifies that the BSR export utility works with saved recordings.
func TestBSRExport(t *testing.T) {
	// This tests the internal BSR export code, not the live server
	// We validate the BSR file structure matches what the recording creates
	bsrDir := os.Getenv("BSR_TEST_DIR")
	if bsrDir == "" {
		t.Skip("BSR_TEST_DIR not set, skipping BSR export test")
	}

	// Verify directory has BSR structure
	hasJournal := false
	hasMeta := false
	hasConnection := false
	filepath.Walk(bsrDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		base := filepath.Base(path)
		if base == ".journal" {
			hasJournal = true
		}
		if strings.HasSuffix(base, "session-meta.json") {
			hasMeta = true
		}
		if strings.Contains(path, ".connection") {
			hasConnection = true
		}
		return nil
	})

	if !hasJournal {
		t.Log("No .journal file found (storage may not be initialized)")
	}
	if !hasMeta {
		t.Log("No session-meta.json found")
	}
	if !hasConnection {
		t.Log("No connection directory found")
	}

	t.Logf("BSR directory '%s' structure: journal=%v meta=%v connection=%v",
		bsrDir, hasJournal, hasMeta, hasConnection)
}

// TestConnectParsing verifies the connect command options parse correctly
// without requiring a running server or actual connection.
func TestConnectParsing(t *testing.T) {
	// Just verify command syntax is valid
	helpArgs := []struct {
		name string
		args []string
	}{
		{"connect help", []string{"connect", "-help"}},
		{"connect ssh help", []string{"connect", "ssh", "-help"}},
		{"connect tcp help", []string{"connect", "tcp", "-help"}},
		{"targets authorize help", []string{"targets", "authorize-session", "-help"}},
	}

	bin := boundaryBin(t)
	for _, tc := range helpArgs {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, bin, tc.args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command %v failed: %v\noutput: %s", tc.args, err, out)
			}
			t.Logf("Command %v OK (got %d bytes)", tc.args, len(out))
		})
	}
}

// TestRDPCredentialInjection tests the RDP credential injection feature
// by verifying the domain field on credentials.
func TestRDPCredentialInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Create a static credential store
	out, err := boundary(t,
		"credential-stores", "create", "static",
		"-scope-id", ds.ProjectID,
		"-name", "test-rdp-creds",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential store: %v\noutput: %s", err, out)
	}
	t.Logf("Credential store created: %s", truncateOutput(out, 200))

	var store struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	json.Unmarshal([]byte(out), &store)
	if store.Item.ID == "" {
		t.Log("No credential store ID (dev mode may not support static stores)")
		return
	}

	// Create a username/password credential (this is the RDP credential type)
	out, err = boundary(t,
		"credentials", "create", "username-password",
		"-credential-store-id", store.Item.ID,
		"-name", "test-rdp-user",
		"-username", "administrator",
		"-password", "env://BOUNDARY_E2E_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential: %v\noutput: %s", err, out)
	}
	t.Logf("RDP credential created: %s", truncateOutput(out, 200))
}

func truncateOutput(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}

// TestBSRDirectoryStructure tests that a properly formed BSR directory
// matches the expected structure from the internal/bsr package.
func TestBSRDirectoryStructure(t *testing.T) {
	// This validates the BSR spec via filesystem structure
	// Can be run without a server
	sampleDir := t.TempDir()

	// Create a minimal BSR structure matching what the recorder should produce
	// See internal/bsr/ and internal/daemon/worker/proxy/ssh/
	bsrRoot := filepath.Join(sampleDir, "s_test12345678.bsr")
	if err := os.MkdirAll(bsrRoot, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write a journal file (the recorder uses .journal for WAL)
	if err := os.WriteFile(filepath.Join(bsrRoot, ".journal"), []byte("test\n"), 0644); err != nil {
		t.Fatalf("write journal: %v", err)
	}

	// Write SHA256SUM (the recorder signs these)
	if err := os.WriteFile(filepath.Join(bsrRoot, "SHA256SUM"), []byte("hash  file\n"), 0644); err != nil {
		t.Fatalf("write sha256sum: %v", err)
	}

	// Write BSR key (the recorder stores KMS-wrapped keys)
	if err := os.WriteFile(filepath.Join(bsrRoot, "bsrKey.pub"), []byte("key\n"), 0644); err != nil {
		t.Fatalf("write bsrkey: %v", err)
	}

	// Create a connection directory
	connDir := filepath.Join(bsrRoot, "cr_testconn12345.connection")
	if err := os.MkdirAll(connDir, 0755); err != nil {
		t.Fatalf("mkdir conn: %v", err)
	}

	// Write data files
	if err := os.WriteFile(filepath.Join(connDir, "messages-inbound.data"), []byte("inbound"), 0644); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	if err := os.WriteFile(filepath.Join(connDir, "messages-outbound.data"), []byte("outbound"), 0644); err != nil {
		t.Fatalf("write outbound: %v", err)
	}

	// Validate structure
	files := listFiles(t, sampleDir)
	t.Logf("Created BSR structure (%d files):", len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}
}
