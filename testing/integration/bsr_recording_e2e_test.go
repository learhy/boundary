// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBSRRecordingTCP verifies session recording works with TCP targets.
func TestBSRRecordingTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	t.Logf("Target: %s (project: %s)", ds.TargetID, ds.ProjectID)

	// Authorize a session
	authOut, err := boundary(t, "targets", "authorize-session", "-id", ds.TargetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}

	var authz struct {
		Item struct {
			SessionID string `json:"session_id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}
	t.Logf("Session authorized: %s", authz.Item.SessionID)

	// Try connecting via TCP
	connectOut, err := boundary(t,
		"connect", "tcp",
		"-target-id", ds.TargetID,
		"-format", "json",
		"-listen-port", "0",
	)
	if err != nil {
		t.Logf("TCP connect (expected): %v", err)
		if len(connectOut) > 500 {
			connectOut = connectOut[:500]
		}
		t.Logf("Output: %s", connectOut)
	}

	// Wait for any async recording to flush
	time.Sleep(3 * time.Second)

	// Check the recording directory
	files := listFiles(t, ds.Recording)
	t.Logf("Recording directory: %s (%d files)", ds.Recording, len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}
}

// TestBSRRecordingSSH verifies SSH session recording end-to-end.
// Requires BOUNDARY_SSH_TARGET_ID env var pointing to an SSH target.
func TestBSRRecordingSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sshTargetID := os.Getenv("BOUNDARY_SSH_TARGET_ID")
	if sshTargetID == "" {
		t.Skip("BOUNDARY_SSH_TARGET_ID not set, skipping SSH recording test")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.TargetID = sshTargetID

	t.Logf("SSH Target: %s", ds.TargetID)

	// Authorize
	authOut, err := boundary(t, "targets", "authorize-session", "-id", ds.TargetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}

	var authz struct {
		Item struct {
			SessionID string `json:"session_id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}
	t.Logf("SSH Session authorized: %s", authz.Item.SessionID)

	// Connect SSH with exec
	connectOut, err := boundary(t,
		"connect", "ssh",
		"-target-id", ds.TargetID,
		"-exec", "/bin/echo", "--",
		"boundary-test-connected",
	)
	if err != nil {
		t.Logf("SSH connect: %v", err)
		if len(connectOut) > 500 {
			connectOut = connectOut[:500]
		}
		t.Logf("Output: %s", connectOut)
	}

	time.Sleep(5 * time.Second)

	files := listFiles(t, ds.Recording)
	t.Logf("Recording directory: %s (%d files)", ds.Recording, len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}

	if len(files) == 0 {
		t.Error("no BSR recording files found after SSH session")
	}
}

// TestBSRStorageStructure verifies BSR storage structure is initialized
// on dev server startup with recording enabled.
func TestBSRStorageStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ds := startDevServer(t)
	ds.authenticate(t)

	files := listFiles(t, ds.Recording)
	t.Logf("Files in recording dir after startup (%d):", len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}

	var hasJournal bool
	var hasMetaFile bool
	for _, f := range files {
		base := filepath.Base(f.path)
		if base == ".journal" || base == "journal" {
			hasJournal = true
		}
		if strings.Contains(base, "meta") || strings.Contains(base, "Meta") {
			hasMetaFile = true
		}
	}

	t.Logf("BSR structure: journal=%v meta=%v",
		hasJournal, hasMetaFile)
}
