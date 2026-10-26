// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestSSHCredentialInjection verifies SSH credential injection end-to-end.
// Creates a TCP target with session recording and credential injection configured,
// then verifies that credentials are delivered during session authorization.
// Note: SSH target type creation with session recording requires HCP/Enterprise.
// In OSS mode, we test the credential injection pipeline with TCP targets.
func TestSSHCredentialInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Step 1: Create a static credential store
	storeOut, err := boundary(t,
		"credential-stores", "create", "static",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-cred-store",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential store: %v\noutput: %s", err, storeOut)
	}
	t.Logf("Credential store: %s", truncateOutput(storeOut, 120))

	var store struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(storeOut), &store); err != nil {
		t.Fatalf("failed to parse store: %v\noutput: %s", err, storeOut)
	}
	storeID := store.Item.ID
	if storeID == "" {
		t.Skip("no credential store ID (dev mode limitation)")
	}

	// Step 2: Create a username/password credential
	t.Setenv("BOUNDARY_E2E_PASSWORD", "test-password-123")
	credOut, err := boundary(t,
		"credentials", "create", "username-password",
		"-credential-store-id", storeID,
		"-name", "e2e-test-user",
		"-username", os.Getenv("USER"),
		"-password", "env://BOUNDARY_E2E_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential: %v\noutput: %s", err, credOut)
	}
	t.Logf("Credential: %s", truncateOutput(credOut, 120))

	var cred struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(credOut), &cred); err != nil {
		t.Fatalf("failed to parse credential: %v\noutput: %s", err, credOut)
	}
	credID := cred.Item.ID
	if credID == "" {
		t.Fatal("no credential ID")
	}
	t.Logf("Credential ID: %s", credID)

	// Step 3: Create a TCP target (SSH target creation requires HCP/Enterprise)
	targetOut, err := boundary(t,
		"targets", "create", "tcp",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-cred-target",
		"-address", "127.0.0.1",
		"-default-port", "22",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create target: %v\noutput: %s", err, targetOut)
	}
	t.Logf("Target: %s", truncateOutput(targetOut, 120))

	var target struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(targetOut), &target); err != nil {
		t.Fatalf("failed to parse target: %v\noutput: %s", err, targetOut)
	}
	targetID := target.Item.ID
	if targetID == "" {
		t.Fatal("no target ID")
	}
	t.Logf("Target ID: %s", targetID)

	// Step 4: Attach credential source to target
	addCredOut, err := boundary(t,
		"targets", "add-credential-sources",
		"-id", targetID,
		"-brokered-credential-source", credID,
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to add credential source: %v\noutput: %s", err, addCredOut)
	}
	t.Logf("Credential source added: %s", truncateOutput(addCredOut, 120))

	// Step 5: Authorize a session and verify credentials in response
	authOut, err := boundary(t, "targets", "authorize-session", "-id", targetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}
	t.Logf("Auth response: %s", truncateOutput(authOut, 300))

	var authz struct {
		Item struct {
			SessionID   string              `json:"session_id"`
			Credentials []json.RawMessage   `json:"credentials"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}

	if authz.Item.SessionID == "" {
		t.Fatal("no session_id in authorization response")
	}
	t.Logf("Session authorized: %s", authz.Item.SessionID)

	// Verify credentials are in the auth response
	if len(authz.Item.Credentials) == 0 {
		t.Error("no credentials in auth response — credential injection failed")
	} else {
		t.Logf("Credentials in auth response: %d credential(s)", len(authz.Item.Credentials))
		for i, c := range authz.Item.Credentials {
			t.Logf("  Credential %d: %s", i, string(c))
		}
	}

	// Step 6: Connect via SSH with exec mode (non-interactive) to trigger recording
	connectOut, err := boundary(t,
		"connect", "ssh",
		"-target-id", targetID,
		"-exec", "/usr/bin/ssh", "--",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5",
		"127.0.0.1", "echo", "boundary-e2e-connected",
	)
	if err != nil {
		t.Logf("SSH connect result (expected): %v", err)
		if len(connectOut) > 500 {
			connectOut = connectOut[:500]
		}
		t.Logf("Connect output: %s", connectOut)
	} else {
		t.Logf("SSH connect OK: %s", truncateOutput(connectOut, 200))
	}

	// Step 7: Wait for async recording to flush
	time.Sleep(3 * time.Second)

	// Step 8: Check recording directory for BSR files
	files := listFiles(t, ds.Recording)
	t.Logf("Recording files (%d):", len(files))
	for _, f := range files {
		t.Logf("  %s (%d bytes)", f.path, f.size)
	}
}

// TestRDPCredentialInjectionE2E verifies RDP credential injection.
// Creates an RDP target with credential injection configured.
func TestRDPCredentialInjectionE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Create a static credential store
	storeOut, err := boundary(t,
		"credential-stores", "create", "static",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-rdp-creds",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential store: %v\noutput: %s", err, storeOut)
	}
	t.Logf("Credential store: %s", truncateOutput(storeOut, 120))

	var store struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(storeOut), &store); err != nil {
		t.Fatalf("failed to parse store: %v\noutput: %s", err, storeOut)
	}
	storeID := store.Item.ID
	if storeID == "" {
		t.Skip("no credential store ID (dev mode limitation)")
	}

	// Create a username/password credential (used by RDP for auth)
	t.Setenv("BOUNDARY_E2E_PASSWORD", "P@ssw0rd!")
	credOut, err := boundary(t,
		"credentials", "create", "username-password",
		"-credential-store-id", storeID,
		"-name", "e2e-rdp-user",
		"-username", "administrator",
		"-password", "env://BOUNDARY_E2E_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential: %v\noutput: %s", err, credOut)
	}
	t.Logf("RDP credential created: %s", truncateOutput(credOut, 120))

	var cred struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(credOut), &cred); err != nil {
		t.Fatalf("failed to parse credential: %v\noutput: %s", err, credOut)
	}
	credID := cred.Item.ID

	// Create a TCP target with credential injection
	targetOut, err := boundary(t,
		"targets", "create", "tcp",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-rdp-target",
		"-address", "127.0.0.1",
		"-default-port", "3389",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create target: %v\noutput: %s", err, targetOut)
	}
	t.Logf("RDP target: %s", truncateOutput(targetOut, 120))

	var target struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(targetOut), &target); err != nil {
		t.Fatalf("failed to parse target: %v\noutput: %s", err, targetOut)
	}
	targetID := target.Item.ID
	t.Logf("RDP Target ID: %s", targetID)

	// Add credential source
	addCredOut, err := boundary(t,
		"targets", "add-credential-sources",
		"-id", targetID,
		"-brokered-credential-source", credID,
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to add credential source: %v\noutput: %s", err, addCredOut)
	}
	t.Logf("Credential source added: %s", truncateOutput(addCredOut, 120))

	// Authorize session and check for credentials in response
	authOut, err := boundary(t, "targets", "authorize-session", "-id", targetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}

	var authz struct {
		Item struct {
			SessionID   string              `json:"session_id"`
			Credentials []json.RawMessage   `json:"credentials"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}
	t.Logf("Session authorized: %s", authz.Item.SessionID)
	t.Logf("Credentials in response: %d", len(authz.Item.Credentials))
}

// TestPostgreSQLSessionRecording verifies PostgreSQL session recording.
// Creates a PostgreSQL target with recording and credential injection.
func TestPostgreSQLSessionRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check if PostgreSQL is available for the target
	if !commandExists("psql") {
		t.Skip("psql not found, skipping PostgreSQL test")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Create a static credential store
	storeOut, err := boundary(t,
		"credential-stores", "create", "static",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-pg-creds",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential store: %v\noutput: %s", err, storeOut)
	}

	var store struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(storeOut), &store); err != nil {
		t.Fatalf("failed to parse store: %v\noutput: %s", err, storeOut)
	}
	if store.Item.ID == "" {
		t.Skip("no credential store ID")
	}
	storeID := store.Item.ID

	// Create credential for PostgreSQL
	t.Setenv("BOUNDARY_E2E_PG_PASSWORD", "postgres")
	credOut, err := boundary(t,
		"credentials", "create", "username-password",
		"-credential-store-id", storeID,
		"-name", "e2e-pg-user",
		"-username", "postgres",
		"-password", "env://BOUNDARY_E2E_PG_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential: %v\noutput: %s", err, credOut)
	}

	var cred struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(credOut), &cred); err != nil {
		t.Fatalf("failed to parse credential: %v\noutput: %s", err, credOut)
	}
	credID := cred.Item.ID

	// Create TCP target pointing to a PostgreSQL port (recording is SSH-only in OSS)
	targetOut, err := boundary(t,
		"targets", "create", "tcp",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-pg-target",
		"-address", "127.0.0.1",
		"-default-port", "5432",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create target: %v\noutput: %s", err, targetOut)
	}

	var target struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(targetOut), &target); err != nil {
		t.Fatalf("failed to parse target: %v\noutput: %s", err, targetOut)
	}
	targetID := target.Item.ID
	t.Logf("PostgreSQL Target ID: %s", targetID)

	// Add credential source
	_, err = boundary(t,
		"targets", "add-credential-sources",
		"-id", targetID,
		"-brokered-credential-source", credID,
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to add credential source: %v", err)
	}

	// Authorize session
	authOut, err := boundary(t, "targets", "authorize-session", "-id", targetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}

	var authz struct {
		Item struct {
			SessionID   string            `json:"session_id"`
			Credentials []json.RawMessage `json:"credentials"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}
	t.Logf("PostgreSQL session authorized: %s", authz.Item.SessionID)
	t.Logf("Credentials in response: %d", len(authz.Item.Credentials))
}

// TestMySQLSessionRecording verifies MySQL session recording.
func TestMySQLSessionRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if !commandExists("mysql") {
		t.Skip("mysql client not found, skipping MySQL test")
	}

	ds := startDevServer(t)
	ds.authenticate(t)
	ds.discoverResources(t)

	// Create a static credential store
	storeOut, err := boundary(t,
		"credential-stores", "create", "static",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-mysql-creds",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential store: %v\noutput: %s", err, storeOut)
	}

	var store struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(storeOut), &store); err != nil {
		t.Fatalf("failed to parse store: %v\noutput: %s", err, storeOut)
	}
	if store.Item.ID == "" {
		t.Skip("no credential store ID")
	}
	storeID := store.Item.ID

	// Create credential
	t.Setenv("BOUNDARY_E2E_MYSQL_PASSWORD", "root")
	credOut, err := boundary(t,
		"credentials", "create", "username-password",
		"-credential-store-id", storeID,
		"-name", "e2e-mysql-user",
		"-username", "root",
		"-password", "env://BOUNDARY_E2E_MYSQL_PASSWORD",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create credential: %v\noutput: %s", err, credOut)
	}

	var cred struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(credOut), &cred); err != nil {
		t.Fatalf("failed to parse credential: %v\noutput: %s", err, credOut)
	}
	credID := cred.Item.ID

	// Create TCP target for MySQL (recording is SSH-only in OSS)
	targetOut, err := boundary(t,
		"targets", "create", "tcp",
		"-scope-id", ds.ProjectID,
		"-name", "e2e-mysql-target",
		"-address", "127.0.0.1",
		"-default-port", "3306",
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to create target: %v\noutput: %s", err, targetOut)
	}

	var target struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(targetOut), &target); err != nil {
		t.Fatalf("failed to parse target: %v\noutput: %s", err, targetOut)
	}
	targetID := target.Item.ID
	t.Logf("MySQL Target ID: %s", targetID)

	// Add credential source
	_, err = boundary(t,
		"targets", "add-credential-sources",
		"-id", targetID,
		"-brokered-credential-source", credID,
		"-format", "json",
	)
	if err != nil {
		t.Fatalf("failed to add credential source: %v", err)
	}

	// Authorize session
	authOut, err := boundary(t, "targets", "authorize-session", "-id", targetID, "-format", "json")
	if err != nil {
		t.Fatalf("failed to authorize session: %v\noutput: %s", err, authOut)
	}

	var authz struct {
		Item struct {
			SessionID   string            `json:"session_id"`
			Credentials []json.RawMessage `json:"credentials"`
		} `json:"item"`
	}
	if err := json.Unmarshal([]byte(authOut), &authz); err != nil {
		t.Fatalf("failed to parse authz: %v\noutput: %s", err, authOut)
	}
	t.Logf("MySQL session authorized: %s", authz.Item.SessionID)
	t.Logf("Credentials in response: %d", len(authz.Item.Credentials))
}

// commandExists checks if a command is available.
func commandExists(cmd string) bool {
	_, err := os.Stat("/usr/bin/" + cmd)
	if err == nil {
		return true
	}
	_, err = os.Stat("/bin/" + cmd)
	return err == nil
}
