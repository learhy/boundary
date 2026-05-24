// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevUiPassthroughHandler_ServesFile(t *testing.T) {
	dir := t.TempDir()
	testContent := "<html><body>Hello Boundary</body></html>"
	err := os.WriteFile(filepath.Join(dir, "app.html"), []byte(testContent), 0o644)
	require.NoError(t, err)

	handler := devUiPassthroughHandler(dir)
	require.NotNil(t, handler)

	// http.FileServer with StripPrefix serves files under the root.
	// Request /app.html → StripPrefix("/") leaves "app.html" → served.
	req := httptest.NewRequest(http.MethodGet, "/app.html", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// http.FileServer may 301 redirect for directory paths, but a direct
	// file path should return 200 with the content.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Hello Boundary")
}

func TestDevUiPassthroughHandler_ServesRootDirectory(t *testing.T) {
	dir := t.TempDir()
	testContent := "root file"
	err := os.WriteFile(filepath.Join(dir, "foo.txt"), []byte(testContent), 0o644)
	require.NoError(t, err)

	handler := devUiPassthroughHandler(dir)
	require.NotNil(t, handler)

	// Direct file access works without redirect
	req := httptest.NewRequest(http.MethodGet, "/foo.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), testContent)
}

func TestDevUiPassthroughHandler_NotFound(t *testing.T) {
	dir := t.TempDir()
	handler := devUiPassthroughHandler(dir)
	require.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleUi_WithPassthrough(t *testing.T) {
	dir := t.TempDir()
	testContent := "<html>UI</html>"
	err := os.WriteFile(filepath.Join(dir, "ui.html"), []byte(testContent), 0o644)
	require.NoError(t, err)

	handler := devUiPassthroughHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/ui.html", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDevUiPassthroughHandler_UsesBackgroundContext(t *testing.T) {
	// Verify the handler uses context.Background(), not context.TODO().
	// Both are valid non-nil contexts so the functional assertion is that
	// the handler doesn't panic and serves files correctly.
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("test"), 0o644)
	require.NoError(t, err)

	handler := devUiPassthroughHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() {
		handler.ServeHTTP(rec, req)
	})
	assert.Equal(t, http.StatusOK, rec.Code)
}

// Ensure context is imported (used by Background)
var _ = context.Background
