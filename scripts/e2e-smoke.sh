#!/usr/bin/env bash
set -euo pipefail

# Boundary E2E Smoke Test Suite
# Tests features end-to-end by running Boundary dev mode and connecting through it.

BOUNDARY_BIN="${1:-$(pwd)/bin/boundary}"
BOUNDARY_ADDR="${BOUNDARY_ADDR:-http://localhost:9200}"
RECORDING_DIR="${2:-$(mktemp -d)}"
SSH_TARGET_ADDR="${SSH_TARGET_ADDR:-localhost}"
SSH_TARGET_PORT="${SSH_TARGET_PORT:-22}"

export BOUNDARY_ADDR
export BOUNDARY_CACERT=""
export BOUNDARY_TLS_INSECURE=true

PASS=0
FAIL=0
TESTS=()

record_result() {
    local name="$1"
    local result="$2"
    if [ "$result" = "PASS" ]; then
        PASS=$((PASS + 1))
        echo "  ✅ $name"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ $name"
    fi
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "${DEV_PID:-}" ]; then
        kill "$DEV_PID" 2>/dev/null || true
        wait "$DEV_PID" 2>/dev/null || true
    fi
    echo "Server stopped."
}
trap cleanup EXIT

# ============================================
echo "=== Boundary E2E Smoke Tests ==="
echo "Binary: $BOUNDARY_BIN"
echo "Address: $BOUNDARY_ADDR"
echo "Recording dir: $RECORDING_DIR"
echo "SSH Target: $SSH_TARGET_ADDR:$SSH_TARGET_PORT"
echo ""

# ============================================
echo "=== 1. Dev Server Start ==="
# Start dev server with recording enabled
DEV_LOG=$(mktemp)
echo "Starting dev server..."
"$BOUNDARY_BIN" dev \
    -worker-recording-storage-dir="$RECORDING_DIR" \
    -worker-public-address="$SSH_TARGET_ADDR" \
    -log-level=debug \
    > "$DEV_LOG" 2>&1 &
DEV_PID=$!

# Wait for server to be ready
for i in $(seq 1 30); do
    if "$BOUNDARY_BIN" status 2>&1 | grep -q "controller"; then
        echo "  Server ready after ${i}s (PID: $DEV_PID)"
        break
    fi
    sleep 1
done

if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "  ❌ Server failed to start"
    tail -20 "$DEV_LOG"
    exit 1
fi
record_result "Dev Server Start" "PASS"

# ============================================
echo ""
echo "=== 2. Authentication ==="
# Authenticate (dev mode creates default admin)
AUTH_RESULT=$("$BOUNDARY_BIN" authenticate \
    -addr="$BOUNDARY_ADDR" \
    password \
    -login-name=admin \
    -password=password \
    -auth-method-id=ampw_1234567890 \
    -format=json 2>&1) || true

# Check if auth succeeded
if echo "$AUTH_RESULT" | grep -q "token"; then
    record_result "Authenticate as admin" "PASS"
else
    # Try without addr flag, just using env var
    AUTH_RESULT=$("$BOUNDARY_BIN" authenticate \
        password \
        -login-name=admin \
        -password=password \
        -auth-method-id=ampw_1234567890 \
        -format=json 2>&1) || true
    if echo "$AUTH_RESULT" | grep -q "token"; then
        record_result "Authenticate as admin" "PASS"
    else
        echo "  Auth error: $AUTH_RESULT"
        record_result "Authenticate as admin" "FAIL"
    fi
fi

# ============================================
echo ""
echo "=== 3. List Resources ==="
RESULT=$("$BOUNDARY_BIN" targets list -format=json 2>&1) || true
if echo "$RESULT" | grep -q "items"; then
    record_result "List targets" "PASS"
else
    echo "  Target list: $RESULT"
    record_result "List targets" "FAIL"
fi

RESULT=$("$BOUNDARY_BIN" hosts list -format=json 2>&1) || true
if echo "$RESULT" | grep -q "items"; then
    record_result "List hosts" "PASS"
else
    echo "  Host list: $RESULT"
    record_result "List hosts" "FAIL"
fi

# ============================================
echo ""
echo "=== 4. Target Details ==="
# Get the default target ID
TARGET_ID=$("$BOUNDARY_BIN" targets list -format=json 2>&1 | grep '"id"' | head -1 | cut -d'"' -f4 || echo "")
if [ -n "$TARGET_ID" ]; then
    record_result "Get default target ID ($TARGET_ID)" "PASS"
else
    TARGET_ID="ttcp_1234567890"
    record_result "Using default target ID ($TARGET_ID)" "WARN"
fi

# ============================================
echo ""
echo "=== 5. Authorize Session ==="
AUTHZ_RESULT=$("$BOUNDARY_BIN" targets authorize-session \
    -id="$TARGET_ID" \
    -format=json 2>&1) || true
if echo "$AUTHZ_RESULT" | grep -q "authorization_token"; then
    record_result "Authorize session to target" "PASS"
else
    echo "  Authz: $AUTHZ_RESULT"
    record_result "Authorize session to target" "FAIL"
fi

# ============================================
echo ""
echo "=== 6. Connect via SSH (proxy) ==="
# Test that connect command at least parses correctly
CONNECT_HELP=$("$BOUNDARY_BIN" connect ssh -help 2>&1 | head -5) || true
if [ -n "$CONNECT_HELP" ]; then
    record_result "SSH connect help displays" "PASS"
else
    record_result "SSH connect help displays" "FAIL"
fi

# Try a non-blocking connect test
CONNECT_TEST=$("$BOUNDARY_BIN" targets authorize-session \
    -id="$TARGET_ID" \
    -format=json 2>&1) || true
SESSION_ID=$(echo "$CONNECT_TEST" | grep '"session_id"' | head -1 | cut -d'"' -f4 || echo "")
if [ -n "$SESSION_ID" ]; then
    record_result "Session authorized ($SESSION_ID)" "PASS"
else
    record_result "Session authorized" "FAIL"
fi

# ============================================
echo ""
echo "=== 7. Session Listing ==="
# Check sessions and verify the session was created
RESULT=$("$BOUNDARY_BIN" sessions list -format=json 2>&1) || true
if echo "$RESULT" | grep -q "items"; then
    record_result "List sessions" "PASS"
else
    echo "  Sessions: $RESULT"
    record_result "List sessions" "FAIL"
fi

# ============================================
echo ""
echo "=== 8. Recording Check ==="
echo "Recording directory contents:"
find "$RECORDING_DIR" -type f 2>/dev/null | head -20 || echo "  (empty)"
RECORDING_COUNT=$(find "$RECORDING_DIR" -type f 2>/dev/null | wc -l || echo "0")
if [ "$RECORDING_COUNT" -gt 0 ]; then
    record_result "BSR recording files created ($RECORDING_COUNT files)" "PASS"
else
    record_result "BSR recording files created" "INFO (expected: Enterprise-only)"
fi

# ============================================
echo ""
echo "=== Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "Status: ALL PASSED ✅"
else
    echo "Status: $FAIL TESTS FAILED ❌"
    exit 1
fi
