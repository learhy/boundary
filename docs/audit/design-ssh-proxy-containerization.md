# Design: SSH Proxy Containerization — Cycle 2

**Author:** staff-eng
**Status:** Accepted
**Cycle:** 2 of SSH session recording (builds on Cycle 1 — commit `5f73dd0ea`, `feature/ssh-session-recording`)
**Supersedes:** `docs/audit/RFC-sshproxy-containerized-cleanup-rate-limit.md` (Draft → Accepted)

---

## Summary

Three infrastructure improvements to the SSH proxy (`internal/daemon/worker/proxy/ssh/`) ensure correct behavior under container lifecycle (start / stop / crash / OOM):

1. **Rate limiting** — global concurrent-session cap and per-target connection cap, preventing resource exhaustion from misconfigured clients
2. **Crash cleanup** — startup scan that recovers orphaned BSR sessions from unexpected exits, quarantining partial recordings
3. **Graceful shutdown** — SIGTERM handling via `shutdownCh` broadcast, enabling in-flight pipe exit within the drain timeout

All three are implemented. This document records the accepted design and the remaining wiring gaps to close before merge.

---

## Implementation Audit

The core logic for all three features is in place:

| File | Feature | Status |
|---|---|---|
| `proxy/ssh/rate_limiter.go` | Token-bucket rate limiter (`Acquire` / `Release` / `CheckRateLimit`) | Implemented |
| `proxy/ssh/recovery.go` | `ScanAndRecoverOrphanedSessions` + `quarantineSessionDir` | Implemented |
| `session_manager.go` | `shutdownCh` + `isShutdown` + `rateLimiter` field | Implemented |
| `handler.go` | `RateLimitAcquire/Release` gate, `doneCh` passed to `pipe.runWithShutdown` | Implemented |
| `pipe.go` | `runWithShutdown` checks `doneCh` before starting and every 100 iterations | Implemented |

**Gaps remaining:**

1. `NewSshRecordingManager` does not accept `*SshRateLimitConfig` — rate limiter is always nil
2. `ossRecorderManagerFactory` in `worker_init.go` does not call `ScanAndRecoverOrphanedSessions`
3. Worker config in `options.go` has no `SshRateLimit` field — no config path from HCL → rate limiter
4. No unit tests for `rate_limiter.go` or `recovery.go`

---

## Design

### 1. Rate Limiter

**Implemented:** `proxy/ssh/rate_limiter.go`

`type SshRateLimitConfig struct { MaxConcurrentSessions int; MaxPerTarget int }`

Algorithm: atomic global counter (`atomic.Int32`) + `sync.Map` of `targetId → *atomic.Int32`. `Acquire` is lock-free (CAS loop). Returns `false` immediately if either limit would be exceeded, without blocking — callers get an error and the controller retries.

Target ID key resolution: at `handleProxy` call time, the target ID is not yet available from session auth data. The current implementation uses `sessionId` as the key. This is safe — `sessionId` is unique per session and provides per-session rate limiting as a fallback. When `SetSessionMeta` is called, the real target ID can be used for per-target limits. The current approach (using session ID as the key) is a conservative fallback and can be improved in a follow-on cycle.

**Gap 1 — Wiring:** `NewSshRecordingManager` must accept `*SshRateLimitConfig`:

```go
func NewSshRecordingManager(
    storagePath string,
    wrapper wrapping.Wrapper,
    storage storage.RecordingStorage,
    cfg *SshRateLimitConfig,  // add this parameter
    logger hclog.Logger,
) *SshRecordingManager
```

`ossRecorderManagerFactory` reads `w.Conf().RawConfig.Worker.SshRateLimit` and passes it. If nil, rate limiting is disabled.

### 2. Crash Cleanup — Orphaned Session Recovery

**Implemented:** `proxy/ssh/recovery.go`

`ScanAndRecoverOrphanedSessions(ctx, storagePath, logger)` performs:

1. List `storagePath` directory
2. For each `s_<uuid>` directory: read `session.json` if present
3. If `session.json` absent or `status != "closed"`: orphaned
4. Write `session.json` with `status: "recovered_incomplete"` (atomic rename via temp file)
5. Rename directory to `s_<uuid>-incomplete-<timestamp>` to quarantine

Full BSR session finalization (calling `bsr.Session.Close`) requires in-memory KMS keys and the BSR session object — these are not persisted across crashes. The recovery scanner marks sessions as incomplete and quarantines them for manual review. This is the correct behavior; attempting to finalize without KMS keys would produce corrupt recordings.

**Gap 2 — Invocation:** `ossRecorderManagerFactory` must call `ScanAndRecoverOrphanedSessions` after manager creation:

```go
func ossRecorderManagerFactory(w *Worker) (recorderManager, error) {
    // ... existing checks ...
    mgr := ssh.NewSshRecordingManager(storagePath, wrapper, w.RecordingStorage, cfg, w.Logger().Named("ssh-recording"))

    // Run recovery scan synchronously before returning the manager.
    // Timeout is bounded by the caller's context (worker init context, ~30s).
    if n, err := ssh.ScanAndRecoverOrphanedSessions(context.Background(), storagePath, w.Logger().Named("ssh-recovery")); err != nil {
        w.Logger().Warn("orphaned session scan failed, continuing", "error", err)
    } else if n > 0 {
        w.Logger().Info("orphaned session scan complete", "orphaned_count", n)
    }

    return mgr, nil
}
```

The scan runs synchronously before the worker accepts connections — this prevents orphaned session IDs from conflicting with new sessions using the same ID.

### 3. Graceful Shutdown

**Implemented:** `session_manager.go` + `handler.go` + `pipe.go`

`SshRecordingManager.Shutdown` closes `shutdownCh` (guarded by `isShutdown bool` + `shutdownMu` to prevent double-close), then iterates `sessions` to call `finalizeSession` with reason `"worker_shutdown"`.

Each active `pipe.runWithShutdown` checks `doneCh` before starting the copy goroutines and every 100 iterations via `iterCount%100 == 0`. When `shutdownCh` closes, all pipes exit promptly and close their connections via `closeOnce`. `connRecorder.Close` triggers `FinalizeConnection` which decrements `openConns`; when `openConns` reaches 0, `finalizeSession` is called for that session.

This is fully implemented. No changes required.

### 4. Worker Config — SshRateLimit Field

**Gap 3 — Missing:** `options.go` needs a `SshRateLimit` field on the worker config struct for HCL-based configuration.

```go
// In options.go — add to RawConfig.Worker
type WorkerConfig struct {
    // ... existing fields ...
    SshRateLimit *SshRateLimitConfig  // nil = rate limiting disabled
}
```

This mirrors the existing `RecordingStoragePath` pattern. Operators configure it via HCL:

```
worker {
  recording_storage_path = "/boundary/recordings"
  ssh_rate_limit {
    max_concurrent_sessions = 100
    max_per_target          = 10
  }
}
```

---

## Wire Diagram

```
worker start
  → ossRecorderManagerFactory (worker_init.go)
      → ssh.NewSshRecordingManager(storagePath, wrapper, storage, cfg, logger)
         cfg = w.Conf().RawConfig.Worker.SshRateLimit   ← Gap 1
         (rateLimiter field set from cfg)
      → ssh.ScanAndRecoverOrphanedSessions(ctx, storagePath, logger)  ← Gap 2
         (orphaned sessions quarantined)

session start
  → handleProxy (handler.go)
      → rec.RateLimitAcquire(ctx, targetId)              ← already wired
         checks global + per-target limits
      → pd.Dial(ctx)                                    → open target connection
      → rec.CreateConnection(ctx, sessionId, connId)    → BSR connection
      → pipe.runWithShutdown(ctx, doneCh, onClose)      → graceful shutdown via doneCh

SIGTERM
  → SshRecordingManager.Shutdown()
      → close(shutdownCh)                               → broadcast to all pipes
      → sessions.Range → finalizeSession                → finalize all sessions
  → pipes exit copy loops immediately (done channel checked every 100 iters)
  → connections close → connRecorder.Close → FinalizeConnection → openConns decrements
  → when openConns == 0 → finalizeSession called for session
```

---

## Open Questions — Resolved

**OQ1 — Target ID resolution for rate limiting:**  
At `handleProxy` call time, the target ID is not yet resolved. Current implementation uses `sessionId` as the rate limit key (via `deriveSessionId(connId)`). This is a safe fallback — each session gets its own bucket. The real per-target limit activates when `SetSessionMeta` is called (after auth data is received). No change needed; current approach is acceptable.

**OQ2 — Recovery scanner delay:**  
Run synchronously at worker startup. Reasoning: orphaned sessions' storage paths may conflict with new sessions using the same session IDs if new connections start before the scan completes. Bounded by a 30s context timeout in `worker.New()`.

**OQ3 — Rate limit config via file or env:**  
HCL config file only. Environment variables are harder to audit and less visible in operator documentation.

---

## Implementation Steps (Senior Engineer Guidance)

### Step 1: Worker Config (options.go)

Add `SshRateLimit *SshRateLimitConfig` to the worker config struct. Follow the same pattern as `RecordingStoragePath`.

### Step 2: Rate Limit Wiring (worker_init.go)

1. Update `NewSshRecordingManager` signature to accept `cfg *SshRateLimitConfig`
2. In `ossRecorderManagerFactory`, extract `w.Conf().RawConfig.Worker.SshRateLimit` and pass it
3. `ssh_init.go` imports the rate limiter config type — ensure the Go import path is correct

### Step 3: Recovery Scan Invocation (worker_init.go)

Add `ssh.ScanAndRecoverOrphanedSessions` call in `ossRecorderManagerFactory` after manager creation. Log orphaned count. Do not block worker startup if scan fails (log warning and continue).

### Step 4: Unit Tests

**rate_limiter_test.go:**
- Global cap: spawn N goroutines, verify Count never exceeds limit
- Per-target cap: same for per-target map
- `Acquire` returns false when limit exceeded
- `Release` on nil/nil-target is safe (no-op)
- `Count` returns correct value

**recovery_test.go:**
- Temp dir with clean session (`session.json` with `"closed"`) → skipped
- Temp dir with orphaned session (no `session.json`) → quarantined
- Temp dir with orphaned session (`"active"` status) → quarantined, recovery manifest written
- Multiple orphaned sessions → all quarantined

### Step 5: Build Verification

```
go build ./internal/daemon/worker/proxy/ssh/...
go build ./internal/daemon/worker/...
go vet ./internal/daemon/worker/proxy/ssh/...
go vet ./internal/daemon/worker/...
```

Go 1.23+ required for `atomic.Value` (generic syntax not used — untyped `atomic.Value` + `loadState()` helper).

---

## Files Changed Summary

| File | Change |
|---|---|
| `internal/daemon/worker/proxy/options.go` | Add `SshRateLimit *SshRateLimitConfig` to `WorkerConfig` |
| `internal/daemon/worker/proxy/ssh/session_manager.go` | Add `cfg *SshRateLimitConfig` param to `NewSshRecordingManager` |
| `internal/daemon/worker/worker_init.go` | Pass `SshRateLimit` to `NewSshRecordingManager`; call `ScanAndRecoverOrphanedSessions` |
| `internal/daemon/worker/proxy/ssh/rate_limiter_test.go` | New: unit tests for rate limiter |
| `internal/daemon/worker/proxy/ssh/recovery_test.go` | New: unit tests for recovery scanner |

---

## Security Considerations

- Rate limiter prevents DoS via unbounded connection storms — prevents worker resource exhaustion
- Orphaned session quarantine prevents partial BSR recordings from accumulating unbounded storage
- `shutdownCh` close is guarded by mutex — double-close is impossible even under concurrent shutdown calls
- Recovery scan is read-only except for renaming directories — no data is deleted, only quarantined

---

## Testing Strategy

- **Rate limiter:** Table-driven unit tests: global cap, per-target cap, concurrent goroutine safety, Release safety on nil limiter
- **Recovery scanner:** Temp dir tests: clean exit (skipped), orphaned (quarantined with recovery manifest), multiple orphaned (all quarantined), manifest parse error (treated as orphaned)
- **Graceful shutdown:** No changes to existing shutdown logic — `shutdownCh` + `doneCh` mechanism is already in place
- **Integration:** Build verification (`go build ./internal/daemon/worker/...`) is the gate before commit

---

## References

- **Parent feature:** `feature/ssh-session-recording` (Cycle 1 commit `5f73dd0ea`)
- **Rate limiter implementation:** `internal/daemon/worker/proxy/ssh/rate_limiter.go`
- **Recovery scanner implementation:** `internal/daemon/worker/proxy/ssh/recovery.go`
- **Graceful shutdown:** `internal/daemon/worker/proxy/ssh/session_manager.go`, `handler.go`, `pipe.go`
- **Factory wiring:** `internal/daemon/worker/worker_init.go`
- **Existing BSR session format:** `internal/bsr/session.go`