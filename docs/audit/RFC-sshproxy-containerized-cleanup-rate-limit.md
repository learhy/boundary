# RFC: SSH Proxy Containerization — Cycle 2
## Containerized sshproxy with cleanup and rate limiter

**Author:** staff-eng  
**Created:** 2026-05-30  
**Status:** Superseded — see `docs/audit/design-ssh-proxy-containerization.md` (Accepted)  
**Replaces:** (none — Cycle 2 of SSH session recording, builds on Cycle 1)  
**PRD Source:** t_cb9c0f1a (researcher brief)

---

## Summary

Cycle 2 of the SSH session recording feature adds three infrastructure improvements to the
SSH proxy handler (`internal/daemon/worker/proxy/ssh/`):

1. **Rate limiting** — global concurrent-session cap and per-target connection cap
2. **Crash cleanup** — startup scan that recovers orphaned BSR sessions from unexpected exits
3. **Graceful shutdown** — SIGTERM handling with connection drain timeout before finalizing BSR sessions

These changes are confined to the `internal/daemon/worker/proxy/ssh/` package and
`internal/daemon/worker/worker_init.go`. The SSH proxy remains part of the boundary
worker binary; no sidecar process is introduced. The "containerized" aspect is ensuring
correct behavior under container lifecycle (start/stop/crash) rather than extracting a
separate process.

---

## Background

Cycle 1 (commit e1b675cb7) delivered the core BSR session recording infrastructure:

- `handler.go`: intercepting pipe architecture, bidirectional copy with BSR chunk emission
- `pipe.go`: Option B bidirectional copy with `InterceptingConn` wrapping
- `recorder.go`: `ConnectionRecorder` wrapping BSR connection with channel tracking
- `session_manager.go`: `SshRecordingManager` with BSR session state machine (initializing → active → closing → closed)
- `ssh_init.go`: handler registration via `proxy.RegisterHandler`
- `worker_init.go`: OSS recorder manager factory wiring

Three gaps remain for production container deployment:

1. **No rate limiting** — a misconfigured target or client can open unbounded concurrent SSH
   connections, exhausting worker resources. No mechanism exists to cap total or per-target
   concurrency.
2. **Orphaned sessions on crash** — if the container is killed (OOM, `docker kill`, node
   preemption), in-flight sessions in `initializing` or `active` state are never finalized.
   BSR chunk files are left on disk with no DB record, leaking storage and leaving partial
   recordings.
3. **No graceful shutdown protocol** — the current `Shutdown()` method on
   `SshRecordingManager` finalizes sessions synchronously, but `handleProxy` runs in a
   goroutine with no mechanism to interrupt in-flight pipe copies on SIGTERM. Under
   `docker stop` with default 10s timeout, connections are abruptly closed and BSR sessions
   end in `active` state with partial data.

---

## Design

### 1. Rate Limiter

**Location:** `internal/daemon/worker/proxy/ssh/rate_limiter.go`

**Config fields** (added to worker config `RawConfig.Worker`):

```go
type SshRateLimitConfig struct {
    MaxConcurrentSessions int // global cap; 0 = unlimited
    MaxPerTarget          int // per target-id cap; 0 = unlimited
}
```

**Algorithm:** Token-bucket per target + global counter.
- Global counter: atomic int32 tracking active sessions. Incremented on session start,
  decremented on close.
- Per-target map (`sync.Map` of `targetId → atomic.Int32`). Keyed on the target ID from
  the session authorization data (extracted from `bsr.SessionMeta.Target.PublicId`).
- Before `handleProxy` opens the target connection, it checks both limits. If either is
  exceeded, returns an error; the worker responds to the controller with a connection
  error.

**State:** `SshRecordingManager` gains a `*rateLimiter` field initialized at construction.

```go
type rateLimiter struct {
    global    atomic.Int32
    perTarget sync.Map // targetId(string) → atomic.Int32
    maxGlobal int
    maxTarget int
}
```

**Check at handleProxy entry:**
```go
if m.rateLimiter != nil {
    if !m.rateLimiter.Acquire(ctx, targetId) {
        return nil, boundaryErrors.New(controlCtx, boundaryErrors.LimitExceeded, op, "ssh session rate limit exceeded")
    }
    defer m.rateLimiter.Release(targetId)
}
```

**Deferral:** `defer m.rateLimiter.Release(targetId)` must be registered after successful
connection open, not before, so crash before connection open does not leak the slot.

**Target ID resolution:** The target ID is not available at `handleProxy` call time — only
the `connId` and `pd *ProxyDialer`. The target ID is derived from `connId → sessionId →
target info`. For rate limiting at connection time, use a best-effort key from the
`ProxyDialer` connection target or fall back to `"_unknown_"` for the first request while
metadata is being resolved. The per-target counter for `_unknown_` provides a ceiling on
unidentified connections as a protective measure.

### 2. Crash Cleanup — Orphaned Session Recovery

**Location:** `internal/daemon/worker/proxy/ssh/recovery.go`  
**Invocation:** Called from `worker_init.go` `ossRecorderManagerFactory` at worker startup.

**What it scans:**
The `storagePath` directory (configured via `worker.recording_storage_path`) contains one
subdirectory per BSR session ID. Each session directory has a `session.json` manifest file.
If the worker exited cleanly, `session.json` is absent (finalized) or contains a `closed`
status. If the worker crashed, the directory exists with a partial/incomplete BSR.

**Algorithm:**
1. List all entries in `storagePath`.
2. For each entry that is a directory with name matching `s_<uuid>` (session ID pattern),
   read `entry/session.json` if present.
3. If `session.json` is absent or `status != "closed"`, the session is orphaned.
4. For orphaned sessions: log a warning, rename the directory to `s_<uuid>-incomplete-<timestamp>`
   to quarantine it, and emit a metric/event.
5. Sessions that were in `closing` state at crash may have valid data — the recovery
   scanner should attempt to finalize them (call `bsr.Session.Close`) before quarantine,
   so recordings are not lost if the crash was brief.

**Implementation detail:** Use `storage.NewSyncingFS` to walk the directory tree. The
recovery scanner is stateless — it does not update the `sessions` sync.Map (those sessions
are gone). It operates purely on the filesystem.

```go
func ScanAndRecoverOrphanedSessions(ctx context.Context, storagePath string, storage storage.RecordingStorage, logger hclog.Logger) error
```

### 3. Graceful Shutdown — Context Cancellation for In-Flight Sessions

**Changes to:** `handler.go`, `session_manager.go`, `worker_init.go`

**Problem:** `pipe.run(ctx)` blocks on `io.Copy` until connections close. When SIGTERM
arrives, the worker's `ctx` is cancelled, but `pipe.run` holds a copy of that context at
the time of call and does not check it until the next buffer read. Under load, a
long-running SSH session (e.g., interactive shell) can block shutdown indefinitely.

**Solution:** Add a `done` channel to `pipe` that signals immediate termination on shutdown.

**In `SshRecordingManager.Shutdown`:**
```go
func (m *SshRecordingManager) Shutdown(ctx context.Context) {
    // Signal all in-flight pipes to close immediately.
    close(m.shutdownCh) // new field: shutdownCh chan struct{}
    // Finalize all sessions with reason "worker_shutdown".
    m.sessions.Range(...)
}
```

**In `pipe.run`:**
```go
func (p *pipe) run(ctx context.Context, done <-chan struct{}) {
    // Check done before starting copies.
    select {
    case <-done:
        p.close()
        return
    default:
    }
    // ... bidirectional copy ...
}
```

The `shutdownCh` is created in `NewSshRecordingManager` as `make(chan struct{})`. Closing
it broadcasts shutdown to all active pipes. Each pipe checks it before starting and can
check it periodically (every N reads) for faster response.

**Drain timeout:** The worker's existing graceful shutdown has a configurable timeout.
The `Shutdown()` call is already bounded by the caller's context. The key improvement is
that closing `shutdownCh` causes all pipes to exit their copy loops immediately rather
than waiting for the next read timeout.

**Connection finalization order:**
1. Close `shutdownCh` → all pipes close their connections immediately
2. `pipe.close()` closes both `clientConn` and `targetConn`
3. Each `pipe.close()` triggers `connRecorder.Close` via the `closeOnce`
4. `connRecorder.Close` → `FinalizeConnection` on the manager
5. When last connection closes → `finalizeSession` is called asynchronously
6. `Shutdown()` iterates remaining sessions and finalizes any that didn't close via
   connection tear-down

---

## Implementation Plan

### Step 1: Rate Limiter (`rate_limiter.go`)
- Add `rate_limiter.go` with `rateLimiter` struct, `Acquire`, `Release`, `Count`
- Add `SshRateLimitConfig` type
- Add `rateLimiter` field to `SshRecordingManager`
- Modify `NewSshRecordingManager` to accept `*SshRateLimitConfig`
- Wire config from worker `RawConfig.Worker.SshRateLimit` in `worker_init.go`
- Gate `handleProxy` connection open with rate limit check
- Add unit tests: global cap, per-target cap, concurrent safety

### Step 2: Recovery Scanner (`recovery.go`)
- Add `recovery.go` with `ScanAndRecoverOrphanedSessions`
- Add call in `ossRecorderManagerFactory` after manager creation
- Log orphaned sessions at WARN, quarantine with timestamp suffix
- Add unit tests: no orphans, one orphan, multiple orphans

### Step 3: Graceful Shutdown
- Add `shutdownCh chan struct{}` to `SshRecordingManager`
- Add `shutdownMu sync.Mutex` and `isShutdown bool` to prevent double-close
- Modify `Shutdown()` to close `shutdownCh` then finalize sessions
- Pass `shutdownCh` to `handleProxy` via a closure over the recording manager's shutdown channel
- Modify `pipe.run` to accept done channel and check it before starting copies
- Add periodic done-check in `copyClientToTarget` and `copyTargetToClient` (every 100 reads)

### Step 4: Worker Config
- Add `SshRateLimit` field to the worker's config struct
- Document `worker.ssh_rate_limit { max_concurrent_sessions, max_per_target }` in config docs

---

## Alternative Approaches Considered

**Rate limiter as middleware in `proxy.go`:** Could add rate limiting at the generic proxy
layer, but the per-target limit requires target ID resolution that is only available after
the session authorization data is fetched (in the SSH handler). Limiting at the proxy layer
would only support global limits. Keeping the rate limiter inside the SSH package is the
right place.

**Sidecar process for SSH handler:** Extracting the SSH proxy as a separate binary and
communicating via Unix socket would provide process isolation but adds significant
operational complexity (two container images, socket coordination, double the attack surface).
Not warranted for the current feature scope. Revisit if SSH-specific processing requires
different dependencies or privilege levels than the main worker.

**Crash recovery via BSR manifest file:** Could write a `recording.json` manifest at
session creation time and check it on startup, but this requires changes to the BSR library
(`internal/bsr`). The filesystem scan approach is self-contained and works with the existing
BSR session format.

**Context-with-timeout per pipe:** Could pass a context with shutdown timeout to each
`pipe.run`, but that requires the shutdown timeout to be communicated at `handleProxy` call
time. The done-channel approach is simpler and composes with the existing context handling.

---

## Open Questions

1. **Target ID resolution for rate limiting:** At `handleProxy` call time, the target ID is
   not yet resolved from the session authorization. Should rate limiting use a preliminary
   key (e.g., `"worker-<worker-id>"`) until the real target ID is known, or should we defer
   rate limit checks until after `SetSessionMeta` is called?
   **Proposed answer:** Use a best-effort key from the connection metadata available at
   `handleProxy` time. If unavailable, use `"_unidentified_"` as a catch-all bucket. This
   prevents unbounded connection storms from unidentified sources while the session metadata
   is being resolved.

2. **Recovery scanner delay:** Should the recovery scan run synchronously at worker startup
   (blocking `worker.New()`) or asynchronously in a background goroutine?
   **Proposed answer:** Run synchronously but with a timeout (30s max). Orphaned session
   recovery should complete before the worker accepts new connections, otherwise the
   orphaned sessions' storage paths may conflict with new sessions using the same IDs.

3. **Rate limit config via file or env:** Should `SshRateLimitConfig` be read from the HCL
   config file or from environment variables?
   **Proposed answer:** HCL config file only. Environment variables are harder to audit and
   less visible in operator documentation.

---

## Files Changed

```
internal/daemon/worker/proxy/ssh/rate_limiter.go      [new]
internal/daemon/worker/proxy/ssh/recovery.go          [new]
internal/daemon/worker/proxy/ssh/handler.go           [modify: done channel, rate limit gate]
internal/daemon/worker/proxy/ssh/pipe.go              [modify: run signature, done check]
internal/daemon/worker/proxy/ssh/session_manager.go   [modify: shutdownCh, rateLimiter field]
internal/daemon/worker/worker_init.go                 [modify: SshRateLimitConfig wiring, recovery scan]
internal/daemon/worker/proxy/options.go               [modify: SshRateLimit field on worker config]
internal/daemon/worker/proxy/ssh/rate_limiter_test.go [new]
internal/daemon/worker/proxy/ssh/recovery_test.go     [new]
```

---

## Testing Strategy

- **Rate limiter:** Table-driven unit tests for global cap, per-target cap, concurrent
  goroutines hitting the limiter simultaneously, and cleanup on session close.
- **Recovery scanner:** Tests with temp directories simulating: clean exit (session.json
  closed), crash mid-session (session.json active), partial directory, no session.json.
  Assert orphaned directories are renamed with `incomplete-<timestamp>` suffix.
- **Graceful shutdown:** Integration test that starts an SSH session, sends SIGTERM to the
  worker, and asserts that BSR sessions are finalized within the drain timeout and that
  `shutdownCh` is closed exactly once.
- **Compile and vet:** All modified packages must pass `go build ./internal/daemon/worker/...`
  and `go vet ./internal/daemon/worker/...` before commit.
