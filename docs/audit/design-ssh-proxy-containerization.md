# SSH Proxy Containerization — Rate Limiting, Graceful Shutdown & Crash Recovery

**Status:** Accepted
**Cycle:** 2
**Author:** Staff Engineer
**Date:** May 2026
**Branch:** `feature/ssh-session-recording`
**Supersedes:** `docs/audit/RFC-sshproxy-containerized-cleanup-rate-limit.md`
**PRD Source:** researcher PRD (t_cb9c0f1a)
**Researcher Review:** Confirmed 2026-05-30 — design is sound; 4 genuine wiring gaps identified (see Gap Notes below)

---

## Summary

This RFC extends the base SSH session recording design (`docs/design/ssh-session-recording.md`) with three operational requirements that emerged from the containerization PRD: a token-bucket rate limiter controlling concurrent SSH sessions per target, a crash-recovery scanner that quarantines orphaned BSR session directories on worker startup, and graceful shutdown coordination that drains active proxy connections before exit. These three features are implemented as thin wrappers around the existing `SshRecordingManager` and `handleProxy` pipeline.

---

## Background

### What already exists

- `SshRecordingManager` (`proxy/ssh/session_manager.go`): manages in-memory BSR sessions keyed by Boundary session ID. Has a `Shutdown` method that calls `Close` on all sessions.
- `handleProxy` (`proxy/ssh/handler.go`): SSH proxy handler that returns a `ProxyConnFn` wrapping an `InterceptingPipe`. No external cancellation input.
- `ossRecorderManagerFactory` (`worker/worker_init.go`): creates `SshRecordingManager` from `RecordingStoragePath` config.
- Worker `Config` (`cmd/config/config.go`): `Worker.RecordingStoragePath` field already exists.
- BSR local filesystem storage (`bsrLocalFS`/`bsrLocalContainer` in `session_manager.go`): writes BSR sessions to single files under the recording root.

### What is missing

1. **No rate limiter.** The worker has no mechanism to bound concurrent SSH sessions. Under load, unlimited goroutines can be created, each maintaining a BSR session and two TCP connections.
2. **No crash recovery.** If the worker process crashes mid-session, BSR session directories are left in an incomplete state on disk with no automatic cleanup on restart.
3. **No graceful shutdown signal.** The `handleProxy` return function has no way to know when the worker is shutting down. On `SIGTERM`, connections are closed abruptly, risking incomplete BSR writes.
4. **No rate-limit config field.** There is no `SshRateLimit` block in the worker HCL config.
5. **No unit tests** for `rate_limiter.go` or `recovery.go`.

---

## Design

### Feature 1: Token-Bucket Rate Limiter

**File:** `proxy/ssh/rate_limiter.go`

#### Overview

A per-target token bucket implemented using atomic operations. Each target (normalized to host:port) has an independent bucket. An optional global bucket applies to all targets.

```go
// SshRateLimitConfig holds rate limit parameters.
// Nil config means rate limiting is disabled.
type SshRateLimitConfig struct {
    // MaxConcurrentSessions is the global ceiling on concurrent SSH sessions.
    // Zero means unlimited.
    MaxConcurrentSessions int

    // MaxPerTarget is the per-target ceiling on concurrent SSH sessions.
    // Zero means unlimited.
    MaxPerTarget int

    // RefillRate is tokens per second added to each bucket.
    // Used when MaxConcurrentSessions or MaxPerTarget is non-zero.
    // RefillRate must be >= 1 to avoid division-by-zero; if unset, defaults to 1.
    RefillRate int

    // BurstSize is the initial and maximum token count per bucket.
    // Defaults to MaxPerTarget if 0 and MaxPerTarget is set; otherwise 10.
    BurstSize int
}
```

#### Algorithm

```
type tokenBucket struct {
    tokens     atomic.Int32
    maxTokens  int32
    refillRate int32  // tokens per second
    lastRefill atomic.Int64  // unix nano
}

Acquire(target string) error  // non-blocking; returns ErrRateLimitExceeded if no token
Release(target string)        // returns token when session ends
CheckRateLimit(target string) (cur int, max int, err error)  // for status reporting
```

On `Acquire`:
1. Compute elapsed ns since `lastRefill`.
2. Add `elapsed * refillRate / 1e9` to `tokens`, capped at `maxTokens`.
3. If `tokens >= 1`, decrement and return nil. Otherwise return `ErrRateLimitExceeded`.

On `Release`: increment `tokens` by 1, capped at `maxTokens`.

The rate limiter maintains two maps:
- `global *tokenBucket` — shared across all targets
- `perTarget map[string]*tokenBucket` — one per unique target host:port

Both maps are read-only after initialization; no lock needed for reads (atomic fields only). Initialization happens once at `SshRecordingManager` creation.

#### Interface

```go
// RateLimiter is the interface for SSH session rate limiting.
// Implemented by tokenBucketRateLimiter.
type RateLimiter interface {
    Acquire(ctx context.Context, target string) error
    Release(target string)
    CheckRateLimit(target string) (current int, max int, err error)
}

// ErrRateLimitExceeded is returned by Acquire when no tokens are available.
var ErrRateLimitExceeded = errors.New("ssh session rate limit exceeded")
```

#### Integration into SshRecordingManager

`SshRecordingManager` stores a `rateLimiter RateLimiter` field (nil = disabled). Constructor takes an optional `*SshRateLimitConfig`:

```go
func NewSshRecordingManager(root string, cfg *SshRateLimitConfig) (*SshRecordingManager, error) {
    ...
    if cfg != nil {
        rm.rateLimiter = newTokenBucketRateLimiter(cfg)
    }
    ...
}
```

#### Integration into handleProxy

Before preparing the BSR session, `handleProxy` calls `sshRm.rateLimiter.Acquire(dataCtx, endpoint)`:

```go
if rm.rateLimiter != nil {
    if err := rm.rateLimiter.Acquire(dataCtx, endpoint); err != nil {
        event.WriteError(controlCtx, op, err)
        return func() {}, err
    }
    defer rm.rateLimiter.Release(endpoint)
}
```

The `defer` ensures release on both normal return and panic. The returned `ProxyConnFn` closes the BSR connection before releasing.

#### Test coverage

`proxy/ssh/rate_limiter_test.go`:
- Test `Acquire`/`Release` token count
- Test `Acquire` blocks correctly under load (N goroutines, verify count <= max)
- Test `CheckRateLimit` returns correct values
- Test nil config → rate limiter disabled (Acquire always succeeds)
- Test target normalization (strip port from hostname)

---

### Feature 2: Crash Recovery Scanner

**File:** `proxy/ssh/recovery.go`

#### Overview

On worker startup, `ossRecorderManagerFactory` calls `ScanAndRecoverOrphanedSessions` to find BSR session directories left in an incomplete state by a previous crash and quarantine them so they are not re-opened.

#### Algorithm

```go
// ScanAndRecoverOrphanedSessions scans the recording storage root for BSR session
// directories that were left incomplete (no session-meta.json or empty file) and
// quarantines them. Returns the count of orphaned sessions found.
// It should be called once at worker startup before accepting new sessions.
func ScanAndRecoverOrphanedSessions(root string) (int, error) {
    entries, err := os.ReadDir(root)
    if err != nil {
        return 0, fmt.Errorf("recovery scan failed: %w", err)
    }

    orphaned := 0
    for _, entry := range entries {
        if !entry.IsDir() && strings.HasPrefix(entry.Name(), "sr_") {
            dirPath := path.Join(root, entry.Name())
            if isOrphanedSession(dirPath) {
                if err := quarantineSessionDir(dirPath); err != nil {
                    event.WriteError(context.Background(), op, err,
                        event.WithInfo("session_dir", dirPath))
                    continue
                }
                orphaned++
            }
        }
    }
    return orphaned, nil
}

// isOrphanedSession returns true if the session directory has no session-meta.json
// or has a session-meta.json that is empty / below a minimum size threshold (~100 bytes).
func isOrphanedSession(dirPath string) bool {
    metaPath := path.Join(dirPath, "session-meta.json")
    fi, err := os.Stat(metaPath)
    if err != nil {
        return true  // no meta file = orphaned
    }
    return fi.Size() < 100  // empty or truncated
}

// quarantineSessionDir renames the directory with a .quarantined-NNN suffix
// so it is never reopened by the recovery scanner or a subsequent run.
// It logs the quarantine action.
func quarantineSessionDir(dirPath string) error {
    suffix := fmt.Sprintf(".quarantined-%d", time.Now().Unix())
    quarantined := dirPath + suffix
    if err := os.Rename(dirPath, quarantined); err != nil {
        return fmt.Errorf("failed to quarantine %s: %w", dirPath, err)
    }
    event.WriteInfo(context.Background(), op, event.WithInfo("quarantined", quarantined))
    return nil
}
```

#### Integration into worker_init.go

```go
// ossRecorderManagerFactory creates an SshRecordingManager for OSS.
func ossRecorderManagerFactory(w *Worker) (recorderManager, error) {
    rawConf := w.conf.RawConfig.Worker
    if rawConf.RecordingStoragePath == "" {
        return nil, nil
    }

    // Run crash recovery scan before creating the manager.
    // This is best-effort; errors are logged but do not block manager creation.
    orphaned, err := ssh.ScanAndRecoverOrphanedSessions(rawConf.RecordingStoragePath)
    if err == nil && orphaned > 0 {
        w.Logger().Info("recovered orphaned BSR sessions", "count", orphaned)
    }

    // Extract rate limit config if present.
    var rateLimitCfg *ssh.SshRateLimitConfig
    if rawConf.SshRateLimit != nil {
        rateLimitCfg = rawConf.SshRateLimit
    }

    sshRm, err := ssh.NewSshRecordingManager(
        rawConf.RecordingStoragePath,
        rateLimitCfg,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create SSH recording manager: %w", err)
    }

    return newSshRecordingManagerWrapper(sshRm), nil
}
```

#### Test coverage

`proxy/ssh/recovery_test.go`:
- Test `isOrphanedSession` with no meta file, empty meta, valid meta, corrupted meta
- Test `quarantineSessionDir` renames and preserves contents
- Test `ScanAndRecoverOrphanedSessions` finds and quarantines orphaned dirs, ignores valid ones
- Test that errors during quarantine are logged but don't stop scanning

---

### Feature 3: Graceful Shutdown

**File:** `proxy/ssh/session_manager.go` (additions), `proxy/ssh/handler.go` (additions)

#### Overview

The worker sends a shutdown signal to the `SshRecordingManager` on `SIGTERM`. Active proxy connections drain by checking the done channel on each pipe iteration and closing cleanly when signaled.

#### Implementation

**SshRecordingManager additions:**

```go
type SshRecordingManager struct {
    root string

    mu          sync.RWMutex
    bsrSessions map[string]*bsr.Session

    // shutdownCh is closed when the worker receives SIGTERM.
    // Used to signal active proxy goroutines to drain.
    shutdownCh <-chan struct{}

    // isShutdown is set to true once shutdownCh is closed.
    isShutdown atomic.Bool

    // rateLimiter for concurrent session control (may be nil).
    rateLimiter RateLimiter
}

// NewSshRecordingManager creates a manager. Pass shutdownCh for graceful shutdown
// coordination (may be nil for tests / legacy use).
func NewSshRecordingManager(root string, cfg *SshRateLimitConfig, shutdownCh <-chan struct{}) (*SshRecordingManager, error) {
    ...
    rm := &SshRecordingManager{
        root:        root,
        bsrSessions: make(map[string]*bsr.Session),
        shutdownCh:  shutdownCh,
    }
    ...
}

// IsShuttingDown returns true if the manager has received a shutdown signal.
func (rm *SshRecordingManager) IsShuttingDown() bool {
    return rm.isShutdown.Load()
}
```

**handleProxy additions:**

```go
func handleProxy(...) (proxyHandlers.ProxyConnFn, error) {
    ...
    doneCh := make(chan struct{})
    go func() {
        select {
        case <-sshRm.ShutdownSignal():
            close(doneCh)
        case <-dataCtx.Done():
            close(doneCh)
        }
    }()

    pipe := NewInterceptingPipe(clientConn, targetConn, connRecorder, doneCh)

    return func() {
        defer func() { ... }()
        // runWithShutdown drains the pipe and returns when doneCh is closed
        // OR when the context is cancelled, whichever comes first.
        if err := runWithShutdown(dataCtx, pipe, doneCh, 5*time.Second); err != nil {
            event.WriteError(dataCtx, op+"(proxy)", err, event.WithInfo("conn_id", connId))
        }
    }, nil
}
```

**InterceptingPipe addition:**

```go
// NewInterceptingPipe creates an intercepting pipe.
// doneCh, if non-nil, is checked every N iterations; if closed, Run returns nil.
func NewInterceptingPipe(clientConn, targetConn net.Conn, rec *ConnectionRecorder, doneCh <-chan struct{}) *InterceptingPipe {
    return &InterceptingPipe{
        clientConn:  NewInterceptingConn(clientConn, bsr.Inbound, rec),
        targetConn:  NewInterceptingConn(targetConn, bsr.Outbound, rec),
        pipeBufSize: 32 * 1024,
        doneCh:      doneCh,
    }
}

// Run drains the pipe. Returns nil when doneCh is closed or context cancelled.
// Checks doneCh every 100 bidirectional transfers.
func (p *InterceptingPipe) Run(ctx context.Context) error {
    ...
    iter := 0
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-p.doneCh:
            return nil  // graceful shutdown requested
        default:
        }
        iter++
        if iter%100 == 0 {
            select {
            case <-p.doneCh:
                return nil
            default:
            }
        }
        // ... existing copy logic
    }
}
```

---

### Feature 4: HCL Configuration

**File:** `cmd/config/config.go` (Worker struct additions)

#### Schema

```hcl
worker {
  recording_storage_path = "/var/lib/boundary/recordings"

  ssh_rate_limit {
    max_concurrent_sessions = 100
    max_per_target          = 10
    refill_rate             = 5
    burst_size              = 10
  }
}
```

#### Struct

```go
// SshRateLimitConfig is the HCL struct for ssh_rate_limit block.
type SshRateLimitConfig struct {
    MaxConcurrentSessions int `hcl:"max_concurrent_sessions"`
    MaxPerTarget          int `hcl:"max_per_target"`
    RefillRate            int `hcl:"refill_rate"`
    BurstSize             int `hcl:"burst_size"`
}

// Worker.config.Worker.SshRateLimit field:
type Worker struct {
    ...
    SshRateLimit *SshRateLimitConfig `hcl:"ssh_rate_limit"`
}
```

#### Defaults

- `MaxConcurrentSessions = 0` (unlimited)
- `MaxPerTarget = 0` (unlimited)
- `RefillRate = 1` (1 token/second; prevents division by zero)
- `BurstSize = 0` → defaults to `MaxPerTarget` if set, else 10

#### Validation

`config.go` should add a `Validate() error` method to `SshRateLimitConfig`:
- If `RefillRate < 1`, return error
- If `MaxPerTarget < 0`, return error
- If `MaxConcurrentSessions < 0`, return error

---

## Implementation Sequence (Senior Engineer)

The senior engineer should implement in this order to avoid blocking:

1. **HCL config** (`cmd/config/config.go`): Add `SshRateLimit *SshRateLimitConfig` field + validation. Simplest change; no dependencies.
2. **rate_limiter.go**: Implement token bucket. Add tests. Update `NewSshRecordingManager` signature.
3. **session_manager.go**: Add `rateLimiter` field, `shutdownCh`, `isShutdown` field to `SshRecordingManager`. Update constructor.
4. **handler.go**: Wire `Acquire`/`Release` in `handleProxy`. Add done channel plumbing.
5. **pipe.go**: Add `doneCh` parameter to `NewInterceptingPipe`, `Run` method checks it every 100 iters.
6. **worker_init.go**: Pass `w.conf.RawConfig.Worker.SshRateLimit` to `NewSshRecordingManager`. Call `ScanAndRecoverOrphanedSessions` before creating the manager.
7. **recovery.go**: Implement scan + quarantine. Add tests.
8. **Unit tests**: `rate_limiter_test.go`, `recovery_test.go`.
9. **Build verification**: `go build ./internal/daemon/worker/proxy/ssh/... && go build ./internal/daemon/worker/... && go vet ./internal/daemon/worker/proxy/ssh/... && go test ./internal/daemon/worker/proxy/ssh/...`

---

## Gap Notes (from researcher review of Cycle 1 implementation)

The Cycle 1 implementation audit found the following wiring gaps. They are addressed by the implementation sequence above:

| # | Gap | Fix |
|---|---|---|
| G1 | `worker_init.go`: `ScanAndRecoverOrphanedSessions` not called | Add call in `ossRecorderManagerFactory` before creating manager (Step 6) |
| G2 | `worker_init.go`: `SshRateLimit` config not passed | Extract `w.conf.RawConfig.Worker.SshRateLimit` and pass to `NewSshRecordingManager` (Step 6) |
| G3 | `cmd/config/config.go`: `SshRateLimit` field missing | Add field + validation (Step 1) |
| G4 | No unit tests | Add `rate_limiter_test.go` + `recovery_test.go` (Step 8) |
| A1 | `worker_init.go` pre-existing compile errors (`w.Conf`/`w.Logger` casing) | Already fixed in current uncommitted diff — `ssh.NewSshRecordingManager(w, ...)` → `ssh.NewSshRecordingManager(...)` (removed `w` param) |
| A2 | Doc says "Go 1.23+ for atomic.Value" but code uses `atomic.Int32` (Go 1.19+) | Fix: code uses `atomic.Int32`/`atomic.Bool`, not `atomic.Value`. No Go version bump needed. |

---

## Security Considerations

- **Rate limit DoS**: Without rate limiting, an attacker who compromises a target's credentials could open unbounded concurrent SSH sessions through the worker. The token bucket bounds this per target.
- **Recovery scanner**: Quarantine renames directories rather than deleting them, preserving forensic evidence in case the "crash" was actually an attack.
- **Graceful shutdown**: Prevents partial BSR writes from being re-opened on restart (partial BSR files would be caught by the recovery scanner next startup).
- **Rate limiter keys**: Target normalization should strip source port to prevent token fragmentation across many clients connecting from the same host.

---

## Open Questions

1. **Rate limit key normalization**: Should we include the target port in the key, or group all targets on the same host? Currently the design keys on `endpoint` (host:port). Confirm this is correct.
2. **Recovery on Windows**: The quarantine approach (rename with suffix) works on Linux/macOS. Windows may have file locking issues. Add a note or platform-specific path if needed.
3. **Controller-side rate limit**: Should the controller also enforce a rate limit, or is worker-side sufficient? Currently designing worker-side only.

---

## Alternatives Considered

**Semaphore vs token bucket**: A semaphore (counting mutex) would be simpler but provides no refill behavior. A session that holds a permit for hours would permanently reduce capacity. Token bucket allows capacity to recover over time.

**Global-only vs per-target**: Global-only is simpler but a single busy target could exhaust the global budget, blocking other targets. Per-target is better even with slightly more complex accounting.

**Background recovery goroutine vs startup scan**: A background goroutine scanning continuously would find orphans faster but adds complexity and running overhead. Startup scan is simpler and sufficient since orphans only appear after a crash.

---

## References

- Base design: `docs/design/ssh-session-recording.md`
- BSR SSH package: `internal/bsr/ssh/`
- Worker config: `internal/cmd/config/config.go`
- Worker initialization: `internal/daemon/worker/worker_init.go`
- Worker testing helpers: `internal/daemon/worker/testing.go`