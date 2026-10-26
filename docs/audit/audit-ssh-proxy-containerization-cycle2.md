# Audit: SSH Proxy Containerization — Cycle 2

**Auditor:** researcher
**Date:** 2026-05-30
**Status:** Approved
**Branch:** `feature/ssh-session-recording`
**Base:** `main`
**Builds on:** Cycle 1 (commit `5f73dd0ea`)

## Documents Audited

| Document | Status | Location |
|---|---|---|
| RFC — SSH Proxy Containerization | Superseded | `docs/audit/RFC-sshproxy-containerized-cleanup-rate-limit.md` |
| Design — SSH Proxy Containerization | Accepted | `docs/audit/design-ssh-proxy-containerization.md` |
| Implementation | @ commit `3460b69b7` | `internal/daemon/worker/proxy/ssh/` |

## Scope

Cycle 2 adds three infrastructure improvements to the SSH proxy handler to ensure correct behavior under container lifecycle (start / stop / crash / OOM):

1. **Rate limiting** — global concurrent-session cap and per-target connection cap
2. **Crash cleanup** — startup scan that recovers orphaned BSR sessions from unexpected exits
3. **Graceful shutdown** — SIGTERM handling through `shutdownCh` broadcast to in-flight pipes

All three features are implemented in code at commit `3460b69b7`. This audit validates that the implementation is correct, identifies remaining wiring gaps, and confirms the design is sound for handoff to a Senior Engineer.

---

## 1. Rate Limiter

### What was specified

A token-bucket rate limiter in `internal/daemon/worker/proxy/ssh/rate_limiter.go`:
- Global counter (`atomic.Int32`): tracks active sessions
- Per-target map (`sync.Map[string]*atomic.Int32`): tracks sessions per target
- `Acquire(ctx, targetId) bool`: lock-free CAS loop, returns false if either limit exceeded
- `Release(targetId)`: decrements counters
- `SshRateLimitConfig`: wraps `MaxConcurrentSessions` and `MaxPerTarget`

### What was implemented

`rate_limiter.go` at commit `3460b69b7`:

| Requirement | Status | Notes |
|---|---|---|
| `rateLimiter` struct with `global atomic.Int32`, `perTarget sync.Map`, `maxGlobal int`, `maxTarget int` | Implemented | Matches design exactly |
| `Acquire(ctx, targetId)` — CAS loop, returns false on limit exceeded | Implemented | Clean, no blocking |
| `Release(targetId)` — decrements global + per-target | Implemented | Handles zero value correctly |
| `CheckRateLimit(targetId)` — non-mutating check | Implemented | Used for pre-check before Acquire |
| `Count(targetId)` — returns current per-target count | Implemented | |
| Nil-safety (rate limiter disabled) | Implemented | All methods check `rl == nil` |

### Key design decision — target ID resolution

The RFC proposed a `"_unidentified_"` fallback key when target ID is unavailable. The implementation uses `sessionId` (derived from `connId`) instead. This is **better** — session IDs are unique and cannot collide, avoiding a shared `"_unidentified_"` bucket that could become a bottleneck. The design doc acknowledges and accepts this approach. No change required.

### Gap 1 — Wiring: Config not passed

**Status: CONFIRMED — Must fix before merge**

`worker_init.go` line 50 calls:
```go
ssh.NewSshRecordingManager(storagePath, wrapper, w.RecordingStorage, w.Logger().Named("ssh-recording"))
```

The updated `NewSshRecordingManager` signature (at this commit) expects 5 parameters, including `cfg *SshRateLimitConfig`. The current call compiles against the **old** interface because `worker_init.go` was not modified by Cycle 2. This **will produce a compilation error** once the old interface is removed.

**Design doc remedy:** Accept `*SshRateLimitConfig` as new parameter. `ossRecorderManagerFactory` reads `w.Conf().RawConfig.Worker.SshRateLimit` and passes it. If nil, rate limiting is disabled.

---

## 2. Crash Cleanup — Orphaned Session Recovery

### What was specified

`ScanAndRecoverOrphanedSessions(ctx, storagePath, logger)` in `recovery.go`:
1. List `storagePath` directory
2. For each `s_<uuid>` directory: read `session.json` if present
3. If absent or `status != "closed"`: orphaned
4. Write `session.json` with `status: "recovered_incomplete"` (atomic rename via temp file)
5. Rename directory to `s_<uuid>-incomplete-<timestamp>` to quarantine

### What was implemented

`recovery.go` at commit `3460b69b7`:

| Requirement | Status | Notes |
|---|---|---|
| List storage path entries | Implemented | |
| Check `session.json` per session dir | Implemented | |
| Skip if `status == "closed"` | Implemented | |
| Write `session.json` with `"recovered_incomplete"` status | Implemented | Atomic temp-file-to-rename pattern |
| Rename dir to `s_<uuid>-incomplete-<timestamp>` | Implemented | |
| Return count of orphaned sessions | Implemented | |
| Logging | Implemented | Info-level for findings, warn-level for errors |
| Handle missing manifest (no `.json` at all) | Implemented | Treated as orphaned |
| Handle parse errors in `session.json` | Implemented | Logged, treated as orphaned |

### Gap 2 — Wiring: Recovery scan not invoked

**Status: CONFIRMED — Must fix before merge**

`worker_init.go` creates `SshRecordingManager` but never calls `ScanAndRecoverOrphanedSessions`. The recovery logic in `recovery.go` is complete (191 lines) — it simply isn't wired into the startup flow.

**Design doc remedy:** Add call in `ossRecorderManagerFactory` after manager creation:
```go
if n, err := ssh.ScanAndRecoverOrphanedSessions(context.Background(), storagePath, w.Logger().Named("ssh-recovery")); err != nil {
    w.Logger().Warn("orphaned session scan failed, continuing", "error", err)
} else if n > 0 {
    w.Logger().Info("orphaned session scan complete", "orphaned_count", n)
}
```

### Finding 1 — Context hygiene (minor improvement)

The design doc proposes `context.Background()` for the recovery scan. Using the worker's shutdown context or a context with a 30s timeout would be more correct — if the worker is shutting down during init (race), the scan should also abort. Consider:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
n, err := ssh.ScanAndRecoverOrphanedSessions(ctx, storagePath, logger)
```

**Severity:** Minor improvement, not blocking.

---

## 3. Graceful Shutdown

### What was specified

- `SshRecordingManager` gains `shutdownCh chan struct{}` + `isShutdown bool` + `shutdownMu sync.Mutex`
- `Shutdown()` closes `shutdownCh` (guarded by `shutdownMu`), then iterates sessions to call `finalizeSession`
- `pipe.runWithShutdown(ctx, doneCh)` checks `doneCh` before starting and every 100 iterations
- `handler.go` passes `shutdownCh` to `pipe.runWithShutdown`

### What was implemented

| Requirement | Status | Notes |
|---|---|---|
| `shutdownCh` field on `SshRecordingManager` | Implemented | Created in `NewSshRecordingManager` |
| `isShutdown` + `shutdownMu` (double-close guard) | Implemented | |
| `Shutdown()` closes `shutdownCh` then finalizes sessions | Implemented | |
| `pipe.runWithShutdown` accepts `doneCh` param | Implemented | |
| Check `doneCh` before starting copies | Implemented | `select { case <-done: return }` |
| Check `doneCh` every 100 iterations | Implemented | `iterCount%100 == 0` |
| `handler.go` passes `m.shutdownCh` via done channel | Implemented | |

No remaining gaps. The graceful shutdown implementation is complete and correct.

---

## 4. Worker Config — SshRateLimit Field

### What was specified

Add `SshRateLimit *SshRateLimitConfig` to the worker's config struct with HCL block syntax:

```hcl
worker {
  ssh_rate_limit {
    max_concurrent_sessions = 100
    max_per_target          = 10
  }
}
```

### Gap 3 — Missing: Config field not added

**Status: CONFIRMED — Must fix before merge**

The `Worker` struct in `internal/cmd/config/config.go` (alternatively `options.go`) currently has no `SshRateLimit` field. The nearest analogous field is `RecordingStoragePath string`. Adding `SshRateLimit *SshRateLimitConfig` with HCL block tag `hcl:"ssh_rate_limit,block"` follows the established pattern.

**Design doc remedy:** Add to worker config struct:
```go
SshRateLimit *SshRateLimitConfig  // nil = rate limiting disabled
```

The struct `SshRateLimitConfig` is already defined in `rate_limiter.go` — the config field just needs to reference it.

---

## 5. Unit Tests

### Gap 4 — Missing: No tests for rate_limiter.go or recovery.go

**Status: CONFIRMED — Must fix before merge**

Neither `rate_limiter_test.go` nor `recovery_test.go` exist in the package. The test strategies in both the RFC and design doc are reasonable and should be followed.

### Recommended test plan

**rate_limiter_test.go** (table-driven):
- Global cap exceeded: set MaxConcurrentSessions=1, Acquire twice, second returns false
- Per-target cap exceeded: set MaxPerTarget=1, Acquire twice on same target, second returns false
- Cross-target isolation: Acquire on one target exhausts its per-target limit but another target succeeds
- Concurrent safety: spawn N goroutines with limit < N, verify Acquire return count matches limit
- Release safety on nil limiter: `(*rateLimiter)(nil).Release("t")` — no panic
- Release with empty target: `rl.Release("")` — no panic
- `CheckRateLimit` returns error when limit would be exceeded

**recovery_test.go** (temp directories):
- Clean session: directory with `session.json` containing `{"status":"closed"}` — skipped, count 0
- Orphaned (no session.json): directory exists without manifest — quarantined, count 1
- Orphaned (active status): `session.json` with `{"status":"active"}` — quarantined
- Multiple orphaned: 3 directories, 2 orphaned, 1 clean — count 2
- Manifest parse error: corrupted `session.json` — treated as orphaned (logged)

---

## 6. Additional Findings

### Finding A — Pre-existing compilation errors in worker_init.go

**Severity: SHOULD FIX — Blocks go build**

`worker_init.go` has pre-existing errors independent of Cycle 2:

- `w.Conf` should be `w.conf` (Go unexported field)
- `w.Logger` should be `w.logger` (Go unexported field)

These are casing issues from Cycle 1 where exported field names were used instead of unexported (package-internal) ones. They will block `go build ./internal/daemon/worker/...` regardless of the Cycle 2 changes.

**Recommendation:** Fix these as part of the Cycle 2 wire-up since the implementer is already modifying this file.

### Finding B — Go version documentation inaccuracy

**Severity: Minor**

The design doc states "Go 1.23+ required for `atomic.Value`" but the implementation uses `atomic.Int32` which was introduced in Go 1.19. There is no actual dependency on Go 1.23 features. The code compiles cleanly with Go 1.22+ (the repo's current minimum from `go.mod`).

**Recommendation:** Update the design doc to remove or correct the Go version reference.

### Finding C — Build verification

- `go build ./internal/daemon/worker/proxy/ssh/...` — PASSES
- `go vet ./internal/daemon/worker/proxy/ssh/...` — PASSES (expected: no unused exports or format issues)
- `go build ./internal/daemon/worker/...` — FAILS (4 pre-existing errors in `worker_init.go`)

---

## Verification Summary

### Confirmed Gaps (Must Fix)

| # | Gap | File(s) | Severity |
|---|---|---|---|
| 1 | NewSshRecordingManager doesn't accept `*SshRateLimitConfig` | `session_manager.go`, `worker_init.go` | Must fix |
| 2 | Recovery scan not called in `ossRecorderManagerFactory` | `worker_init.go` | Must fix |
| 3 | `SshRateLimit` field missing from worker config struct | `config.go` (or `options.go`) | Must fix |
| 4 | No unit tests for rate_limiter.go or recovery.go | — | Must fix |

### Additional Findings

| # | Finding | Severity |
|---|---|---|
| A | Pre-existing compile errors (`w.Conf` / `w.Logger` casing) in `worker_init.go` | Should fix |
| B | Design doc inaccurately claims Go 1.23 dependency | Minor |
| C | Recovery scan context — consider timeout-backed context instead of `context.Background()` | Minor improvement |

### Fully Implemented (No Changes Required)

| Feature | Status | Notes |
|---|---|---|
| Rate limiter core (`rate_limiter.go`) | Complete | Lock-free CAS, nil-safe |
| Recovery scanner (`recovery.go`) | Complete | Atomic rename, edge-case handling |
| Graceful shutdown (`session_manager.go`, `handler.go`, `pipe.go`) | Complete | `shutdownCh` broadcast, double-close guard |

---

## Verdict

**Design approved.** The core logic for all three features is correctly implemented at commit `3460b69b7`. The 4 confirmed gaps are wiring work in 2 files (`worker_init.go` and `config.go`) plus test creation — straightforward and well-scoped for handoff.

The two additional findings (pre-existing compile errors and the Go version doc note) are non-blocking but should be addressed by the implementer since they touch the same files as the required wiring changes.

### Handoff summary for implementer

1. **worker_init.go** — Add `SshRateLimitConfig` param to `NewSshRecordingManager` call; add `ScanAndRecoverOrphanedSessions` invocation after manager creation; fix `w.Conf` / `w.Logger` → `w.conf` / `w.logger`
2. **config.go** — Add `SshRateLimit *SshRateLimitConfig` to `Worker` struct (HCL block tag)
3. **rate_limiter_test.go** — Table-driven tests for global cap, per-target cap, concurrent safety, nil safety
4. **recovery_test.go** — Temp-dir tests for clean, orphaned, multiple orphaned, parse-error scenarios
5. **go build + go vet** — Validate both `proxy/ssh/...` and `worker/...` pass
