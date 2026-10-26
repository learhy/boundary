# SSH Session Recording — Revised RFC (rev2)

## Status

| Field | Value |
|-------|-------|
| Author | staff-eng (orchestrator-mediated) |
| Version | rev2 |
| Audit | Based on review-rev1.md findings: B1-B3 (blocking), D1-D2 (advisory), A1-A6 (advisory) |
| Verification | Codebase-verified against live Boundary commit (internal/bsr/ssh/chunk.go etc.) |
| Target Phase | Phase 1 (session lifecycle + BSR types) |

## B1 — TRY_EACH Credential Strategy (BLOCKING)

### Resolution

**`BSRsession.Attempts []CredentialAttempt`** — tracks each credential offer in sequence.

- `CredentialAttempt` type: `{credential_id string, auth_method string, username string, timestamp time.Time, result AttemptResult}`
- `AttemptResult` enum: `pending`, `accepted`, `rejected`, `server_closed`
- Recording begins at **`auth_started`** (first `USERAUTH_REQUEST`), NOT at `recording_active`
- This ensures failed attempts are part of the audit trail
- Final outcome: **`all_credentials_exhausted`** when all credentials rejected
- Partial recordings marked **`incomplete`** per disposition table below

### Disposition Table

| Outcome | Recording Disposition |
|---------|----------------------|
| All credentials rejected | Marked `incomplete`, retained for audit |
| One credential accepted | Recording proceeds normally |
| Server closes before auth | Marked `incomplete`, retained for audit |
| Client disconnects during auth | Marked `incomplete`, retained if any attempts recorded |

## B2 — SSH Parsing Layer (BLOCKING)

### Resolution

New **`internal/sshdec/`** package with:

```go
// Decoder reads SSH binary wire format (RFC 4253 §4)
type Decoder struct {
    buf     *bytes.Buffer
    handler EventHandler
}

type EventHandler interface {
    OnAuthRequest(addr string, method string, username string)
    OnAuthFailure(addr string, method string, username string, partial bool)
    OnAuthSuccess(addr string, method string, username string)
    OnChannelOpen(addr string, channelID uint32, channelType string, senderChannel uint32)
    OnChannelData(addr string, channelID uint32, data []byte)
    OnChannelClose(addr string, channelID uint32)
    OnChannelEOF(addr string, channelID uint32)
    OnGlobalRequest(addr string, requestType string, wantReply bool)
}

type chunkBuilder struct {
    // Maps SSH wire events to BSR chunk types
}
```

### Capabilities
- Reads SSH binary wire format: length-prefixed packets, padding, compression (zlib/zlib-openssh), message type dispatch
- Emits typed `EventHandler` events
- `chunk_builder.go` maps wire events to existing BSR chunk types
- **Out of scope**: KEX, cipher negotiation, full SSH state machine
- **Fail closed** on malformed input — decoder returns error for unparseable packets

### Key Design Decisions
1. **No SSH library dependency** — pure wire-format reader; avoids Go crypto/ssh version coupling
2. **Streaming by default** — processes fragments as they arrive; caller manages reassembly
3. **Event-driven** — handler receives callbacks; decouples parsing from chunk production

## B3 — Session Lifecycle on Auth Failure (BLOCKING)

### Resolution

Explicit state machine:

```
session_created → auth_started → auth_failed → session_terminated
                                 ↓
                          (retry with next credential)
                                     ↓
                          all_credentials_exhausted
```

### Types

```go
type SessionAuthState int
const (
    SessionAuthStateCreated SessionAuthState = iota
    SessionAuthStateStarted
    SessionAuthStateFailed
    SessionAuthStateTerminated
)

type SessionAuthFailureReason int
const (
    FailureReasonNone SessionAuthFailureReason = iota
    FailureReasonAllCredentialsExhausted
    FailureReasonServerClosed
    FailureReasonClientDisconnect
    FailureReasonAuthTimeout
)
```

### Protocol Extension

Worker sends `SessionAuthFailed(reason SessionAuthFailureReason)` message to controller. Controller owns:
- All state transitions
- Recording disposition decisions
- Partial recording retention/lifetime

### Recording Disposition by Failure Type

| Failure Type | Recording Disposition |
|--------------|----------------------|
| All credentials exhausted | Retain partial recording for audit trail |
| Server closed (econnreset) | Retain partial recording |
| Client disconnected | Retain partial if any attempts recorded |
| Auth timeout | Retain partial recording |
| Internal error | Discard (no useful data) |

## D1 — Credential Injection Dependency Order (ADVISORY)

**Resolution:** Credential injection (`internal/daemon/worker/proxy/`) must ship before or alongside Phase 1. The sshdec package receives bytes via `*ssh.ServerConn` pipe from the proxy layer. Without credential injection, the worker only gets raw TCP — no SSH protocol context for the decoder.

Dependency chain:
1. Credential injection → establishes SSH session with target
2. sshdec → reads SSH wire bytes from the established session
3. BSR chunk types → record structured events from sshdec events

## D2 — KMS Wrapping for BSR Encryption (ADVISORY)

**Resolution:** `w.conf.BsrKms` via `kms.NewWrapper(...)`. Development fallback with startup warning:

```
WARNING: BSR KMS not configured — recording is disabled
```

In production, `BsrKms` points to a worker-scoped KMS key configured in `worker.config`. The wrapper provides encrypt/decrypt operations for BSR session keys.

## A1 — Chunk Type Count (ADVISORY)

**Resolution:** Corrected to **19 registered types** (from `internal/bsr/ssh/chunk.go`) + `UNKR` (unknown) fallback = **20 total**.

Verified against `internal/bsr/ssh/chunk.go` Enum:

| ID | Name | Description |
|----|------|-------------|
| 0 | UNKR | Unknown/fallback |
| 1 | AUTH | Authentication attempt |
| 2 | AUTHO | Auth success outcome |
| 3 | AUTHN | Auth failure |
| 4 | CHOF | Channel open failure (NEW — proposed) |
| 5 | OPNL | Channel open |
| 6 | OPNC | Channel open confirmation |
| 7 | CLOS | Channel close |
| 8 | DATA | Channel data |
| 9 | DATAE | Extended channel data (stderr) |
| 10 | EOF | End of file |
| 11 | REQ | Channel request |
| 12 | SUCC | Channel success |
| 13 | FAIL | Channel failure |
| 14 | GLOB | Global request |
| 15 | GLBL_S | Global request success |
| 16 | GLBL_F | Global request failure |
| 17 | KEX | Key exchange start |
| 18 | KEXI | Key exchange init |
| 19 | DIS | Disconnect |

## A4 — Multi-Channel Support (ADVISORY)

**Resolution:**
- Per-channel state machine in `internal/sshdec/channel.go`
- `MaxChannels` enforcement configurable (default: 100)
- Channel ID annotation on all data chunks
- New `ChannelOpenFailure` chunk type ("CHOF") proposed for rejected channel opens

## A5 — Auth Redaction (ADVISORY)

**Resolution:**
- 5-entry table in `internal/sshdec/auth.go`
- `redactAuthMessage()` applied before chunk emission
- Password method: password field replaced with `[REDACTED]`
- Publickey method: not redacted (public key material is not sensitive)
- Username/service/method not redacted
- Keyboard-interactive: all responses redacted

## A6 — Deferred Items (ADVISORY)

**Resolution:** The following are explicitly deferred with rationale:

| Item | Rationale |
|------|-----------|
| FR4 (multi-hop sessions) | Requires session routing changes beyond Phase 1 scope |
| FR5 (session replay UI) | Downstream consumer; no BSR changes needed |
| AT7 (fuzz testing) | Deferred to Phase 2 hardening |
| NFR4 (1000 concurrent sessions) | Requires load testing infrastructure not yet available |

## Protocol Gap — ChannelOpenFailure

**New chunk type proposed:** `CHOF` (Channel Open Failure)
- Captures when SSH server rejects a channel open request
- Carries: `channel_id`, `reason_code`, `description`
- Enables complete channel lifecycle tracking in BSR

## 5-Phase Implementation Plan

### Phase 1: Session Lifecycle Types + State Machine (B3 + D1)
- `SessionAuthState`, `SessionAuthFailureReason` types
- State machine transitions in session package
- Protocol message for `SessionAuthFailed`
- Recording disposition logic

### Phase 2: `internal/sshdec/` Decoder (B2)
- `Decoder` struct with wire format reader
- `EventHandler` interface
- `chunk_builder.go` mapping to BSR types
- Unit tests with synthetic SSH wire data

### Phase 3: Credential Redaction (D2/A5)
- `redactAuthMessage()` implementation
- Integration with decoder pipeline
- Auth metadata in BSR header

### Phase 4: TRY_EACH Tracking Integration (B1)
- `CredentialAttempt` type
- `BSRsession.Attempts` field
- Partial recording disposition logic
- Integration with auth state machine

### Phase 5: `SshRecordingManager` + Integration Wiring
- Interface defining recording lifecycle
- Integration with worker proxy layer
- Configuration via `BsrKms`

## 7 Open Questions

1. **KEX inclusion** — Should KEX start/init be recorded in BSR? (Security benefit vs complexity)
2. **Credential attempt cap** — What's the maximum number of `CredentialAttempt` entries before recording is terminated?
3. **PTY stderr encoding** — `DirFromTarget` vs separate channel type for extended data?
4. **Incomplete recording retention** — Immediate delete vs N-hour retention for partial recordings?
5. **Re-key event annotation** — Should SSH re-key events be annotated in BSR metadata?
6. **D1/D2 confirmation** — Resolutions inferred from audit context; confirm against `docs/audit/review-rev1.md`
7. **OSS KMS key availability** — Is a worker-scoped KMS key available in OSS Boundary for BSR wrapping?

## References

- `internal/bsr/ssh/chunk.go` — BSR chunk type registry
- `internal/bsr/meta_session.go` — SessionMeta structure
- `internal/bsr/meta_recording.go` — SessionRecordingMeta, ConnectionRecordingMeta, ChannelRecordingMeta
- `internal/bsr/proto/ssh/v1/ssh_chunks.proto` — Protobuf definitions
- `internal/bsr/gen/ssh/v1/` — Generated protobuf code
- `internal/bsr/ssh/chunk.go` — DecodeChunk dispatcher
- `internal/daemon/controller/handlers/session_recordings/session_recording_service.go` — Session recording service
- `internal/daemon/worker/handler.go` — Worker proxy handler
- `internal/kms/` — KMS wrapper
