# SSH Session Recording — OSS Proxy Handler + RecordingManager

**Status:** Draft
**Author:** Staff Engineer
**Date:** May 2026
**Branch:** `feature/ssh-session-recording`
**Base:** `main`
**Depends on:** `feature/postgres-credential-injection` (base infrastructure)

---

## Summary

This RFC describes the design for enabling SSH session recording in Boundary OSS. The design adds an OSS SSH proxy handler (`internal/daemon/worker/proxy/ssh/`) and a minimal `SshRecordingManager` that writes BSR (Boundary Session Recording) data to a local filesystem path. The BSR SSH protocol package (`internal/bsr/ssh/`) already exists in OSS with 18 chunk types covering SSH channels, requests, and data. Migration 71 already includes the complete `recording_session`, `recording_connection`, `recording_channel`, and `recording_channel_ssh` schema tables with no enterprise-only dependencies.

---

## Background

### What's Already in OSS

**BSR SSH package** (`internal/bsr/ssh/`): Protocol `"BSSH"`, 18 registered chunk types (ShellReq, ExecReq, PtyReq, SubsystemReq, EnvReq, X11Req, X11ForwardingReq, SignalReq, WindowChangeReq, BreakReq, ExitStatusReq, ExitSignalReq, TCPIPForwardReq, CancelTCPIPForwardReq, DirectTCPIPReq, ForwardedTCPIPReq, SessionReq, XonXoffReq, UnknownReq, DataChunk). `DecodeChunk` handles all types. No changes needed here.

**Schema migration 71** (`internal/db/schema/migrations/oss/postgres/71/11_session_recording.up.sql`): Complete self-contained OSS schema:
- `recording_session` — links to `storage_plugin_storage_bucket`, `session`, and historical user/target/host records
- `recording_connection` — links session to connections
- `recording_channel` — base table for channel subtypes
- `recording_channel_ssh` — SSH channel subtype with `bytes_up`, `bytes_down`, `start_time`, `end_time`, `channel_type` (session/x11/forwarded-tcpip/direct-tcpip)
- `recording_channel_ssh_session_channel` — program type (shell/exec/subsystem/none)
- `recording_channel_ssh_session_channel_program_exec` — exec program (unknown/scp/rsync)
- `recording_channel_ssh_session_channel_program_subsystem` — subsystem name

No enterprise-only FKs, no external plugin dependencies in the schema itself.

**Proxy handler registry** (`internal/daemon/worker/proxy/proxy.go`):
- `proxy.RegisterHandler(protocol string, handler Handler)` — registers protocol handlers
- `GetHandler` function variable (defaults to `tcpOnly`) — called in `handler.go:286` to resolve protocol handler
- `Handler` function type: `func(controlCtx, dataCtx context.Context, df DecryptFn, c net.Conn, pd *ProxyDialer, connId string, pb *anypb.Any, rm RecordingManager) (ProxyConnFn, error)`
- `RecordingManager = any` — passed through to handlers, nil in OSS today

**Worker initialization** (`internal/daemon/worker/worker.go:227–262, 301–307`):
- `recordingStorageFactory func(ctx, path, plgClients, loopback) (storage.RecordingStorage, error)` — nil in OSS
- `recorderManagerFactory func(*Worker) (recorderManager, error)` — nil in OSS
- Both are set via `var` overrides by enterprise packages
- `w.conf.RawConfig.Worker.RecordingStoragePath` — config key for storage path
- `w.recorderManager` is stored on the Worker and passed to all handler calls

### What This Design Adds

1. **OSS SSH proxy handler** (`internal/daemon/worker/proxy/ssh/`): minimal handler that terminates SSH client→worker→target and emits BSR chunks
2. **OSS `recordingStorageFactory`** (`internal/daemon/worker/oss_recording_storage.go`): creates a `LocalFS` RecordingStorage backed by the configured `RecordingStoragePath`
3. **OSS `recorderManagerFactory`** (`internal/daemon/worker/oss_recording_manager.go`): creates `SshRecordingManager` bound to the Worker
4. **Init glue** (`internal/daemon/worker/worker_init.go` or similar): sets `recordingStorageFactory` and `recorderManagerFactory` vars
5. **DB writer** (`internal/daemon/worker/ssh_recording_repo.go`): writes `recording_session`/`recording_connection`/`recording_channel` rows from the worker

### What Remains Enterprise

- Storage plugins (S3/GCS/Azure) — requires `recordingStorageFactory` to support plugin clients; OSS provides local-only
- Reauthorization during recording — enterprise `RecordingManager` handles credential rotation mid-session; OSS SSH targets use static credentials so this is not needed
- `recorderManagerFactory` in enterprise handles complex session teardown; OSS version is simplified

---

## Design

### Architecture Overview

```
Client SSH App
    │
    │  TCP / TLS
    ▼
SSH Proxy Handler  (internal/daemon/worker/proxy/ssh/)
    │
    ├─ Frontend: reads SSH client packets, parses channel-open / request messages
    ├─ Backend:  reads SSH target packets, mirrors responses
    │
    └─ Recording phase:
         │
         ├─ SshChannelRecorder: wraps bsr.Channel, emits BSR chunks
         ├─ SshConnectionRecorder: wraps bsr.Connection, emits connection-level chunks
         └─ SshRecordingManager: owns bsr.Session, manages connection/channel lifecycle

    │
    │  TCP / TLS
    ▼
SSH Target ( bastion / remote host )
```

### BSR Container Hierarchy for SSH

SSH is multiplexed at the wire level. Each SSH connection maps to one `bsr.Connection`; each SSH channel maps to one `bsr.Channel`.

```
{recording-session-id}.bsr/
├── session-meta.json
├── wrappedBsrKey / wrappedPrivKey / bsrKey.pub
├── {conn-id}.connection/
│   ├── connection-recording.meta
│   ├── connection-recording-summary.json
│   ├── requests-up.data          ← gzip BSR chunks: client→target
│   ├── requests-down.data        ← gzip BSR chunks: target→client
│   ├── messages-up.data          ← gzip BSR chunks: non-channel data (KEX, auth)
│   ├── messages-down.data        ← gzip BSR chunks
│   └── {channel-id}.channel/
│       ├── channel-recording.meta
│       ├── channel-recording-summary.json
│       ├── requests-up.data      ← channel-level requests: client→target
│       ├── requests-down.data    ← channel-level responses
│       ├── messages-up.data      ← channel data: client→target
│       └── messages-down.data    ← channel data: target→client
```

**One BSR Session per Boundary session** (created once when the first connection is authorized).

**One BSR Connection per SSH connection** (created on `AuthorizeConnection` response for a recording-enabled SSH target).

**One BSR Channel per SSH channel** (created on `channel_open` from client or `channel_open_confirmation` from target). Channel types:
- `session` — shell, exec, subsystem
- `x11` — X11 forwarding
- `forwarded-tcpip` — reverse TCP forwarding (`-L`)
- `direct-tcpip` — local TCP forwarding (`-R`)

---

### Component 1: OSS SSH Proxy Handler

**File:** `internal/daemon/worker/proxy/ssh/`

The handler terminates SSH between client and target, parses SSH messages, and emits BSR chunks. It follows the same registration pattern as MySQL (`proxy.RegisterHandler("ssh", sshHandler)` in `init()`).

#### Handler signature

```go
type sshHandler struct {
    storagePath  string
    rm           proxy.RecordingManager  // SshRecordingManager
}

func (h *sshHandler) Handle(
    controlCtx, dataCtx context.Context,
    df proxy.DecryptFn,
    c net.Conn,
    pd *proxy.ProxyDialer,
    connId string,
    pb *anypb.Any,
    rm proxy.RecordingManager,
) (proxy.ProxyConnFn, error)
```

#### Channel lifecycle

1. `sshHandler` receives `channel_open` message from client
2. Dials target SSH (via `pd.Dial()`)
3. Forwards `channel_open` to target, receives `channel_open_confirmation`
4. Creates `bsr.Channel` via `SshRecordingManager.CreateChannel(connId, channelId, channelType)`
5. Creates `*ChunkEncoder` for each writer direction
6. Runs bidirectional copy in goroutines, emitting BSR chunks as SSH messages are parsed
7. On close: finalizes channel summary (bytes up/down, timestamps), closes BSR channel, updates DB

#### BSR chunk emission

Use the existing `internal/bsr/ssh/` chunk types:

| BSR Chunk | SSH Event | Direction |
|---|---|---|
| `SessionReqChunk` | SSH `session` channel open | up |
| `PtyReqChunk` | PTY request (dims, term) | up |
| `ShellReqChunk` | Shell request | up |
| `ExecReqChunk` | `exec` channel request (command) | up |
| `SubsystemReqChunk` | `subsystem` channel request (name) | up |
| `EnvReqChunk` | Environment variables | up |
| `SignalReqChunk` | Signal (SIGTERM, etc.) | up |
| `WindowChangeReqChunk` | Terminal resize | up |
| `X11ReqChunk` | X11 auth request | up |
| `X11ForwardingReqChunk` | X11 forwarding channel | up |
| `TCPIPForwardReqChunk` | TCP/IP forward request | up |
| `ForwardedTCPIPReqChunk` | Forwarded TCP/IP channel | up |
| `DirectTCPIPReqChunk` | Direct TCP/IP channel | up |
| `ExitStatusReqChunk` | Exit status response | down |
| `ExitSignalReqChunk` | Exit signal response | down |
| `DataChunk` | Raw byte transfer | both |

#### Auth redaction

SSH authentication data (password bytes in `userauth-request`, private key bytes) MUST be redacted before chunk emission. The handler strips credential payloads from auth messages similar to MySQL auth redaction. Non-auth SSH messages (channel ops, data transfer) are recorded in full.

**Implementation note:** The handler operates at the SSH message layer, not the raw packet layer. SSH transport encryption (which uses per-session session keys derived from Diffie-Hellman KEX) means the handler cannot read encrypted payload bytes in an active SSH session without being part of the KEX. However, Boundary SSH sessions are already terminated at the proxy — the worker holds the session key from credential injection (for credential decryption) and additionally needs to participate in the SSH KEX to record message content.

**This is the critical architectural question:** For Boundary SSH targets with credential injection, the worker terminates the SSH connection and has access to decrypted wire bytes. The proxy handler should be able to parse SSH messages and emit BSR chunks from those bytes. For targets WITHOUT credential injection (key-based auth where the client connects directly to the target), the worker proxies at the TCP level and cannot read SSH message content.

**Decision:** Focus recording on credential-injection targets (where the worker terminates SSH). For key-based targets, record connection metadata (connection timestamps, bytes transferred) without BSR content — the `recording_session` and `recording_connection` tables support `state = 'available'` with no BSR file path.

**TODO for senior engineer:** Verify that SSH credential injection handler (`internal/daemon/worker/proxy/ssh/`) provides access to decrypted SSH message bytes. If not, this design needs adjustment to parse messages at the right layer.

#### End-to-end flow

```
1. Client → Worker: SSH handshake (KEXINIT, etc.)
   └─ SshConnectionRecorder records KEX messages to connection-level messages-up.data

2. Client → Worker: SSH auth (keyboard-interactive / password)
   └─ Auth bytes redacted before recording

3. Client → Worker: channel_open (session)
   └─ Create bsr.Channel, emit SessionReqChunk

4. Client → Worker: pty-req, shell-req
   └─ Emit PtyReqChunk, ShellReqChunk to channel-level requests-up.data

5. Data transfer: bidirectional copy with BSR chunk emission
   └─ Emit DataChunks to channel-level messages-{up,down}.data

6. Client closes channel: exit-status
   └─ Emit ExitStatusReqChunk, finalize channel metadata

7. Connection closes
   └─ Close bsr.Connection, update DB recording_connection.end_time
```

---

### Component 2: LocalFS RecordingStorage

**File:** `internal/daemon/worker/oss_recording_storage.go`

OSS provides a local filesystem recording storage implementation. It does NOT support storage plugins (S3/GCS/Azure) — those require the enterprise `recordingStorageFactory`.

```go
// LocalFS implements storage.FS for local filesystem paths.
type LocalFS struct {
    root string
}

// NewLocalFS creates a LocalFS for a given root directory path.
func NewLocalFS(root string) *LocalFS

// LocalFS satisfies storage.FS:
//   - New(ctx, name) → os.MkdirAll + return LocalContainer
//   - Open(ctx, name) → os.Open + return LocalContainer

// LocalContainer satisfies storage.Container:
//   - Create(ctx, name) → os.Create
//   - OpenFile(ctx, name, opts...) → os.OpenFile with flags from opts
//   - SubContainer(ctx, name, opts...) → os.MkdirAll + return LocalContainer

// LocalFS implements storage.RecordingStorage:
//   - NewSyncingFS: not implemented for local FS (no sync to remote)
//   - NewRemoteFS: not implemented (local FS is the source)
//   - PluginClients(): returns empty map
//   - CreateTemp(ctx, p): os.CreateTemp in root
```

**`recordingStorageFactory` init:**

```go
func init() {
    recordingStorageFactory = func(
        ctx context.Context,
        path string,
        plgClients map[string]plgpb.StoragePluginServiceClient,
        enableLoopback bool,
    ) (storage.RecordingStorage, error) {
        if len(plgClients) > 0 {
            return nil, errors.New("OSS does not support storage plugins for session recording")
        }
        return NewLocalRecordingStorage(path)
    }
}
```

---

### Component 3: SshRecordingManager

**File:** `internal/daemon/worker/oss_recording_manager.go`

OSS recording manager satisfies the `recorderManager` interface from `worker.go`:

```go
type recorderManager interface {
    ReauthorizeAllExcept(ctx context.Context, closedSessions []string) error
    SessionsManaged(ctx context.Context) ([]string, error)
    Shutdown(ctx context.Context)
}
```

The OSS version is simplified — no reauthorization needed since OSS SSH targets use static credentials.

```go
// SshRecordingManager manages BSR sessions and recording metadata for SSH targets.
type SshRecordingManager struct {
    worker       *Worker
    logger       hclog.Logger
    storage      storage.RecordingStorage
    sessions     sync.Map  // sessionId → *bsrSession
    connections  sync.Map  // connId → *connInfo
    mu           sync.Mutex
}

type bsrSession struct {
    session   *bsr.Session
    meta      *bsr.SessionRecordingMeta
    connections sync.Map  // connId → bool
    startTime time.Time
}

type connInfo struct {
    connection *bsr.Connection
    channels   sync.Map  // channelId → *bsr.Channel
    startTime  time.Time
    bytesUp    uint64
    bytesDown  uint64
    mu         sync.Mutex
}
```

#### Interface methods

**`SessionsManaged(ctx) ([]string, error)`:** Returns all session IDs currently managed (keys of `sessions` map).

**`ReauthorizeAllExcept(ctx, closedSessions []string) error`:** No-op in OSS. SSH targets use static credentials — no reauthorization needed.

**`Shutdown(ctx)`:** Closes all open BSR sessions, flushes remaining data, returns an error if any session failed to close cleanly. Called on worker shutdown.

#### Session creation

Called when the first connection for a recording-enabled SSH target is authorized:

```go
func (m *SshRecordingManager) CreateSession(ctx context.Context, sessionId string, meta *bsr.SessionMeta) (*bsr.Session, error)
```

Steps:
1. Create `bsr.SessionRecordingMeta{Id: sessionId, Protocol: ssh.Protocol}`
2. Get storage FS via `m.storage.NewSyncingFS(ctx, bucket, ...)` — for local FS, returns LocalFS
3. Generate KMS keys (use `github.com/hashicorp/go-kms-wrapping/v2/extras/crypto` for key generation, wrap with worker's KMS wrapper)
4. Call `bsr.NewSession(ctx, sessionMeta, bsrSessionMeta, fs, keys)`
5. Store in `sessions` map

#### Connection creation

Called on each `AuthorizeConnection` response where `session_recording_id` is set:

```go
func (m *SshRecordingManager) CreateConnection(ctx context.Context, sessionId, connId string) (*bsr.Connection, error)
```

Steps:
1. Look up `bsrSession` from `sessions`
2. Create `bsr.ConnectionRecordingMeta{Id: connId}`
3. Call `bsrSession.session.NewConnection(ctx, connMeta)`
4. Store in `connections` map, register with session

#### Channel creation

Called from the SSH handler when a channel is opened:

```go
func (m *SshRecordingManager) CreateChannel(ctx context.Context, connId, channelId, channelType string) (*bsr.Channel, error)
```

Steps:
1. Look up `connInfo` from `connections`
2. Create `bsr.ChannelRecordingMeta{Id: channelId, Type: channelType}`
3. Call `connInfo.connection.NewChannel(ctx, channelMeta)`
4. Store in `connInfo.channels`, register with connection

#### Byte accounting

```go
func (m *SshRecordingManager) AddBytes(connId string, up, down uint64)
```

Called by the handler during data transfer. Updates `connInfo.bytesUp/Down` atomically.

#### Session finalization

Called when a session ends (no more active connections):

```go
func (m *SshRecordingManager) FinalizeSession(ctx context.Context, sessionId string, state recordingSessionState, errMsg string) error
```

Steps:
1. Update `recording_session` DB row: set `end_time`, `state`, `error_details`
2. Close `bsr.Session`
3. Remove from `sessions` map

#### Connection finalization

```go
func (m *SshRecordingManager) FinalizeConnection(ctx context.Context, connId string) error
```

Steps:
1. Sum bytes from all channels + connection-level bytes
2. Create `recording_connection` DB row
3. Update `recording_session.connection_count`
4. Close `bsr.Connection`
5. Remove from `connections` map

#### Channel finalization

```go
func (m *SshRecordingManager) FinalizeChannel(ctx context.Context, channelId string, bytesUp, bytesDown uint64, program string) error
```

Steps:
1. Create `recording_channel` + `recording_channel_ssh` DB rows
2. If `channel_type = 'session'` and `program` is set: create `recording_channel_ssh_session_channel` row
3. If `program = 'exec'`: create `recording_channel_ssh_session_channel_program_exec` row with exec_program
4. If `program = 'subsystem'`: create `recording_channel_ssh_session_channel_program_subsystem` row with subsystem_name
5. Close `bsr.Channel`

#### `recorderManagerFactory` init

```go
func init() {
    recorderManagerFactory = func(w *Worker) (recorderManager, error) {
        if w.RecordingStorage == nil {
            return nil, errors.New("worker has no recording storage")
        }
        return ssh.NewSshRecordingManager(storagePath, wrapper, w.RecordingStorage, w.Logger().Named("ssh-recording"))
    }
}
```

---

### Component 4: DB Repository

**File:** `internal/daemon/worker/ssh_recording_repo.go`

Worker-side writes to the controller via the established gRPC connection. The worker uses `session.Repository` to write recording metadata through the controller's session service.

The DB records are written through the controller's `SessionRecordingService` RPCs:
- `CreateRecordingSession` — on first connection
- `UpdateRecordingSession` — on finalization (state, end_time)
- `CreateRecordingConnection` — on connection close
- `CreateRecordingChannel` — on channel close

For the initial implementation, the worker can write directly via the existing session/connection service clients that the worker already uses. The `recording_session` table is populated via `insert_session_recording()` trigger when a connection with `session_recording_id` is created.

---

### Component 5: Worker Config

**Config key:** `worker.recording_storage_path` in `config.Worker`

```hcl
worker {
  recording_storage_path = "/var/lib/boundary/recordings"
}
```

When set (non-empty) AND `recordingStorageFactory != nil`, the worker initializes recording infrastructure. Without the config key, recording is disabled (current OSS behavior).

---

## Handler Registration

**File:** `internal/daemon/worker/proxy/ssh/ssh_init.go`

```go
func init() {
    proxy.RegisterHandler("ssh", sshHandler)
}
```

The `ssh` protocol string is communicated from the controller via `ProtocolContext` in the `AuthorizeConnection` response. The controller sets `protocol_context_bssh` (proto defined in `internal/proto/controller/session/v1/session.proto`) when the target has `enable_session_recording = true`.

**Key question for senior engineer:** Verify the controller sends the correct `ProtocolContext` for SSH recording targets. If the existing `ProtocolContext` doesn't include SSH-specific fields, this may need a proto update.

---

## Enterprise Gating

Session recording in OSS is gated at two levels:

1. **Configuration:** `worker.recording_storage_path` must be set. If not set, `recordingStorageFactory` is never called.
2. **Target:** `enable_session_recording` on the target must be `true`. The controller only sends `protocol_context` for recording-enabled targets.
3. **Schema:** All recording tables are in OSS migration 71. No enterprise gating needed in schema.

The enterprise version additionally:
- Validates the storage plugin is available (not just a local path)
- Handles reauthorization during recording (credential rotation)
- Supports `storage_plugin_storage_bucket` with external providers

---

## Data Flow

```
SSH Client → Worker Handler
    │
    ├─ [Auth phase] → bytes redacted, no BSR recording
    │
    └─ [Session phase]
         │
         ├─ SshRecordingManager.CreateConnection(connId)
         │     └─ bsr.Session.NewConnection() → {connId}.connection/
         │
         ├─ channel_open → SshRecordingManager.CreateChannel(chanId, type)
         │     └─ bsr.Connection.NewChannel() → {chanId}.channel/
         │
         ├─ SSH message → BSR chunk → ChunkEncoder → gzip file
         │
         ├─ bytes transferred → SshRecordingManager.AddBytes()
         │
         └─ close → FinalizeChannel() → recording_channel DB rows
                   → FinalizeConnection() → recording_connection DB rows
                   → FinalizeSession() → recording_session DB row
```

---

## Implementation Steps (Senior Engineer)

### Phase 1: Infrastructure
1. Create `internal/daemon/worker/oss_recording_storage.go` — `LocalFS` implementation
2. Create `internal/daemon/worker/oss_recording_storage_init.go` — set `recordingStorageFactory` var
3. Verify worker config `RecordingStoragePath` plumbs to `conf.RawConfig.Worker.RecordingStoragePath`

### Phase 2: SshRecordingManager
4. Create `internal/daemon/worker/oss_recording_manager.go` — `SshRecordingManager` struct with `recorderManager` interface
5. Create `internal/daemon/worker/oss_recording_manager_init.go` — set `recorderManagerFactory` var
6. Create `internal/daemon/worker/ssh_recording_repo.go` — DB write helpers via controller RPC

### Phase 3: SSH Handler
7. Create `internal/daemon/worker/proxy/ssh/` package
8. `ssh_init.go` — `proxy.RegisterHandler("ssh", ...)` in `init()`
9. `handler.go` — `sshHandler.Handle()` implementation
10. `recorder.go` — `SshChannelRecorder`, `SshConnectionRecorder` wrapping BSR APIs
11. `chunk_emitter.go` — maps SSH messages to BSR chunk types
12. Auth redaction in `handler.go` — strip credential bytes from auth messages before chunk emission

### Phase 4: Integration
13. Verify `handler.go` wiring: confirm `w.recorderManager` (type `recorderManager`) can be passed as `proxy.RecordingManager` (type `any`) to handler
14. Verify controller sends correct `ProtocolContext` for SSH recording targets
15. Add unit tests for `SshRecordingManager` using `fstest.MemFS`

---

## Test Plan

### Unit Tests

- **LocalFS:** Test `New`, `Open`, `Create`, `OpenFile`, `SubContainer` with temp directory
- **SshRecordingManager:** Test session/connection/channel creation and finalization with `fstest.MemFS`
- **SSH chunk emission:** Test each chunk type round-trip (encode → decode) using `bsr.DecodeChunk`

### Integration Tests

- **End-to-end SSH session:** Spawn a real SSH server (docker container or localhost sshd), connect via SSH proxy handler, verify BSR files are created and contain expected chunks
- **BSR playback:** Use `bsr.NewChunkDecoder` to read back recorded chunks, verify chunk types and content

### Regression Tests

- Existing `internal/bsr/ssh/*` unit tests continue to pass
- Existing `internal/daemon/worker/proxy/proxy_test.go` continue to pass (TCP-only handler still works)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SSH auth bytes not accessible to handler | Low | High | Design assumes credential injection targets; TCP-only recording for key-based auth |
| BSR KMS key wrapping requires worker KMS | Medium | High | Use `w.conf.WorkerAuthStorageKms` for key wrapping; verify KMS wrapper is available in OSS worker |
| LocalFS fills disk | Medium | Medium | No auto-cleanup in v1; document `worker.recording_storage_path` disk management |
| ProtocolContext proto update needed | Low | Medium | Verify controller proto before Phase 3; fall back to detecting via target config |
| BSR session creation on first connection races | Low | Medium | Use mutex in `SshRecordingManager.CreateSession`; handle duplicate gracefully |

---

## Open Questions

1. **KMS for BSR keys:** The BSR session requires KMS-wrapped keys (`bsr.NewSession` needs `*kms.Keys`). Does the OSS worker have access to a KMS wrapper? The enterprise version uses the worker's `WorkerAuthStorageKms`. Verify this works in OSS.

2. **ProtocolContext for SSH:** Does the controller's `AuthorizeConnection` response include SSH-specific `ProtocolContext` (e.g., `bssh` protocol marker)? If not, the handler needs another way to detect recording targets — check `session_recording_id` in connection metadata.

3. **Controller RPC for recording writes:** Which controller service method does the worker call to create `recording_session` / `recording_connection` / `recording_channel` rows? Verify the existing session service supports these writes or if new RPC methods are needed.

4. **Auth redaction scope:** Exactly which SSH messages carry credential data? `SSH_MSG_USERAUTH_REQUEST` (password method) and `SSH_MSG_USERAUTH_INFO_REQUEST` (keyboard-interactive). Confirm handler can identify and strip these before recording.

---

## References

- BSR SSH chunks: `internal/bsr/ssh/chunk.go`
- BSR Session/Connection/Channel: `internal/bsr/bsr.go`, `internal/bsr/container.go`
- Proxy handler registry: `internal/daemon/worker/proxy/proxy.go`
- Worker recording setup: `internal/daemon/worker/worker.go:227–307`
- Schema migration 71: `internal/db/schema/migrations/oss/postgres/71/11_session_recording.up.sql`
- MySQL recording design: `docs/design/mysql-session-recording.md` (same pattern)
- Worker handler.go: `internal/daemon/worker/handler.go:286–302` (call site)
- BSR test storage: `internal/bsr/internal/fstest/fs.go` (`MemFS`, `NewMemFile`)
