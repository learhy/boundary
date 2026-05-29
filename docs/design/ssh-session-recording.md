# SSH Session Recording — Design Doc

## Summary

Implement SSH session recording for the Boundary worker using the existing BSR (Boundary Session Recording) infrastructure. When an SSH session is established via the SSH credential injection handler (`internal/daemon/worker/proxy/ssh/`), the worker records the full SSH protocol exchange — channel opens, requests, PTY allocations, shell/exec commands, and I/O data — into a BSR session container. BSR SSH chunk types (defined in `internal/bsr/proto/ssh/v1/`) already exist; the work here is wiring them into the live SSH handler so each SSH message is captured as a BSR chunk.

## Background

### What's Already Built

The SSH credential injection handler (`docs/design/ssh-credential-injection.md`) establishes bidirectional SSH connections: the client speaks SSH to the worker (worker presents as SSH server), and the worker speaks SSH to the target (worker presents as SSH client). The handler receives credentials via `SshProtocolContext`, decrypts them, and bridges two `golang.org/x/crypto/ssh` connections.

**BSR infrastructure** is already complete for SSH recording:

- **Chunk types** (`internal/bsr/proto/ssh/v1/ssh_chunks.proto`): `SessionRequest`, `PtyRequest`, `ExecRequest`, `ShellRequest`, `SubsystemRequest`, `EnvRequest`, `SignalRequest`, `ExitStatusRequest`, `ExitSignalRequest`, `WindowChangeRequest`, `X11Request`, `X11ForwardingRequest`, `DirectTCPIPRequest`, `ForwardedTCPIPRequest`, `TCPIPForwardRequest`, `CancelTCPIPForwardRequest`, `BreakRequest`, `DataChunk`, `UnknownRequest` — all implemented in `internal/bsr/ssh/chunk_*.go`.

- **Chunk encoding** (`internal/bsr/encode.go`): `ChunkEncoder` writes BSR chunks to an `io.Writer` with optional gzip compression. Each chunk is serialized via `proto.Marshal` of the protobuf message, wrapped in the BSR chunk envelope (length, protocol, type, direction, timestamp, CRC).

- **BSR container hierarchy**: `Session` → `Connection` → `Channel` (`internal/bsr/bsr.go`). A session contains connections; each connection has a `messages` file (bidirectional byte data) and a `requests` file (channel requests in both directions). For SSH (multiplexed), each channel is a sub-container with its own messages/requests files.

- **`RecordingManager`** (`internal/daemon/worker/proxy/proxy.go:35`): Currently `type RecordingManager any` — a placeholder. The TCP handler ignores it. The SSH handler must use it to acquire BSR recording infrastructure.

- **Worker recording storage** (`internal/daemon/worker/worker.go:159`): `w.RecordingStorage storage.RecordingStorage` — provides `NewSyncingFS()` to create a BSR filesystem for a session.

- **`recorderManager`** (`internal/daemon/worker/worker.go:80`): The interface that manages BSR session lifecycle. It is passed to handlers as `w.recorderManager` in `handler.go:297`. The concrete implementation handles BSR session creation and KMS key management.

### What This Design Adds

The SSH handler needs a recording-specific sub-component that:
1. Accepts a concrete `RecordingManager` interface (replacing `any`)
2. Opens a BSR `Session` for the boundary session when the first connection is authorized
3. Creates a BSR `Connection` per authorized connection
4. For each SSH channel, creates a BSR `Channel` and writes BSR chunks for every SSH message in both directions
5. Closes and syncs the BSR container when the session terminates

---

## Data Model

### Proto Definition

**File:** `internal/proto/worker/proxy/v1/ssh_recording.proto`
**Package:** `worker.proxy.v1`
**Go package:** `github.com/hashicorp/boundary/internal/proxy`

```protobuf
syntax = "proto3";

package worker.proxy.v1;

option go_package = "github.com/hashicorp/boundary/internal/proxy";

import "google/protobuf/timestamp.proto";

// SshRecordingContext is the ProtocolContext payload for SSH sessions
// that opt into session recording. It is marshaled into
// google.protobuf.Any with type URL:
//   type.googleapis.com/worker.proxy.v1.SshRecordingContext
message SshRecordingContext {
  // Whether this session should be recorded.
  bool recording_enabled = 1;

  // Storage bucket to sync recordings to.
  // If empty, recordings are stored locally only.
  string storage_bucket_id = 2;

  // Compression strategy for BSR chunks.
  Compression compression = 3;

  // Encryption strategy for BSR chunks.
  Encryption encryption = 4;
}

enum Compression {
  COMPRESSION_UNSPECIFIED = 0;
  COMPRESSION_NULL        = 1;
  COMPRESSION_GZIP        = 2;
}

enum Encryption {
  ENCRYPTION_UNSPECIFIED = 0;
  ENCRYPTION_NONE        = 1;
  ENCRYPTION_WRAPPED     = 2;
}
```

> **Note:** `SshRecordingContext` is layered on top of `SshProtocolContext` (from the credential injection design). Both can coexist in the same `AuthorizeConnectionResponse.ProtocolContext` — the worker reads `SshProtocolContext` for auth, and reads `SshRecordingContext` for recording configuration. The controller-side code that populates `ProtocolContext` should include `SshRecordingContext` when `target.enable_session_recording` is true and a `storage_bucket_id` is set.

### No New Database Schema

No new tables or schema changes. Recording metadata is derived from the existing session (`sess.GetId()`, `sess.GetEndpoint()`, `sess.GetCredentials()`, target info) and persisted as BSR files.

---

## Architecture

### RecordingManager Interface

Replace the `type RecordingManager any` placeholder with a proper interface that the SSH handler uses to interact with BSR recording:

```go
// File: internal/daemon/worker/proxy/ssh/recording.go

// SshRecordingManager is the concrete recording manager interface for SSH handlers.
// It wraps the worker's BSR session and provides per-connection and per-channel
// recording handles.
type SshRecordingManager interface {
    // Session returns the underlying BSR Session for this boundary session.
    // The session is opened lazily on first request for a given boundary session ID.
    Session() (*bsr.Session, error)

    // NewConnection opens a new BSR Connection within the current BSR Session.
    // Returns ErrSessionNotRecording if recording is not active.
    NewConnection(ctx context.Context, connId string) (*bsr.Connection, error)

    // Close flushes and closes the BSR Session, then triggers async sync to storage.
    Close(ctx context.Context) error
}
```

The concrete implementation (`sshRecordingManager` in `internal/daemon/worker/proxy/ssh/recording.go`) holds:
- `boundarySessionId string` — the Boundary session ID (used as the BSR session ID)
- `bsrSession *bsr.Session` — the open BSR session (opened lazily)
- `sessionMu sync.Mutex` — guards BSR session creation
- `connCounter uint64` — atomic counter for BSR connection IDs
- `workerId string`, `endpoint string`, `sessionMeta *bsr.SessionMeta` — captured at first use

The `RecordingManager` passed to handlers via the handler function signature is typed as this interface. The worker's `recorderManager` concrete implementation (`recordingManager`) implements this interface.

### Handler Signature Update

The `Handler` function signature in `proxy.go` is updated from:
```go
type Handler func(controlCtx, dataCtx, DecryptFn, net.Conn, *ProxyDialer, connId string, *anypb.Any, RecordingManager) (ProxyConnFn, error)
```

`RecordingManager` is now an interface (`SshRecordingManager`). The TCP handler continues to ignore it.

---

## SSH Handler Recording Flow

### Lifecycle

```
AuthorizeConnectionResponse received
    └─ ProtocolContext contains SshRecordingContext
           └─ SSH handler reads recording config
                  └─ If recording_enabled:
                         ├─ Acquire SshRecordingManager from handler context
                         │    └─ BSR Session opened lazily (first connection)
                         ├─ On each connection:
                         │    ├─ BSR Connection created
                         │    ├─ SSH client ↔ worker ↔ SSH server bridge starts
                         │    └─ For each SSH channel:
                         │         ├─ BSR Channel created
                         │         ├─ ChunkEncoder wired to channel's requests/messages writers
                         │         └─ SSH messages intercepted and encoded as BSR chunks
                         └─ On session close:
                              ├─ BSR Session closed
                              └─ Async sync to storage bucket (via NewSyncingFS)
```

### BSR Session Initialization

When the SSH handler is invoked with `SshRecordingContext.recording_enabled = true`:

1. **Resolve `sessionMeta`** from the `session.Session` interface (passed via `controlCtx` or `dataCtx` context):
   - `sess.GetId()` → `SessionMeta.PublicId`
   - `sess.GetEndpoint()` → `SessionMeta.Endpoint`
   - User, Target, Worker info from the session's `GetUser()`, `GetTarget()`, `GetWorker()` methods (or equivalent session interface fields)
   - Credential metadata (credential store IDs, credential type — not secrets)

2. **Resolve KMS keys**: The `recorderManager` provides wrapped KMS keys via `recorderManager.CreateSessionKeys(ctx)`. These keys are passed to `bsr.NewSession`.

3. **Open BSR Session**: Call `bsr.NewSession(ctx, meta, sessionMeta, fs, keys)` where:
   - `meta = &bsr.SessionRecordingMeta{Id: sess.GetId(), Protocol: ssh.Protocol}`
   - `sessionMeta = &bsr.SessionMeta{...}` (populated from session)
   - `fs` from `RecordingStorage.NewSyncingFS(ctx, bucket)` where `bucket` is derived from `SshRecordingContext.storage_bucket_id`
   - `keys` from the KMS wrapper

4. **Store the BSR session** on the `sshRecordingManager` for use by subsequent connections in the same session.

### Per-Connection Recording

On each `AuthorizeConnection` → `GetHandler` call:

1. Call `recordingManager.NewConnection(ctx, connectionId)` → returns `*bsr.Connection`
2. Call `conn.NewMessagesWriter(ctx, bsr.Inbound)` and `conn.NewMessagesWriter(ctx, bsr.Outbound)` → two `io.Writer` handles for byte-level recording
3. Call `conn.NewRequestsWriter(ctx, bsr.Inbound)` and `conn.NewRequestsWriter(ctx, bsr.Outbound)` → two `io.Writer` handles for SSH request recording
4. Wrap each writer with `bsr.NewChunkEncoder(ctx, w, compression, encryption)` — returns `*ChunkEncoder`

### Per-Channel Recording

For each SSH channel opened on a connection:

1. Create a BSR Channel: `conn.NewChannel(ctx, &bsr.ChannelRecordingMeta{Id: channelId, Type: channelType})`
2. Channel creation is gated on `conn.multiplexed == true` — SSH is always multiplexed
3. Within each channel, intercept SSH messages:

**SSH requests** (inbound from client, outbound to target):
- Use `ssh.Request` callbacks: `ssh.ServerConn.HandleChannelOpen()` allows intercepting channel open requests
- The `ssh.Channel` type from `golang.org/x/crypto/ssh` has a `Requests()` channel for channel-specific requests
- For each incoming `ssh.Request` on a channel, map it to the corresponding BSR chunk type:

| SSH Request Type | BSR Chunk Type | Builder Function |
|---|---|---|
| `session` | `SessionReqChunkType` | `ssh.NewSessionRequest(ctx, dir, ts, *ssh.Request)` |
| `pty-req` | `PtyReqChunkType` | `ssh.NewPtyRequest(ctx, dir, ts, *ssh.Request)` |
| `exec` | `ExecReqChunkType` | `ssh.NewExecRequest(ctx, dir, ts, *ssh.Request)` |
| `shell` | `ShellReqChunkType` | `ssh.NewShellRequest(ctx, dir, ts, *ssh.Request)` |
| `subsystem` | `SubsystemReqChunkType` | `ssh.NewSubsystemRequest(ctx, dir, ts, *ssh.Request)` |
| `env` | `EnvReqChunkType` | `ssh.NewEnvRequest(ctx, dir, ts, *ssh.Request)` |
| `signal` | `SignalReqChunkType` | `ssh.NewSignalRequest(ctx, dir, ts, *ssh.Request)` |
| `window-change` | `WindowChangeReqChunkType` | `ssh.NewWindowChangeRequest(ctx, dir, ts, *ssh.Request)` |
| `x11-req` | `X11ForwardingReqChunkType` | `ssh.NewX11ForwardingRequest(ctx, dir, ts, *ssh.Request)` |
| `break` | `BreakReqChunkType` | `ssh.NewBreakRequest(ctx, dir, ts, *ssh.Request)` |
| `tcpip-forward` | `TCPIPForwardReqChunkType` | `ssh.NewTcpipForwardRequest(ctx, dir, ts, *ssh.Request)` |
| `cancel-tcpip-forward` | `CancelTCPIPForwardReqChunkType` | `ssh.NewCancelTcpipForwardRequest(ctx, dir, ts, *ssh.Request)` |
| unknown | `UnknownReqChunkType` | `ssh.NewUnknownRequest(ctx, dir, ts, *ssh.Request)` |

Each chunk is created with the appropriate `bsr.Direction` (inbound = client→worker, outbound = worker→target) and a fresh timestamp, then encoded to the channel's requests writer via `chunkEncoder.Encode(ctx, chunk)`.

**SSH data** (terminal I/O, exec output, etc.):
- For each `ssh.Channel.Read()` that returns data bytes, create `ssh.NewDataChunk(ctx, dir, ts, data)` and encode it
- For each `ssh.Channel.Write()` that receives data bytes, create a `DataChunk` in the opposite direction
- Max chunk size: `ssh.MaxPacketSize` (256 KiB); larger reads are split into multiple chunks

**Channel close events** (exit-status, exit-signal):
- `exit-status` → `ExitStatusReqChunkType` via `ssh.NewExitStatusRequest`
- `exit-signal` → `ExitSignalReqChunkType` via `ssh.NewExitSignalRequest`

### Writer Composition

Each BSR connection maintains four `*ChunkEncoder` instances:
- `requestsInbound` → encodes client→worker SSH requests
- `requestsOutbound` → encodes worker→target SSH requests  
- `messagesInbound` → encodes client→worker raw bytes (for terminal I/O before/after SSH framing — only used if capturing at byte level below the SSH layer)
- `messagesOutbound` → encodes worker→target raw bytes

For SSH, the primary recording path is through **requests** (all SSH protocol messages). The **messages** writers capture raw byte-level data for the SSH data channel (stdout/stderr of the shell/exec). This mirrors the existing non-multiplexed BSR recording pattern where `messages` files contain raw bytes and `requests` files contain parsed protocol structures.

### Chunk Timestamp Strategy

Use a monotonic timestamp from `bsr.NewTimestamp(ctx)` for each chunk. Timestamps are wall-clock time at capture. This matches the existing BSR timestamp pattern.

### Connection Close

When the `ProxyConnFn` returns (connection terminated):
1. Encode a `bsr.ChunkEnd` chunk to all four writers
2. Close each `ChunkEncoder` (triggers final flush)
3. Close BSR `Connection` (`conn.Close(ctx)`) — writes checksum manifest

### Session Close

When the boundary session expires or is terminated:
1. Close all open BSR `Connection` instances
2. Call `bsrSession.Close(ctx)` on the BSR session
3. The BSR session's `NewSyncingFS` triggers async upload to the storage bucket

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Chunk encoding granularity | One BSR chunk per SSH message (request or data frame) | Aligns with existing BSR chunk pattern; enables indexed playback and search |
| Per-connection BSR Connection | One BSR Connection per authorized connection ID | Matches existing BSR architecture; allows correlation between boundary connection and recording |
| Per-channel BSR Channel | One BSR Channel per SSH channel ID | Enables per-channel analysis; channel metadata (exec command, PTY dims) is captured in the channel's meta file |
| BSR protocol identifier | `ssh.Protocol` (`"BSSH"`) | Already defined; used for all SSH recording chunks |
| Compression | Configurable via `SshRecordingContext.compression`; default `GZIP` | Reduces storage size for large terminal sessions |
| Lazy BSR Session creation | First `AuthorizeConnection` creates the BSR Session | Avoids creating empty BSR sessions for sessions that never establish connections |
| Credential metadata in BSR | Credential store ID + type only; no secrets | Consistent with existing BSR `SessionMeta` pattern; secrets already handled by credential injection |

---

## Open Questions

### OQ1: How does the worker get the BSR KMS keys?

The `recorderManager` interface (`internal/daemon/worker/worker.go:80`) has `ReauthorizeAllExcept` and `SessionsManaged` but no explicit BSR session creation method. The current implementation creates BSR sessions via `recorderManager` (injected factory). **Decision needed:** Does the `recorderManager` own BSR session creation, or does the `SshRecordingManager` implementation call `w.RecordingStorage.NewSyncingFS()` directly and manage its own KMS keys?

The design assumes: `recorderManager` owns BSR session creation; `SshRecordingManager` is a thin wrapper that delegates to `recorderManager.GetOrCreateSession(ctx, boundarySessionId, sessionMeta)`.

### OQ2: Should we record raw bytes at the WebSocket layer or at the SSH message layer?

The current design records at the SSH message layer (channel requests + data). An alternative is to also record raw bytes at the WebSocket level (before SSH framing), which would capture the full byte stream including key exchanges and auth. **Decision needed:** Is SSH key exchange and auth phase recording in scope? The design currently records only post-auth SSH channel traffic.

### OQ3: How does the controller signal recording to the worker?

The `SshRecordingContext` is a new `ProtocolContext` payload. The controller must populate this when `target.enable_session_recording = true`. **Decision needed:** Does the controller include `SshRecordingContext` in every `AuthorizeConnectionResponse` for SSH targets with recording enabled, or only on the first connection? (First connection is simpler; all connections inherit the same recording config from session-level state.)

### OQ4: Fallback when recording storage is unavailable

If `RecordingStorage.NewSyncingFS()` fails (e.g., storage bucket unreachable), should the session fail or proceed without recording? **Decision needed:** Fail-fast (session terminated) or degrade gracefully (session continues, warning logged, recording dropped).

---

## Implementation Guidance

### Phase 1: `RecordingManager` Interface and Concrete Type

1. **Define `SshRecordingManager` interface** in `internal/daemon/worker/proxy/ssh/recording.go`:
   ```go
   type SshRecordingManager interface {
       Session() (*bsr.Session, error)
       NewConnection(ctx context.Context, connId string) (*bsr.Connection, error)
       Close(ctx context.Context) error
   }
   ```

2. **Update `proxy.RecordingManager`** type alias to `SshRecordingManager` in `internal/daemon/worker/proxy/proxy.go`:
   ```go
   type RecordingManager = SshRecordingManager
   ```

3. **Implement `sshRecordingManager`** in `internal/daemon/worker/proxy/ssh/recording.go`. It holds a reference to the worker's `recorderManager` and `RecordingStorage`, and lazily creates BSR sessions on first use.

4. **Wire `SshRecordingManager` into the worker's handler setup**: The worker creates an `sshRecordingManager` per session (stored on the session struct or in a map keyed by session ID). On each `handleProxy` call, it passes the session's `SshRecordingManager` to the handler.

### Phase 2: BSR Session Lifecycle in SSH Handler

1. **Modify `ssh.go` handler** to accept `SshRecordingManager` instead of `proxy.RecordingManager`:
   ```go
   func sshHandler(controlCtx, dataCtx, df, conn, pd, connId string, protoCtx *anypb.Any, rm ssh.SshRecordingManager) (ProxyConnFn, error)
   ```

2. **Add session recording setup** to `ssh.go`:
   - On first connection: resolve `sessionMeta` from the session, call `rm.Session()` to open BSR session
   - Store the BSR session on the handler struct for use across connections

3. **Add per-connection recording setup**:
   - Call `rm.NewConnection(ctx, connId)` → returns `*bsr.Connection`
   - Create four `*bsr.ChunkEncoder` instances (requests in/out, messages in/out)
   - Store on the connection context

### Phase 3: SSH Message → BSR Chunk Encoding

1. **Create `internal/daemon/worker/proxy/ssh/chunk_writer.go`**:
   - `type chunkWriter struct { encoder *bsr.ChunkEncoder, mu sync.Mutex }`
   - `func (cw *chunkWriter) WriteChunk(ctx context.Context, chunk bsr.Chunk) error` — thread-safe encode

2. **Create `internal/daemon/worker/proxy/ssh/ssh_interceptor.go`**:
   - `type sshInterceptor struct { requestsInbound, requestsOutbound, messagesInbound, messagesOutbound *chunkWriter }`
   - `func (si *sshInterceptor) EncodeRequest(ctx context.Context, dir bsr.Direction, req *ssh.Request) error` — maps request type to chunk, creates chunk via `ssh.NewXxxRequest()`, encodes
   - `func (si *sshInterceptor) EncodeData(ctx context.Context, dir bsr.Direction, data []byte) error` — creates `ssh.NewDataChunk()`, encodes
   - `func (si *sshInterceptor) Close()` — encodes `ChunkEnd` to all writers, closes encoders

3. **Wire interceptor into SSH bridge** in `ssh.go`:
   - After SSH handshake completes, wrap each SSH channel with an interceptor
   - For each incoming SSH request on a channel: call `interceptor.EncodeRequest()`, then forward to the other side
   - For each data read from an SSH channel: call `interceptor.EncodeData()`, then forward

4. **Handle channel lifecycle**:
   - On `session` channel open: create `bsr.Channel`, create new `sshInterceptor` for that channel
   - On `direct-tcpip` channel open: create `bsr.Channel`, create `sshInterceptor` for that channel (data only — no PTY/exec requests)
   - On channel close (exit-status/exit-signal): encode exit chunk, then close interceptor

### Phase 4: Controller-Side Recording Configuration

1. **Update `sshProtocolContext`** in `internal/daemon/cluster/handlers/ssh_protocol_context.go` to include `SshRecordingContext` when the target has `enable_session_recording = true`.

2. **Marshal `SshRecordingContext`** into a second `*anypb.Any` field (or combine with `SshProtocolContext` as a sub-message). The worker reads both from `AuthorizeConnectionResponse.ProtocolContext`.

### Phase 5: Testing

1. **Unit test `sshInterceptor.EncodeRequest`**: Mock `chunkWriter`, call `EncodeRequest` with each request type, verify correct chunk type and direction.
2. **Unit test `sshRecordingManager`**: Mock `recorderManager` and `RecordingStorage`, verify BSR session is created on first connection.
3. **Integration test**: Start an SSH target with a Boundary session, enable recording, verify BSR session files are created with correct chunk types.
4. **Playback test**: Open the BSR session with `bsr.OpenSession`, verify all expected chunks are present (session open, channel open, PTY request, exec, data chunks, exit status, close).

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Credential exposure in BSR | Credentials are NOT written to BSR. Only credential store ID and type (not secrets) are in `SessionMeta`. |
| Recording data exposure | BSR files are encrypted at rest via KMS wrapper. Session sync to storage bucket uses TLS. |
| Large recording DoS | Chunk size is capped at `ssh.MaxPacketSize` (256 KiB). Per-connection and per-session byte count limits apply from existing Boundary session limits. |
| BSR file corruption | Each BSR file has SHA256 checksum and HMAC signature verified on read. |
| Worker compromise | If the worker is compromised, recordings may be tampered with. This is mitigated by KMS-managed signing keys that the worker cannot access for the signing operation. |

---

## References

- **Parent design:** `docs/design/ssh-credential-injection.md`
- **BSR session/container:** `internal/bsr/bsr.go`, `internal/bsr/container.go`
- **BSR SSH chunks:** `internal/bsr/proto/ssh/v1/ssh_chunks.proto`, `internal/bsr/ssh/chunk.go`
- **BSR SSH chunk builders:** `internal/bsr/ssh/chunk_*.go` (e.g., `chunk_session_request.go`, `chunk_exec_request.go`)
- **BSR chunk encoder:** `internal/bsr/encode.go`
- **BSR session meta:** `internal/bsr/meta_session.go`, `internal/bsr/meta_recording.go`
- **Proxy handler signature:** `internal/daemon/worker/proxy/proxy.go`
- **Proxy handler invocation:** `internal/daemon/worker/handler.go:297`
- **Worker recording storage:** `internal/daemon/worker/worker.go:159`, `internal/storage/storage.go`
- **Session recording storage:** `internal/cmd/commands/dev/dev.go` (recording storage path configuration)
- **SSH library:** `golang.org/x/crypto/ssh`
- **Remote branch reference:** `backport/dheath-reorg-session-recording-operations/terribly-alert-bug` (existing session recording reorg)