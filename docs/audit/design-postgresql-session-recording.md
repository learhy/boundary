# PostgreSQL Session Recording — Design Doc

## Summary

PostgreSQL session recording captures SQL query events from a PostgreSQL wire-protocol proxy handler and persists them in Boundary Session Recording (BSR) format, following the same container/chunk hierarchy used for SSH session recording. This design extends the postgres credential injection handler (the "proxy" phase) with a "recording" phase that parses PostgreSQL v3 protocol messages, emits typed BSR chunks per query, and writes them to the session's BSR store via the existing `proxy.RecordingManager` interface. Credential injection must be completed first per `PRD_POSTGRES_CREDENTIAL_INJECTION.md`; this document covers only the session recording layer.

**Branch:** `feature/postgresql-session-recording`
**Base:** `feature/ssh-credential-injection`
**Depends on:** `feature/postgres-credential-injection` (proxy handler + auth infrastructure)
**Deliverable:** `docs/design/postgresql-session-recording.md` (this document) + implementation in `internal/daemon/worker/proxy/postgres/` and `internal/bsr/postgres/`

---

## Background

### Existing Architecture

#### BSR Container Hierarchy

The BSR stores session recordings in a directory structure under a storage bucket:

```
{session-recording-id}.bsr/
├── session-meta.json
├── wrappedBsrKey
├── wrappedPrivKey
├── bsrKey.pub
├── pubKeyBsrSignature.sign
├── pubKeySelfSignature.sign
├── {conn-id}.connection/
│   ├── meta.json
│   ├── connection
│   ├── messages-up.data   ← chunk stream, client→backend
│   ├── messages-down.data ← chunk stream, backend→client
│   └── {channel-id}.channel/ (SSH only — not used for postgres)
```

- **Session** (`.bsr/`): top-level container. Created once per Boundary session.
- **Connection** (`{conn-id}.connection/`): created per TCP connection within the session. PostgreSQL sessions are multiplexed at the TCP level — each `psql` connection is one `Connection`.
- **Channel** (`{channel-id}.channel/`): used for SSH (which is multiplexed within a TCP connection). PostgreSQL is not multiplexed at the wire level; channels are not used.
- **Messages files**: gzip-compressed chunk streams. Each chunk is 4-byte length + protocol (4) + chunk type (4) + direction (1) + timestamp (12) + compression + data + CRC (4).

The BSR `Session` is created at session activation time (controller side). `Connection` containers are created by the worker via the `RecordingManager` interface passed to the proxy handler.

#### SSH Chunk Pattern

The SSH BSR package (`internal/bsr/ssh/`) registers protocol `"BSSH"` and defines typed chunk structs (e.g., `ExecRequest`, `PtyRequest`) that wrap protobuf-generated types from `internal/bsr/gen/ssh/v1/`. Each chunk:
1. Has a 4-character type ID (e.g., `"EXEC"`, `"PTYR"`)
2. Implements `bsr.Chunk` (embedding `*bsr.BaseChunk`)
3. Is registered with `bsr.RegisterChunkType(Protocol, ChunkType, DecodeFn)` in `init()`
4. Has a `NewXxx()` constructor and a `MarshalData()` method

The SSH handler writes chunks by constructing them and piping to a `*bsr.ChunkEncoder` backed by the connection's `NewMessagesWriter()`.

#### PostgreSQL Credential Injection Handler (Prerequisite)

The postgres proxy handler (`internal/daemon/worker/proxy/postgres/`) implements:

1. **Full termination**: maintains independent auth on both sides — client→proxy and proxy→backend
2. **pgproto3/v2**: parses and forwards all PostgreSQL v3 wire protocol messages after auth
3. **TLS termination**: client-facing and backend-facing TLS
4. **Auth handling**: cleartext, MD5, SCRAM-SHA-256 (types 3, 5, 10)
5. **Bridge**: bidirectional `io.Copy`-equivalent using `pgproto3.Frontend` / `pgproto3.Backend` after auth

The postgres handler currently has no recording integration. Once the credential injection phase is complete, the next step (this design) is to replace the `io.Copy`-equivalent bridge with a recording-aware message forwarder that emits BSR chunks.

#### Key Existing Types

- `proxy.Handler` signature: `func(controlCtx, dataCtx, DecryptFn, net.Conn, *ProxyDialer, connId string, *anypb.Any, RecordingManager) (ProxyConnFn, error)`
- `proxy.RecordingManager` is typed as `any` — the handler receives it but does not use it in the current implementation
- `GetHandler` (proxy.go): dispatches to handlers by `*anypb.Any.TypeUrl`. For postgres: `"type.googleapis.com/worker.proxy.v1.PostgresProtocolContext"`
- `bsr.Protocol` = `string` — max 4 chars. SSH uses `"BSSH"`. PostgreSQL uses `"PGSQ"`.
- `bsr.Direction` = enum `{up, down}`
- `bsr.ChunkEncoder.Encode(ctx, chunk)`: serializes + compresses + writes a chunk to the backing io.Writer

---

## Design

### Architecture Overview

```
Client App (psql)
  │
  │  TCP / TLS
  ▼
PostgreSQL Proxy Handler (internal/daemon/worker/proxy/postgres/)
  │
  ├─ Frontend (pgproto3.Frontend) ← reads from client
  ├─ Backend  (pgproto3.Backend)  ← reads from backend
  │
  ├─ Auth phase: credential injection (postgres-credential-injection feature)
  │
  └─ Recording phase (this design):
       │
       ├─ MessageParser: reads pgproto3 messages, identifies query/response/event
       ├─ ChunkEmitter: wraps parsed data in bsr.Chunk, encodes via ChunkEncoder
       └─ Bridge: forwards messages client↔backend after recording

  │
  │  TCP / TLS
  ▼
PostgreSQL Backend
```

### BSR Chunk Protocol: `"PGSQ"`

Register `"PGSQ"` as the PostgreSQL protocol identifier, following the `"BSSH"` pattern.

#### Chunk Types

| Type ID | Name | Direction | Contains |
|---------|------|-----------|----------|
| `"STRD"` | Startup | up | Full startup message (user, database, params) — sanitized |
| `"AUTH"` | Auth | up | Auth method + outcome (success/failure) |
| `"QRY"`  | Query | up | SQL query text |
| `"QRP"`  | Query Response | down | Row count, column count, error (if any) |
| `"BIND"` | Bind | up | Prepared statement name + portal + parameter values |
| `"BNDR"` | Bind Response | down | Bind outcome (success/error) |
| `"EXEC"` | Execute | up | Portal name + max rows |
| `"EXCR"` | Execute Response | down | Execution outcome (rows affected, error) |
| `"SYNC"` | Sync | up | Sync message (ends implicit transaction) |
| `"ERRR"` | Error | down | PostgreSQL ErrorResponse |
| `"DONE"` | Session End | both | Normal termination |
| `"DATA"` | Raw Data | both | Fallback: raw bytes for unparsed messages |

**Design decision:** Use typed chunks for auditable events (query, bind/execute with params) and raw chunks for protocol messages that don't carry audit-relevant data (CopyData, CopyDone, etc.). This mirrors the SSH pattern where SSH channel requests are typed but raw channel data uses `DATA`.

**OQ1 (open):** Should `QRY` include the database name and username from the StartupMessage, or is that metadata only in the session/connection metadata? The BSR already captures session metadata — confirm whether the postgres chunk should carry a copy or rely on metadata only.

### Proto Definitions

**File:** `internal/bsr/proto/postgres/v1/postgres_chunks.proto`
**Package:** `postgres.v1`
**Go package:** `github.com/hashicorp/boundary/internal/bsr/gen/postgres/v1`

```protobuf
syntax = "proto3";

package postgres.v1;

option go_package = "github.com/hashicorp/boundary/internal/bsr/gen/postgres/v1";

// QueryChunk contains a SQL query and its context.
message QueryChunk {
  string query = 1;
  string database = 2;
  bool is_simple = 3;  // true if from Query message; false if from Parse+Bind+Execute
}

// BindChunk contains a prepared statement execution with parameter values.
message BindChunk {
  string statement_name = 1;
  string portal_name    = 2;
  repeated bytes param_values = 3;
  repeated string param_types = 4;  // OIDs, if known
  string database = 5;
}

// BindResponseChunk contains the outcome of a Bind.
message BindResponseChunk {
  int32 num_params = 1;
  bool  error = 2;
  string error_message = 3;
}

// ExecuteResponseChunk contains the outcome of an Execute.
message ExecuteResponseChunk {
  int64 rows_affected = 1;
  bool  error = 2;
  string error_message = 3;
}

// StartupChunk contains the sanitized startup message parameters.
message StartupChunk {
  string user    = 1;
  string database = 2;
  map<string, string> options = 3;
}

// AuthChunk contains the authentication method and result.
message AuthChunk {
  string method = 1;   // "cleartext", "md5", "scram-sha-256", "unspecified"
  bool   success = 2;
  string error = 3;
}

// ErrorChunk contains a PostgreSQL ErrorResponse.
message ErrorChunk {
  string severity = 1;
  string code     = 2;  // SQLSTATE
  string message  = 3;
  string detail   = 4;
}
```

> **Note:** The `QueryChunk.query` field carries the raw SQL string as received from the client. The BSR does **not** do SQL redaction — that is a downstream concern for the playback/analysis layer. Credentials are never embedded in chunk data because the proxy has already consumed them for auth.

### New Package: `internal/bsr/postgres/`

Mirrors `internal/bsr/ssh/`. Files:

```
postgres/
├── chunk.go            — Protocol constant, chunk type constants, init() registration, DecodeChunk
├── chunk_startup.go    — StartupChunk struct, NewStartupChunk()
├── chunk_auth.go       — AuthChunk struct, NewAuthChunk()
├── chunk_query.go      — QueryChunk struct, NewQueryChunk()
├── chunk_bind.go       — BindChunk struct, NewBindChunk()
├── chunk_bind_response.go
├── chunk_execute_response.go
├── chunk_error.go      — ErrorChunk struct
├── chunk_data.go       — DataChunk (raw bytes fallback)
├── chunk_done.go       — Done chunk (marker)
└── postgres_test.go
```

#### `chunk.go` Skeleton

```go
const (
    Protocol bsr.Protocol = "PGSQ"
)

const (
    StartupChunkType      bsr.ChunkType = "STRD"
    AuthChunkType         bsr.ChunkType = "AUTH"
    QueryChunkType        bsr.ChunkType = "QRY"
    BindChunkType         bsr.ChunkType = "BIND"
    BindResponseChunkType bsr.ChunkType = "BNDR"
    ExecuteChunkType      bsr.ChunkType = "EXEC"
    ExecuteRespChunkType  bsr.ChunkType = "EXCR"
    SyncChunkType         bsr.ChunkType = "SYNC"
    ErrorChunkType        bsr.ChunkType = "ERRR"
    DataChunkType         bsr.ChunkType = "DATA"
    DoneChunkType         bsr.ChunkType = "DONE"
)

func init() {
    for _, ct := range []bsr.ChunkType{
        StartupChunkType, AuthChunkType, QueryChunkType,
        BindChunkType, BindResponseChunkType, ExecuteChunkType,
        ExecuteRespChunkType, SyncChunkType, ErrorChunkType,
        DataChunkType, DoneChunkType,
    } {
        if err := bsr.RegisterChunkType(Protocol, ct, DecodeChunk); err != nil {
            panic(err)
        }
    }
}
```

### New Package: `internal/daemon/worker/proxy/postgres/recording.go`

Replaces or wraps the existing post-auth bridge in `postgres.go`. The recording-aware bridge:

1. Maintains a `statementName → parsedSQL` map per connection (for prepared statement reconstruction)
2. Maintains a `portalName → statementName` map per connection (for bind/execute tracking)
3. Reads messages from the client `pgproto3.Frontend` and the backend `pgproto3.Backend` separately
4. For each message, decides whether to emit a typed chunk or a raw `DATA` chunk
5. Forwards messages to the other side after chunk emission

**Core interface:**

```go
// MessageRecorder wraps a pgproto3 message and emits a BSR chunk.
type MessageRecorder struct {
    enc      *bsr.ChunkEncoder
    ts       *bsr.Timestamp
    stmtMap  map[string]string  // statement name → parsed SQL
    portalMap map[string]string // portal name → statement name
}

// RecordFrontend reads from the client-facing pgproto3.Frontend and emits chunks.
// RecordBackend reads from the backend-facing pgproto3.Backend and emits chunks.
// Both run in goroutines until the connection closes.
```

**Key capture points:**

| pgproto3 Type | Action |
|---|---|
| `pgproto3.Query` | Emit `QueryChunk` (is_simple=true) |
| `pgproto3.Parse` | Store `stmtName → SQL` in stmtMap |
| `pgproto3.Bind` | Emit `BindChunk` with resolved SQL from stmtMap; store `portalName → stmtName` |
| `pgproto3.Describe` | No chunk — just updates portal tracking |
| `pgproto3.Execute` | Emit `ExecuteChunk` (portal name, max rows) |
| `pgproto3.Sync` | Emit `SyncChunk` |
| `pgproto3.Terminate` / `pgproto3.Close` | Emit `DoneChunk` |
| `pgproto3.ErrorResponse` | Emit `ErrorChunk` on both directions |
| Any other frontend message | Emit `DATA` chunk (raw bytes) |

> **Note:** `pgproto3.Frontend` reads from the client; `pgproto3.Backend` reads from the database. Both directions emit BSR chunks to their respective message files.

### RecordingManager Integration

The `proxy.RecordingManager` passed to the handler is `any`-typed. The postgres handler casts it to the concrete type used by the worker.

**OQ2 (open):** How does the worker create and pass the `RecordingManager` for postgres connections? In the SSH handler, the recording manager is passed as a parameter. Confirm the worker-side wiring for a non-multiplexed protocol where each TCP connection corresponds to one `bsr.Connection`.

The expected pattern:
1. Worker calls `handleProxy` with `rm proxy.RecordingManager`
2. Postgres handler creates `bsr.Connection` via `rm.NewConnection(ctx, meta)`
3. Gets `NewMessagesWriter(ctx, bsr.Up)` and `NewMessagesWriter(ctx, bsr.Down)`
4. Wraps writers in `*bsr.ChunkEncoder` (with gzip compression, per session settings)
5. Passes encoders to `MessageRecorder`

### Prepared Statement Tracking

PostgreSQL uses a three-message sequence for prepared statements: `Parse` (send SQL template) → `Bind` (assign parameters and portal) → `Execute` (run). To produce audit logs with actual parameter values substituted:

- On `Parse`: store `stmtName → SQL` in `stmtMap`
- On `Bind`: look up `stmtMap[stmtName]` → SQL. Emit `BindChunk` with SQL + param values. Store `portalName → stmtName` in `portalMap`
- On `Execute`: look up `portalMap[portalName]` → stmtName → SQL. Emit `ExecuteChunk` with portal name

This gives audit logs that show: the template, the bound parameter values, and the row count.

> **Note:** For simple `Query` messages, the full SQL is available in one message. Emit `QueryChunk` immediately.

### No Channels

PostgreSQL v3 protocol does not multiplex multiple "channels" within a single TCP connection the way SSH does with `session`/`direct-tcpip` channels. Therefore:
- No `bsr.Channel` containers are created for postgres sessions
- Each `psql` invocation = one `bsr.Connection`
- Multiple concurrent `psql` connections = multiple `bsr.Connection` entries within the same `bsr.Session`

### Database Schema Changes

**None required.** The BSR storage format already supports arbitrary protocols via the chunk system. No database migrations are needed.

---

## Data Model

### No New Tables

Session recording metadata is already stored in the existing `session_recording` table. The postgres handler writes chunk files to the BSR store (S3/MinIO/etc.) via the existing storage bucket infrastructure.

### No New Proto Definitions for Controller/Worker Wire Protocol

The `worker.proxy.v1.PostgresProtocolContext` from the credential injection design already carries the credential and TLS configuration. Session recording does not require additional wire protocol messages — chunks are written by the worker directly to the BSR store, not sent over the wire.

---

## Worker Routing

No changes to `GetHandler` routing. The postgres handler is selected because `AuthorizeConnectionResponse.ProtocolContext` contains a `PostgresProtocolContext` (from the credential injection feature). Once the handler is invoked, recording is enabled when the `RecordingManager` is non-nil and the session's storage bucket is configured for recording.

---

## Alternatives Considered

### 1. Raw Byte Recording Instead of Protocol Parsing

Record all bytes as `DATA` chunks without parsing the PostgreSQL protocol. This avoids the complexity of `pgproto3` message parsing and prepared statement tracking.

**Rejected because:**
- Raw byte recording is indistinguishable from TCP proxying for audit purposes — you can't reconstruct SQL queries from a byte stream without protocol parsing
- Compliance requirements (SOC2 AU-2, CC6.1) require query-level attribution, not just byte-level
- The `pgproto3` library is already an indirect dependency; the parsing work is bounded

### 2. Store Query Events in Database Instead of BSR

Write query events to the existing Boundary database instead of the BSR store.

**Rejected because:**
- BSR is the established session recording infrastructure with encryption, KMS key management, storage bucket isolation, and playback/convert tooling already in place
- Database writes at query frequency would be a significant performance and storage burden
- BSR is designed for high-throughput binary recording; the database is not

### 3. Use a Separate Recording Connection

Have the postgres proxy open a separate connection to the database for the purpose of replicating queries to a logging service.

**Rejected because:**
- Adds latency (two connections per query instead of one)
- Credential management complexity (separate auth context for the logging connection)
- The proxy already sees all traffic — no need for a second channel

### 4. Defer Recording to a Separate Process

Run query recording in a separate goroutine or process that receives parsed events over a channel.

**Rejected because:**
- Complexity of IPC between proxy and recorder goroutines
- The pgproto3 message stream is naturally sequential; parallelizing adds no benefit
- The BSR write is already buffered and compressed in the `ChunkEncoder`; the dominant latency is network I/O, not encoding

---

## Implementation Guidance

### Prerequisites (Must Be Completed First)

1. `feature/postgres-credential-injection` — postgres handler with full termination + TLS + auth + basic message bridge
2. `make protos` must succeed so `internal/bsr/gen/postgres/v1/` exists

### Phase 1: BSR Protocol Registration

1. Create `internal/bsr/proto/postgres/v1/postgres_chunks.proto` with chunk types above
2. Run `buf generate` (or `make protos`) to generate `internal/bsr/gen/postgres/v1/`
3. Create `internal/bsr/postgres/chunk.go` — protocol constant, type constants, `init()` registration, `DecodeChunk`
4. Create all typed chunk files: `chunk_startup.go`, `chunk_auth.go`, `chunk_query.go`, `chunk_bind.go`, `chunk_bind_response.go`, `chunk_execute_response.go`, `chunk_error.go`
5. Verify: `go build ./internal/bsr/postgres/...`
6. Write unit tests for each chunk type (encode/decode roundtrip)

### Phase 2: RecordingManager Wiring

1. Trace how `proxy.RecordingManager` is constructed and passed to handlers in `internal/daemon/worker/handler.go`
2. Confirm the type assertion needed in the postgres handler (may be `*bsr.Session` or a wrapper)
3. In the postgres handler's `handleProxy` function, after auth succeeds and before starting the bridge:
   - If `rm` is nil → fall back to plain message forward (no recording)
   - If `rm` is non-nil → call `rm.NewConnection(meta)` to create a `*bsr.Connection`
   - Create `*bsr.ChunkEncoder` wrappers for `Up` and `Down` directions

**OQ3 (open):** Confirm the exact `RecordingManager` type in this fork. The `RecordingManager` is typed as `any` in `proxy.go` — trace the concrete type in the worker handler to determine the correct type assertion.

### Phase 3: MessageParser / ChunkEmitter

1. Create `internal/daemon/worker/proxy/postgres/recording.go`
2. Implement `MessageRecorder` struct with `stmtMap` and `portalMap`
3. Implement `recordFrontend()` and `recordBackend()` goroutines
4. Handle all pgproto3 message types per the capture point table above
5. For `Parse` messages: extract SQL from `pgproto3.Parse` and store in `stmtMap`
6. For `Bind` messages: look up `stmtMap[stmtName]`, emit `BindChunk` with resolved SQL + param values
7. For `Execute` messages: look up `portalMap[portalName]`, emit `ExecuteChunk`
8. Wrap raw/unparsed messages in `DataChunk`

### Phase 4: Replace the Existing Bridge

The current `postgres.go` post-auth bridge is a `io.Copy`-equivalent. After Phase 3, replace it with the recording-aware forwarder.

1. Keep the auth phase exactly as-is (credential injection is working and tested before recording is added)
2. After auth completes, start `recordFrontend()` and `recordBackend()` goroutines
3. Shut down gracefully when either side closes
4. Emit `DoneChunk` on normal termination; emit `ErrorChunk` on abnormal termination

### Phase 5: End-to-End Test

1. Create a real PostgreSQL container in the test suite (Docker or testinfra)
2. Start a Boundary session with postgres target + injected credential + storage bucket with recording enabled
3. Execute queries via `psql`: simple `SELECT`, prepared statement with params, transaction with multiple statements
4. Open the resulting BSR file and verify:
   - `StartupChunk` with correct user/database
   - `QueryChunk` with correct SQL
   - `BindChunk` + `ExecuteChunk` with correct SQL and parameter values
   - `ErrorChunk` for any intentionally bad query
5. Verify playback/convert tooling can read the postgres BSR (may require a convert plugin — see OQ4)

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Credential in query text | Credentials are consumed during auth (PasswordMessage is intercepted and used for backend auth, not forwarded). Query text never contains the password. |
| Credential in Bind parameters | `BindChunk` records parameter values in plaintext. For sensitive parameters (passwords, PII), the recording layer must support field-level redaction — tracked as OQ5. |
| SQL injection via recorded queries | BSR records what was executed; SQL injection is a query-content concern for the analysis/playback layer. |
| BSR key compromise | BSR key management is handled by the existing KMS infrastructure (`bsr/kms/keys.go`). No new key management needed. |
| Large queryDoS | Chunk size is bounded per BSR spec. Long queries are chunked at the max packet size boundary. |

---

## Open Questions

### OQ1: Session metadata in chunks vs. metadata only

Should postgres chunks carry database name and username inline, or is that metadata exclusively in `session-meta.json`? The SSH chunks carry `session_id` (via the header chunk) but not user/target inline — it's in metadata. Confirm this is acceptable for postgres audit logs.

### OQ2: RecordingManager type and creation path

The `RecordingManager` is passed to handlers as `any`. The postgres handler needs to:
1. Determine the concrete type (likely `*bsr.Session` or a wrapper)
2. Call `NewConnection()` to create a BSR connection
3. Get the message writers

**Decision needed:** Trace `RecordingManager` creation in `internal/daemon/worker/handler.go` before Phase 2.

### OQ3: BSR convert/playback support for postgres

The existing BSR convert tooling (e.g., `bsr convert`) has SSH-specific output formatters. PostgreSQL recordings need a playback path — either a `psql` replay tool or a structured JSON export.

**Recommendation:** Add a `convert/postgres.go` that emits structured JSON with one JSON object per chunk, suitable for log aggregation pipelines (Splunk, Datadog, etc.). Full visual replay (like asciinema for SSH) is out of scope for MVP.

### OQ4: Sensitive parameter redaction

The `BindChunk` records parameter values in plaintext. If a parameter contains a password or PII, this is recorded. Need a redaction strategy — either field-level redaction by OID (e.g., OID for `text` vs. OID for `bpchar`) or a config option per credential library.

**Decision needed from product requirements:** Should all parameters be recorded, only numeric parameters, or parameters classified by type?

### OQ5: Fallback if recording fails

If `rm.NewConnection()` returns an error (e.g., storage bucket unreachable), should the session continue without recording or should it fail? Current BSR behavior for SSH: if recording fails, the session terminates. Confirm this is the desired behavior for postgres.

---

## Key Design Decisions (Made)

| Decision | Choice | Rationale |
|---|---|---|
| Protocol identifier | `"PGSQ"` | 4-character limit; mirrors `"BSSH"` for SSH |
| Chunk strategy | Typed for auditable events, raw `DATA` for non-auditable | Matches SSH pattern; avoids over-engineering for protocol messages that carry no audit signal |
| Prepared statement tracking | In-process maps per connection | Single TCP connection = single postgres connection; maps are safe without locking |
| Storage format | BSR chunk files (same as SSH) | Reuses existing infrastructure; no new storage design needed |
| No channels | Per SSH — not applicable to postgres | PostgreSQL is not multiplexed; each connection is one `bsr.Connection` |
| Message direction | `up` = client→backend, `down` = backend→client | Standard BSR convention |
| Compression | gzip (default, per session settings) | Matches existing BSR default |

---

## Testing Strategy

### Unit Tests

1. **Chunk encode/decode roundtrip**: Each chunk type (`QueryChunk`, `BindChunk`, etc.) → `MarshalData()` → `DecodeChunk()` → verify fields match
2. **Prepared statement map**: Parse + Bind + Execute sequence → verify `QueryChunk` contains correct SQL and params
3. **Error chunk**: Verify `ErrorResponse` maps to `ErrorChunk` fields
4. **Data chunk (fallback)**: Raw bytes → `DataChunk` → decode → verify raw bytes preserved

### Integration Tests

1. **Happy path**: Start postgres container, establish session with recording enabled, run `SELECT`, `INSERT`, `UPDATE`, verify chunks in BSR
2. **Prepared statement**: `PREPARE`, `EXECUTE` with parameters, verify `BindChunk` + `ExecuteChunk`
3. **Auth**: Verify `StartupChunk` has correct user/database and `AuthChunk` shows success
4. **Error path**: Send invalid SQL, verify `ErrorChunk` with correct SQLSTATE and message
5. **Multiple connections**: Two concurrent `psql` sessions → two `Connection` containers in BSR
6. **Regression**: Ensure credential injection still works after recording is wired in

### Non-Goals for Testing

- Performance benchmarking (tracked separately)
- TLS failure scenarios (handled by credential injection tests)
- All 50+ PostgreSQL message types (only the audit-relevant ones)

---

## References

- **Parent PRD (credential injection):** `PRD_POSTGRES_CREDENTIAL_INJECTION.md`
- **SSH BSR chunk pattern:** `internal/bsr/ssh/chunk.go`, `internal/bsr/ssh/chunk_exec_request.go`
- **BSR encode infrastructure:** `internal/bsr/encode.go`, `internal/bsr/chunk.go`, `internal/bsr/chunk_header.go`
- **BSR container hierarchy:** `internal/bsr/bsr.go` — `Session`, `Connection` types
- **PostgreSQL wire protocol:** [PostgreSQL Protocol Documentation](https://www.postgresql.org/docs/current/protocol.html) — Message formats for `Query`, `Parse`, `Bind`, `Execute`, `ErrorResponse`
- **pgproto3/v2:** `github.com/jackc/pgproto3/v2` — frontend/backend message types used by the postgres handler
- **Existing postgres proxy handler:** `internal/daemon/worker/proxy/postgres/` (depends on `feature/postgres-credential-injection`)
- **Worker handler wiring:** `internal/daemon/worker/handler.go:286` — how `GetHandler` and `RecordingManager` are passed
- **BSR SSH session recording:** `internal/bsr/convert/ssh.go` — playback/convert pattern for reference