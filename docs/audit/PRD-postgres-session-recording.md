# PRD: PostgreSQL Session Recording for Boundary

**Status:** Draft v1
**Author:** researcher
**Date:** May 2026
**Target branch:** feature/postgres-session-recording
**Setup:** `learhy/boundary` fork on `feature/ssh-credential-injection` base

---

## 1. Problem Statement

Boundary currently supports session recording for SSH via the BSR (Boundary Session Recording) format, but has no database protocol recording capability. Enterprise customers running PostgreSQL databases need:

1. Tamper-resistant query-level audit logs that capture every SQL statement executed during a privileged database session.
2. A wire-protocol proxy that captures the actual bytes sent to the database (not a screen recording of a SQL GUI tool).
3. Storage of recordings in the same BSR format used for SSH recordings, enabling a unified playback/export pipeline.
4. Compliance coverage for SOC2 (CC6.1, CC7.2), PCI-DSS v4.0 (Req 10), HIPAA (164.312(b)), and FedRAMP (AU-2, AU-3, AU-12).

The solution is a PostgreSQL protocol-aware proxy handler registered in Boundary's worker, using the pgproto3 library to parse the PostgreSQL wire protocol and emit structured chunks into BSR containers.

---

## 2. Users and Use Cases

### Primary Users

| User | Description | Priority |
|------|-------------|----------|
| **Platform/Security Engineers** | Configure Boundary targets for PostgreSQL with session recording enabled; review query audit logs from BSR storage | P0 |
| **Auditors / Compliance Officers** | Export recorded DB sessions to demonstrate SOC2/PCI-DSS/HIPAA compliance; review query-level logs | P0 |
| **DBAs / Operations** | Connect via psql or application ORM through Boundary's TCP proxy with session recording; may have credentials managed by Boundary | P1 |
| **DevOps / Platform Teams** | Run automated database migrations through Boundary with session recording to maintain change audit trail | P1 |

### Key Use Cases

1. **Privileged DBA audit**: A DBA connects with `psql -h boundary-worker -p 5432 target_db`. Every SQL query they execute is recorded as structured BSR chunks with query text, parameters, and timestamps.

2. **Application database access**: A backend service connects via connection pooler through Boundary. All queries from that application instance are captured in a session recording.

3. **Credential injection with recording**: Boundary injects dynamic database credentials (from Vault) and simultaneously records all queries made with those credentials — binding who requested the creds to what they did.

4. **Compliance export**: Security team opens a recorded session from the Boundary UI/API and sees a time-ordered list of all SQL queries executed, with full parameter values reconstructed (not `$1`, `$2` placeholders).

5. **Real-time query alerting**: (Future) The proxy emits structured query events that trigger alerts for suspicious SQL patterns (`SELECT * FROM users`, `COPY users TO ...`, `DROP TABLE`).

---

## 3. Requirements

### 3.1 Functional Requirements

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| F1 | Proxy must register as a protocol handler for PostgreSQL connections | P0 | `proxy.RegisterHandler("postgres", ...)` |
| F2 | Proxy must accept raw TCP from the client, detect PostgreSQL startup | P0 | Detected via SSLRequest message or StartupMessage |
| F3 | Proxy must MITM TLS from client (terminate TLS, re-encrypt to backend) | P0 | Worker presents cert signed by Boundary CA |
| F4 | Proxy must capture the database name from the StartupMessage | P0 | Part of connection metadata |
| F5 | Proxy must capture the database user from the StartupMessage | P0 | Part of connection metadata |
| F6 | Proxy must capture Simple Query (`Q` message): full SQL text | P0 | Already handled in Teleport's pgproto3 model |
| F7 | Proxy must capture Extended Query protocol: Parse + Bind + Execute | P0 | Must correlate Parse+Execute by statement name; must decode Bind parameter values (binary or text format) |
| F8 | Proxy must capture CopyIn/CopyOut operations with metadata | P1 | Log table name, operation type; do NOT log data rows |
| F9 | Proxy must capture `CancelRequest` messages | P1 | Log cancellation events |
| F10 | Proxy must capture error responses from backend | P1 | Log error codes and messages |
| F11 | Proxy must capture query execution duration | P2 | From ReadyForQuery timing |
| F12 | Proxy must handle connection draining: write EndChunk, close BSR container | P0 | On both graceful close and error |
| F13 | Proxy must emit structured BSR chunks (new protocol "BPG4") | P0 | Follow SSH "BSSH" pattern |
| F14 | Proxy must write chunks as new data files under the Connection container in the BSR | P0 | Following `Connection.NewMessagesWriter` pattern |
| F15 | Proxy must accept `RecordingManager` from the worker and use it to initiate recording | P0 | Passed in Handler signature |
| F16 | Proxy must write an initial HeaderChunk when recording starts | P0 | Contains protocol "BPG4", compression, session ID |
| F17 | Proxy must NOT log result row data (SELECT results) | P0 | Log query text + params only, not response rows |

### 3.2 Non-Functional Requirements

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NF1 | Maximum throughput impact on proxied connection | <15% latency increase | vs raw TCP proxy |
| NF2 | Maximum memory per connection | <10MB baseline, <50MB burst | Pg buffer for pgproto3 parsing |
| NF3 | Maximum recording event write latency | <100ms before chunk is persisted | BSR buffer + periodic flush |
| NF4 | Max chunk data size before flush | 256KB | Matching SSH's MaxPacketSize |
| NF5 | Graceful degradation when recording storage is unavailable | Connection proceeds without recording; error is logged | Do NOT block the user's DB session |
| NF6 | TLS certificate provisioning | Per-cluster Boundary CA with per-target short-lived certs | POC: self-signed. Production: Vault PKI |
| NF7 | BSR format backward compatibility | New protocol types must be independently decodable | Existing BSR readers must not crash on unknown protocols |

### 3.3 Non-Goals

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | Capture SELECT result row data | Prohibitive volume; no compliance framework requires it |
| NG2 | PostgreSQL function/trigger source code auditing | Out of scope — this is query-level recording, not code review |
| NG3 | pg_stat_statements style query analysis | BSR is for session recording, not query optimization |
| NG4 | Wake-on-LAN or proxy warm-up | Connection establishment latency is acceptable |
| NG5 | MySQL / MSSQL / Oracle protocol support | This PRD covers PostgreSQL only |
| NG6 | Real-time query alerting engine | Future feature; this phase captures the data |
| NG7 | PgBouncer transaction-mode pooler support behind proxy | Would cause user attribution loss — must document this limitation |
| NG8 | Kerberos/GSSAPI authentication support | Deferred; SQL auth + SCRAM-SHA-256 first |

---

## 4. Architecture Overview

### 4.1 Hierarchy

```
BSR Session Container (.bsr)
  ├── session-meta.json         (SessionMeta: user, target, host, credentials)
  ├── session-recording.meta    (k:v pairs: id, protocol=BPG4, connection:<id>)
  ├── session-recording-summary.json
  ├── kms/                      (BSR key files, wrapped keys, signatures)
  ├── SHA256SUM                 (checksums for all files)
  ├── SHA256SUM.sig             (signature of SHA256SUM)
  │
  └── <connId>.connection/      (Connection container)
        ├── connection-recording.meta
        ├── connection-recording-summary.json
        ├── messages-inbound.data      (Chunks: client→server PG messages)
        ├── messages-outbound.data     (Chunks: server→client PG messages)
        ├── SHA256SUM
        └── SHA256SUM.sig
```

Key design decision: Unlike SSH where the hierarchy is Session→Connection→Channel (because SSH multiplexes channels over a connection), PostgreSQL sessions have a single bidirectional byte stream per connection. No Channel layer is needed. The Connection container directly holds `messages-inbound.data` and `messages-outbound.data`.

### 4.2 Data Flow

```
psql / libpq / ORM
  │ TCP (or TLS)
  ▼
Boundary Worker
  ├── WebSocket handler (receives connection from client)
  ├── proxy.GetHandler("postgres", protocolContext)  → handleProxy
  │   └── handleProxy:
  │        1. Detect PostgreSQL protocol (SSLRequest or StartupMessage)
  │        2. If recording enabled, create BSR Connection container
  │        3. If TLS: terminate TLS (Boundary CA cert), establish new TLS to backend
  │        4. Parse StartupMessage → capture db_name, db_user
  │        5. Forward authentication messages between client and backend
  │        6. Enter main loop:
  │           - Read frontend message from client (pgproto3.Frontend)
  │           - If recording: encode as BPG4 chunk, write to messages-inbound.data
  │           - Forward message to backend
  │           - Read response from backend (pgproto3.Backend)
  │           - If recording: encode as BPG4 chunk, write to messages-outbound.data
  │           - Forward response to client
  │        7. On connection close: write EndChunk, close BSR container
  │
  └── BSR Storage (RecordingStorage → SyncingFS → S3/GCS/Azure Blob)

Target PostgreSQL
  │ TCP (or TLS, with database's own CA)
  ▼
PostgreSQL Database
```

### 4.3 Key Integration Points in Boundary

| Component | Role |
|-----------|------|
| `internal/bsr/` | Existing BSR container infrastructure — reusable as-is |
| `internal/bsr/proto/ssh/v1/` | Existing protos — new `postgres/v1/pg_chunks.proto` needed |
| `internal/daemon/worker/proxy/proxy.go` | `RegisterHandler` — registers "postgres" handler |
| `internal/daemon/worker/proxy/tcp/tcp.go` | Pattern to follow for a protocol-aware handler |
| `internal/daemon/worker/handler.go` | Calls `proxyHandlers.GetHandler` then `handleProxyFn` — no changes needed |
| `internal/daemon/worker/worker.go` | `recorderManager` and `RecordingStorage` — consumed by handler |
| `internal/storage/` | `RecordingStorage` / `FS` / `Container` — used for BSR file I/O |

---

## 5. BSR Chunk Protocol

### 5.1 New Protocol Identifier

Following the existing SSH protocol `"BSSH"`:

```go
// New file: internal/bsr/postgres/postgres.go
const (
    Protocol bsr.Protocol = "BPG4"
)
```

**Why BPG4**: Must be exactly 4 characters (the BSR binary format uses a 4-byte protocol field). "BPG4" = Boundary PostgreSQL v4 protocol.

### 5.2 Chunk Types

Chunk type identifiers must be exactly 4 characters (matching the `chunkTypeSize = 4` constraint).

| Chunk Type | ID | Data Encoding | Description |
|------------|-----|---------------|-------------|
| DataChunk | `DATA` | Raw bytes | Any raw PG protocol bytes (fallback for unrecognized messages) |
| QueryChunk | `QUER` | protobuf | A Simple Query or Parse message (SQL text) |
| BindChunk | `BIND` | protobuf | Bind message with reconstructed parameter values |
| ErrorChunk | `ERRR` | protobuf | ErrorResponse from backend |
| NoticeChunk | `NOTC` | protobuf | NoticeResponse from backend |
| CopyChunk | `COPY` | protobuf | CopyIn/CopyOut meta (table name, operation), NOT data |
| CancelChunk | `CANC` | protobuf | CancelRequest |
| CloseChunk | `CLOS` | protobuf | Close message |
| TerminateChunk | `TERM` | protobuf | Terminate message |

### 5.3 Protobuf Schema

New file: `internal/bsr/proto/postgres/v1/pg_chunks.proto`

```protobuf
syntax = "proto3";
package postgres.v1;

// QueryChunk captures a SQL query from either Simple Query or Parse messages.
// For parameterized queries (Parse), the sql_text contains the statement with
// placeholder positions; parameter values come from the corresponding BindChunk.
message QueryChunk {
  // The SQL query text (for Simple Query) or the prepared statement SQL (for Parse)
  string sql_text = 1;

  // The prepared statement name (empty for Simple Query)
  string statement_name = 2;

  // The extended query portal name from Execute (empty for Simple Query)
  string portal_name = 3;

  // Whether this uses the simple query protocol (true) or extended query (false)
  bool is_simple_query = 4;
}

// BindChunk captures parameter values bound to a prepared statement.
// This is the critical piece that makes query logs actually useful — without it,
// parameterized queries record as "SELECT * FROM users WHERE id = $1" with no values.
message BindChunk {
  // The prepared statement name this bind corresponds to
  string statement_name = 1;

  // The portal name
  string portal_name = 2;

  // Parameter values, reconstructed to human-readable strings
  // For binary format parameters, the proxy decodes the type OID and converts to string
  repeated string parameters = 3;

  // The original SQL text from the corresponding Parse message,
  // for convenience (avoiding cross-chunk lookup)
  string sql_text = 4;
}

// ErrorChunk captures an ErrorResponse from the backend
message ErrorChunk {
  // PostgreSQL error code (e.g., "42P01" for undefined_table)
  string code = 1;

  // Human-readable message
  string message = 2;

  // Detail (optional)
  string detail = 3;

  // Hint (optional)
  string hint = 4;

  // Position in the original query (optional, for parse errors)
  uint32 position = 5;
}

// CopyChunk captures CopyIn/CopyOut metadata
message CopyChunk {
  // true = CopyIn (client→server), false = CopyOut (server→client)
  bool is_in = 1;

  // The table name being copied to/from
  string table_name = 2;

  // Column names (if available from CopyData analysis)
  repeated string columns = 3;
}

// CancelChunk captures a CancelRequest
message CancelChunk {
  // The process ID being canceled
  uint32 backend_pid = 1;

  // The secret key for the backend process
  uint32 backend_key = 2;
}

// CloseChunk captures a Close message (closing a prepared statement or portal)
message CloseChunk {
  // 'S' for prepared statement, 'P' for portal
  string close_type = 1;

  // Name of the statement or portal being closed
  string name = 2;
}

// TerminateChunk captures a Terminate message (end of session)
message TerminateChunk {
  // No additional fields needed
}
```

### 5.4 Chunk Registration Pattern

Following the SSH pattern in `internal/bsr/ssh/chunk.go`, the PostgreSQL package registers new chunk types in its `init()`:

```go
func init() {
    for _, ct := range []bsr.ChunkType{
        DataChunkType,
        QueryChunkType,
        BindChunkType,
        ErrorChunkType,
        NoticeChunkType,
        CopyChunkType,
        CancelChunkType,
        CloseChunkType,
        TerminateChunkType,
    } {
        if err := bsr.RegisterChunkType(Protocol, ct, DecodeChunk); err != nil {
            panic(err)
        }
    }
}
```

### 5.5 DataChunk for Raw Passthrough

For any PostgreSQL message type that doesn't have a dedicated chunk type, fall back to a raw `DataChunk`:

```go
type DataChunk struct {
    *bsr.BaseChunk
    Data []byte
}
```

The `DecodeChunk` switch will attempt to decode into the most specific chunk type first, falling back to DataChunk for unrecognized message types (analogous to SSH's UnknownReqChunkType).

---

## 6. PostgreSQL Handler Implementation

### 6.1 Package Structure

```
internal/daemon/worker/proxy/postgres/
├── postgres.go          // Main handler, registration
├── postgres_test.go     // Tests
├── chunker.go           // PG message → BSR chunk encoding
├── tls.go              // TLS termination and re-encryption
└── auth.go             // Authentication message forwarding
```

### 6.2 Handler Signature

Following the `Handler` type from `internal/daemon/worker/proxy/proxy.go`:

```go
type Handler func(
    controlCtx context.Context,
    dataCtx context.Context,
    df DecryptFn,
    conn net.Conn,
    pd *ProxyDialer,
    connId string,
    pb *anypb.Any,
    rm RecordingManager,
) (ProxyConnFn, error)
```

The PostgreSQL handler:
1. Inspects the first bytes from `conn` to determine if it's SSLRequest (4 bytes: length=8, code=80877103) or StartupMessage
2. If SSLRequest: negotiates TLS with client (using Boundary CA cert), then re-encrypts TLS to backend
3. Reads StartupMessage: captures db_name, db_user, client_encoding
4. Forwards authentication messages: AuthenticationOk, AuthenticationMD5Password, AuthenticationSASL (SCRAM-SHA-256) — forwards transparently
5. If recording is enabled and recordingManager is non-nil:
   - Creates BSR Session/Connection via recordingManager (same pattern as SSH recording)
   - Opens `messages-inbound.data` and `messages-outbound.data` writers
   - Writes HeaderChunk for each data file
6. Enters main bidirectional copy loop with protocol-aware parsing

### 6.3 Main Loop Pseudocode

```go
func handleProxy(ctx, dataCtx, conn, dialer, connId, protoCtx, rm) (ProxyConnFn, error) {
    // Detect protocol initiation
    peek, _ := conn.Peek(8)
    var startupParams map[string]string

    if isSSLRequest(peek) {
        // TLS MITM
        conn.Write([]byte{'S'}) // agree to SSL
        tlsConn := tls.Server(conn, boundaryTLSConfig)
        conn = tlsConn
        // Now read StartupMessage over TLS
        startupParams = readStartupMessage(tlsConn)
    } else {
        startupParams = readStartupMessage(conn)
    }

    // Dial backend
    backendConn, _ := dialer.Dial(ctx)

    // If client used TLS, also TLS to backend
    // (or plain TCP if backend doesn't require TLS)
    // ...

    // Forward startup to backend
    writeStartupMessage(backendConn, startupParams)

    // Forward authentication messages transparently
    forwardAuth(conn, backendConn)

    // If recording enabled, init BSR
    var inboundWriter, outboundWriter io.Writer
    if rm != nil && recordingEnabled {
        session := rm.GetOrCreateSession(ctx, sessionId)
        connection := session.NewConnection(ctx, connMeta)
        inboundWriter = connection.NewMessagesWriter(ctx, bsr.Inbound)
        outboundWriter = connection.NewMessagesWriter(ctx, bsr.Outbound)
        // Write HeaderChunks
        encoder := bsr.NewChunkEncoder(ctx, inboundWriter, ...)
        encoder.Encode(ctx, bsr.NewHeader(ctx, Protocol, bsr.Inbound, ...))
        // ... same for outbound
    }

    // Main loop
    go func() {
        pgConn := pgproto3.NewFrontend(conn, backendConn)
        for {
            msg, _ := pgConn.Receive()
            switch m := msg.(type) {
            case *pgproto3.Query:
                writeChunk(ctx, inboundWriter, QueryChunk{sql: m.String})
                writeAndForward(backendConn, m) // forward to backend
            case *pgproto3.Parse:
                writeChunk(ctx, inboundWriter, QueryChunk{sql: m.Query, stmt: m.Name})
                writeAndForward(backendConn, m)
            case *pgproto3.Bind:
                writeChunk(ctx, inboundWriter,
                    BindChunk{stmt: m.PreparedStatement, params: m.Parameters})
                writeAndForward(backendConn, m)
            // ... etc for all message types
            }
        }
    }()

    // Similar goroutine for backend→client direction

    return func() {
        // Wait for both goroutines, write EndChunks, close BSR connection
    }, nil
}
```

### 6.4 pgproto3 Library

**Recommendation**: Use `github.com/jackc/pgproto3/v2` (MIT license).

This library provides:
- `pgproto3.Frontend` — parses client→server messages, provides typed structs (`Query`, `Parse`, `Bind`, `Execute`, `Close`, `Terminate`, `CopyData`, etc.)
- `pgproto3.Backend` — parses server→client messages (`Authentication*`, `ReadyForQuery`, `CommandComplete`, `DataRow`, `ErrorResponse`, `NoticeResponse`, etc.)
- `pgproto3.StartupMessage` — parses PostgreSQL startup parameters
- `pgproto3.SASL` — SCRAM-SHA-256 support

The library is production-grade, used by Teleport's database proxy, and handles the full PostgreSQL wire protocol including error cases.

**Go dependency**: `github.com/jackc/pgproto3/v2 v2.3.2` (or latest)

**Important**: The library does NOT include TLS negotiation (SSLRequest handling). That must be implemented in the handler, which is consistent with how SSH recording handles its protocol negotiation.

### 6.5 TLS Certificate Handling

Current status: Boundary's TCP proxy (`tcp.go`) does no TLS. The SSH proxy uses SSH's own transport security. For PostgreSQL:

1. **Client-facing TLS**: Boundary worker must present a TLS certificate that the client trusts.
   - POC: Use a self-signed Boundary CA cert distributed out-of-band to clients via `PGSSLROOTCERT`.
   - Production: Integrate with Vault PKI secrets engine to issue per-target short-lived certs.

2. **Backend-facing TLS**: Proxy establishes a second TLS connection to the PostgreSQL backend.
   - The proxy can use the backend's native CA cert (if Boundary has access to it) or skip verification if configured (not recommended).
   - For managed PostgreSQL (RDS, CloudSQL), use the public CA root chain — AWS RDS uses public CAs.

3. **SSLRequest negotiation**:
   - Client sends 8 bytes: `Int32(8) | Int32(80877103)`
   - Server (proxy) responds with byte `'S'` (SSL supported) or `'N'` (not supported)
   - Then TLS handshake occurs on the same TCP connection
   - After TLS, the client sends the StartupMessage over the TLS session

```go
// handleSSLNegotiation
func handleSSLNegotiation(conn net.Conn, tlsConfig *tls.Config) (*tls.Conn, error) {
    buf := make([]byte, 8)
    _, err := io.ReadFull(conn, buf)
    if err != nil {
        return nil, err
    }
    length := binary.BigEndian.Uint32(buf[:4])
    sslCode := binary.BigEndian.Uint32(buf[4:])
    if length != 8 || sslCode != 80877103 {
        return nil, fmt.Errorf("not an SSLRequest")
    }
    conn.Write([]byte{'S'})
    return tls.Server(conn, tlsConfig), nil
}
```

### 6.6 Connection State Tracking

The handler must track per-connection state:

```go
type pgState struct {
    // From StartupMessage
    Database     string
    User         string
    ClientEncoding string

    // Prepared statement cache (for Parse+Bind+Execute correlation)
    PreparedStatements map[string]*ParsedStatement

    // TLS info
    UsingTLS     bool
}
```

The prepared statement cache is needed because:
- `Parse` message contains the SQL text with `$1`, `$2` placeholders
- `Bind` message contains parameter values, referenced by statement name
- Without correlating them, logs show `SELECT * FROM users WHERE id = $1` with no actual values
- Cache is per-connection (prepared statements are connection-scoped)

### 6.7 Authentication Message Forwarding

The proxy forwards authentication messages transparently (does NOT participate in authentication). Messages to handle:

| Message Type | Treatment |
|--------------|-----------|
| AuthenticationOk | Forward to client |
| AuthenticationMD5Password | Forward to client |
| AuthenticationSASL | Forward to client |
| AuthenticationSASLContinue | Forward bidirectionally |
| AuthenticationSASLFinal | Forward bidirectionally |
| AuthenticationCleartextPassword | Forward to client |
| BackendKeyData | Capture for CancelRequest tracking; forward to client |
| ReadyForQuery | Signals end of transaction; forward to client |

The proxy does NOT need to inspect or modify credentials — it only needs to track the authentication outcome to know when the session is ready for recording.

---

## 7. BSR Integration Details

### 7.1 New Protocol Package

```go
// internal/bsr/postgres/doc.go
// Package postgres defines chunk types for recordings of the PostgreSQL protocol.
package postgres

// internal/bsr/postgres/postgres.go
const (
    Protocol bsr.Protocol = "BPG4"
)
```

### 7.2 Chunk Registration

New file: `internal/bsr/postgres/chunk.go` — follows the exact pattern of `internal/bsr/ssh/chunk.go`:

```go
package postgres

import (
    "context"
    "fmt"

    "github.com/hashicorp/boundary/internal/bsr"
    ppg "github.com/hashicorp/boundary/internal/bsr/gen/postgres/v1"
    "github.com/hashicorp/boundary/internal/bsr/internal/is"
    "google.golang.org/protobuf/proto"
)

func init() {
    for _, ct := range []bsr.ChunkType{
        DataChunkType,
        QueryChunkType,
        // ... all BPG4 chunk types
    } {
        if err := bsr.RegisterChunkType(Protocol, ct, DecodeChunk); err != nil {
            panic(err)
        }
    }
}

// DataChunk contains the raw byte data from a PostgreSQL session
type DataChunk struct {
    *bsr.BaseChunk
    Data []byte
}

func NewDataChunk(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, data []byte) (*DataChunk, error) {
    baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, DataChunkType)
    if err != nil {
        return nil, fmt.Errorf("...")
    }
    return &DataChunk{BaseChunk: baseChunk, Data: data}, nil
}

// ... similar for QueryChunk, BindChunk, etc.
// Each has: New*Chunk(), MarshalData(), and DecodeChunk() switch branch
```

### 7.3 Write Path

```go
// Inside the main loop, when recording is active:
func writeQueryChunk(w io.Writer, direction bsr.Direction, sql string, ts *bsr.Timestamp) error {
    encoder, _ := bsr.NewChunkEncoder(ctx, w, bsr.GzipCompression, bsr.NoEncryption)
    chunk, _ := postgres.NewQueryChunk(ctx, direction, ts, sql)
    _, err := encoder.Encode(ctx, chunk)
    return err
}
```

Chunks are written to `messages-inbound.data` (client→server) and `messages-outbound.data` (server→client) in the Connection container. Each data file gets:
1. HeaderChunk (protocol=BPG4, compression, session ID)
2. N content chunks (Query, Bind, Error, etc.)
3. EndChunk

### 7.4 Recording Lifecycle

Following the SSH data writer pattern:

1. On initial connection: `recorderManager.GetOrCreateSession()` → creates BSR Session
2. On first data: `session.NewConnection(connMeta)` → creates Connection container
3. For each data file: `connection.NewMessagesWriter(direction)` → returns writer
4. Write HeaderChunk to each writer
5. In main loop: write typed chunks to corresponding writer
6. On connection close: write EndChunk to each writer, close connection container
7. On session close: close session container

---

## 8. BSR Conversion / Playback

### 8.1 Asciicast Export

The current SSH BSR has a `convert` package (`internal/bsr/convert/`) that converts SSH recordings to asciicast format for playback. For PostgreSQL recordings:

- **Phase 1**: No conversion (playback is not the primary use case for DB session recording)
- **Phase 2**: Implement a JSON-export converter that produces a time-ordered list of SQL queries with parameters — essentially a session replay as a SQL script timeline

### 8.2 Query Timeline UI (Future)

For the Boundary admin UI, a recorded PostgreSQL session could render as:
```
Timestamp          | Direction | Query
2026-05-29T14:23:01| Client    | SET statement_timeout = '300s'
2026-05-29T14:23:02| Client    | BEGIN
2026-05-29T14:23:02| Client    | SELECT id, email FROM users WHERE created_at > $1
                   |           | Parameters: [2025-01-01]
                   |           | Duration: 12ms, Rows: 142
2026-05-29T14:23:03| Server    | ErrorResponse: 42P01 (undefined_table)
2026-05-29T14:23:04| Client    | ROLLBACK
2026-05-29T14:23:05| Client    | Terminate
```

---

## 9. Test Plan

### 9.1 Unit Tests

| Test | Description | Coverage |
|------|-------------|----------|
| `TestSSLRequestDetection` | Verify SSLRequest bytes are correctly identified | `postgres/postgres_test.go` |
| `TestStartupMessageParsing` | Verify db_name, db_user captured from StartupMessage | `postgres/postgres_test.go` |
| `TestSimpleQueryCapture` | Verify `Q` message → QueryChunk with correct SQL | `postgres/postgres_test.go` |
| `TestExtendedQueryCapture` | Verify Parse+Bind+Execute → QueryChunk+BindChunk with correct correlation | `postgres/postgres_test.go` |
| `TestBindBinaryParameters` | Verify binary-encoded parameter value decoding | `postgres/postgres_test.go` |
| `TestTLSMITM` | Verify TLS handshake with self-signed CA and re-encryption to backend | `postgres/tls_test.go` |
| `TestErrorMessageCapture` | Verify ErrorResponse → ErrorChunk with code and message | `postgres/postgres_test.go` |
| `TestCancelRequestCapture` | Verify CancelRequest → CancelChunk | `postgres/postgres_test.go` |
| `TestConnectionStateTracking` | Verify prepared statement cache works correctly | `postgres/postgres_test.go` |
| `TestChunkEncodeDecodeRoundtrip` | Verify PG chunk types survive encode→decode roundtrip | `postgres/chunk_test.go` |
| `TestHandlerRegistration` | Verify `proxy.RegisterHandler("postgres", ...)` succeeds | `postgres/postgres_test.go` |
| `TestRecordingLifecycle` | Verify BSR Session→Connection→writer lifecycle with recording manager | Integration test |

### 9.2 Integration Tests

| Test | Description |
|------|-------------|
| `TestLivePostgresProxy` | Start a real PostgreSQL container, connect via proxy, execute queries, verify recorded chunks |
| `TestTLSWithRealPG` | Same as above but with TLS on both client→proxy and proxy→backend |
| `TestCredentialInjection` | Proxy injects Boundary credentials and records session (requires credential manager) |
| `TestLargeQueryCapture` | 10MB query payload, verify chunking and streaming |
| `TestConcurrentSessions` | 10 simultaneous PostgreSQL sessions through proxy, verify all record correctly |
| `TestRecordingStorageFailure` | Storage unavailable, verify connection continues without recording |

### 9.3 Compat Matrix

| psql version | libpq version | Driver | Status |
|---|---|---|---|
| psql 14 | libpq 14 | psycopg2 | Must pass |
| psql 15 | libpq 15 | psycopg3 | Must pass |
| psql 16 | libpq 16 | pgx (Go) | Must pass |
| psql 17 | libpq 17 | node-postgres | Must pass |
| RDS PostgreSQL 14/15/16 | - | - | Must pass |
| CloudSQL PostgreSQL 14/15/16 | - | - | Must pass |
| Aurora PostgreSQL | - | - | Must pass |
| CockroachDB (PG wire) | - | - | Best effort (handled by PG protocol compat) |

---

## 10. Dependencies

### New Go Dependencies

| Package | License | Purpose |
|---------|---------|---------|
| `github.com/jackc/pgproto3/v2` | MIT | PostgreSQL wire protocol message parsing |
| `github.com/jackc/pgtype` | MIT | PostgreSQL OID type resolution (for binary parameter decoding) |

### Protobuf Generation

New proto file: `internal/bsr/proto/postgres/v1/pg_chunks.proto`
Generated file: `internal/bsr/gen/postgres/v1/pg_chunks.pb.go`

Generation command (following existing pattern):
```bash
buf generate internal/bsr/proto/postgres/v1/
```

### BSR Changes

| File | Change |
|------|--------|
| `internal/bsr/proto/postgres/v1/pg_chunks.proto` | NEW — protobuf definitions for PG chunk types |
| `internal/bsr/gen/postgres/v1/pg_chunks.pb.go` | NEW — generated code |
| `internal/bsr/postgres/doc.go` | NEW — package doc |
| `internal/bsr/postgres/postgres.go` | NEW — protocol constant, init() registration |
| `internal/bsr/postgres/chunk.go` | NEW — chunk type definitions, MarshalData/DecodeChunk |
| `internal/bsr/postgres/chunk_test.go` | NEW — encode/decode roundtrip tests |

### New Proxy Handler Files

| File | Change |
|------|--------|
| `internal/daemon/worker/proxy/postgres/postgres.go` | NEW — handler implementation |
| `internal/daemon/worker/proxy/postgres/postgres_test.go` | NEW — handler tests |
| `internal/daemon/worker/proxy/postgres/chunker.go` | NEW — PG message → BSR chunk conversion |
| `internal/daemon/worker/proxy/postgres/tls.go` | NEW — SSLRequest handling, TLS MITM |
| `internal/daemon/worker/proxy/postgres/auth.go` | NEW — authentication message forwarding |

### Existing Files (no changes needed)

- `internal/bsr/bsr.go` — Session, Connection, Channel types (Channel not used for PG)
- `internal/bsr/encode.go` — ChunkEncoder
- `internal/bsr/decode.go` — ChunkDecoder, RegisterChunkType
- `internal/bsr/chunk.go` — BaseChunk, Chunk interface
- `internal/bsr/chunk_header.go` — HeaderChunk
- `internal/bsr/chunk_end.go` — EndChunk
- `internal/bsr/container.go` — container
- `internal/bsr/meta_recording.go` — Session/Connection/Channel recording meta
- `internal/bsr/meta_session.go` — SessionMeta
- `internal/daemon/worker/proxy/proxy.go` — Handler type, RegisterHandler
- `internal/daemon/worker/handler.go` — handler dispatch (no changes)
- `internal/daemon/worker/worker.go` — recorderManager (no changes)

---

## 11. Compliance Coverage Map

| Compliance Requirement | How This Feature Satisfies It |
|------------------------|-------------------------------|
| **SOC2 CC6.1** (Logical Access) | Records who accessed which database with what query |
| **SOC2 CC7.2** (Anomaly Monitoring) | Structured query data enables anomaly detection rules |
| **PCI-DSS v4.0 Req 10.2.1** (Audit Logs) | Captures all individual user access to cardholder data environments |
| **PCI-DSS v4.0 Req 10.2.1.1** (DB Queries) | Explicitly captures SQL queries against database tables |
| **PCI-DSS v4.0 Req 10.3.1** (Protect Logs) | BSR uses checksums + signatures for tamper-evidence |
| **PCI-DSS v4.0 Req 10.5.1** (Retention) | Storage to S3/GCS with Object Lock for immutable log retention |
| **HIPAA 164.312(b)** (Audit Controls) | Records activity in systems containing ePHI at the query level |
| **FedRAMP AU-2** (Event Logging) | Logs database access events in scope for High baseline |
| **FedRAMP AU-3** (Audit Record Content) | Each chunk includes: timestamp, direction, user, query text |
| **FedRAMP AU-12** (Audit Generation) | Wire-protocol capture is independent of application-level logging |

---

## 12. Open Questions

| # | Question | Decision Needed By | Notes |
|---|----------|--------------------|-------|
| Q1 | Should we use `github.com/jackc/pgproto3/v2` or a fork? | Staff engineer | Library is MIT-licensed, used by Teleport |
| Q2 | TLS certificate provisioning: self-signed Boundary CA or Vault PKI for POC? | Staff engineer | Self-signed is simpler for POC; Vault PKI adds dependency |
| Q3 | Should PostgreSQL connections use a Channel container (like SSH) or write directly to Connection data files? | Staff engineer | PG has no multiplexing; Connection-level files are sufficient |
| Q4 | Should `BindChunk` store decoded parameter VALUES (strings) or raw OID+bytes? | Staff engineer | Strings are human-readable for audit; raw bytes are lossless for forensic replay |
| Q5 | What is the maximum acceptable chunk flush interval? | Staff engineer | Teleport defaults to per-query (flush on ReadyForQuery). For high-throughput, may need periodic flush. |
| Q6 | Should the proxy log `CommandComplete` metadata (rows affected, OID)? | Staff engineer | Useful for DUration tracking — captured in Server message direction |
| Q7 | What is the prepared statement cache eviction policy? | Staff engineer | Per-connection, bounded by connection lifetime (no eviction needed for typical sessions) |
| Q8 | Do we need to handle the PostgreSQL v3 or v2 protocols? | Staff engineer | v3 only (PostgreSQL 7.4+). v2 is obsolete. |
| Q9 | Should the BPG4 protocol identifier be versioned for future PG protocol changes? | Staff engineer | BPG4 → BPG5 for future extensions if needed |
| Q10 | How should SCRAM-SHA-256 authentication be handled? Forward transparently or participate? | Staff engineer | Forward transparently is simpler and avoids credential handling |
| Q11 | What about `pg_stat_statements` query IDs — should we include them in chunks? | Staff engineer | Optional enrichment — not needed for MVP |
| Q12 | Should we handle `LISTEN`/`NOTIFY` messages? | Staff engineer | Log the subscribe/unsubscribe; NOTIFY payload messages are low-value for audit |

---

## 13. Prior Art

- **Teleport Database Access** (`github.com/gravitational/teleport/lib/srv/db/`): Wire-protocol proxy with full PostgreSQL support, session recording to S3, and typed chunk storage. Closest architectural analog.
- **StrongDM**: Commercial wire-protocol proxy for 30+ databases with session recording. Validates the product category.
- **CyberArk PSM for Databases**: Agent-based database session recording (not wire-protocol). Does not intercept native client connections.
- **Boundary SSH Recording**: The existing BSR infrastructure and SSH handler pattern in this codebase is the direct template for this work.

---

## 14. Success Criteria

### MVP Milestone (Phase 1)

1. PostgreSQL client connects through Boundary worker proxy
2. Simple Query protocol: all `Q` messages are recorded as `BPG4` chunks in BSR
3. Extended Query protocol: Parse+Bind+Execute queries are correlated and recorded with reconstructed parameter values
4. TLS MITM works: client↔proxy TLS terminated, proxy↔backend TLS established
5. BSR container hierarchy is correct: Session → Connection → `messages-inbound.data` / `messages-outbound.data`
6. Recordings survive encode→decode roundtrip (roundtrip test)
7. Storage integration works: BSR files persist to `RecordingStorage` (local filesystem for dev)
8. All unit tests pass (15+ tests)
9. Integration test with real PostgreSQL container

### Phase 2 (Stretch)

10. ErrorResponse messages are recorded
11. CopyIn/CopyOut metadata is recorded
12. CancelRequest is handled
13. CockroachDB (PG wire-compatible) works
14. Concurrent connections all record correctly

### Phase 3 (Future)

15. BSR export/converter to structured JSON timeline
16. Vault PKI for TLS certificate provisioning
17. Per-query performance metrics (duration, row count)
18. Boundary admin UI can display PG session recordings

---

## 15. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| pgproto3 library has unhandled message types | Chunks silently dropped | Medium | Fall back to DataChunk for unknown types |
| TLS certificate management complexity | Project stall | Medium | Start with self-signed; Vault PKI is a separate workstream |
| Parameterized query binary format decoding | Broken logs for prepared statements | Medium | Use pgtype for OID resolution; test with all common types (text, int, uuid, timestamp, jsonb) |
| Performance impact on high-throughput DB | Proxy becomes bottleneck | Low | Async writes to BSR; never block the byte forwarding path |
| BSR format changes from upstream Boundary | Breaking changes | Low | Stick to published interfaces (bsr.Chunk, bsr.RegisterChunkType) |
| pgproto3 v2 vs v3 API changes | Library upgrade breakage | Low | Pin to specific version; use in isolation |
| Connection pooling behind proxy | Attribution errors | Medium | Document limitation: proxy must be between client and pooler, not between pooler and database |
