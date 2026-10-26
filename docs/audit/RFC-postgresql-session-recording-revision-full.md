# PostgreSQL Session Recording — Revision RFC (Full)

## Metadata

- **Feature:** PostgreSQL Session Recording (BSR extension)
- **Protocol ID:** BPG4 (Boundary PostgreSQL Generation 4)
- **Original Rejected Design:** Used "PGSQ" instead of "BPG4", mismatched chunk type count
- **Previous Audit:** 13 issues (3 blocking, 4 high, 3 medium, 3 low)
- **Author:** staff-eng (via t_ab791d6c)
- **Lines:** 478 (summary header)
- **Codebase Source:** BSR SSH pattern in `internal/bsr/ssh/`, BSR core in `internal/bsr/`, session recording service

## 1. Protocol ID

**Decision:** Use `BPG4` (Boundary PostgreSQL Generation 4).

- Not `BPG3`, `PGSQ`, or `BPG`
- Follows the BSSH naming pattern: 4-character ID, product prefix + protocol
- Matches PRD specification §5.1

## 2. Chunk Types (9 Required)

### Chunk Type Table

| ID | Name | Mnemonic | Direction | PG Wire Type | Description |
|----|------|----------|-----------|-------------|-------------|
| 0 | HEAD | Header | - | - | Session initialization metadata |
| 1 | DONE | Done | I | Terminate ('X') | Session/connection termination |
| 2 | PGST | Startup | I | Startup packet | Startup message (null-terminated k=v pairs) |
| 3 | PGQR | Query | I | Query ('Q') | Simple query protocol |
| 4 | PGBR | Bind/Execute | I | Bind ('B')/Execute ('E') | Extended query bind + execute |
| 5 | PGEX | Error | O | ErrorResponse ('E') | Error responses from server |
| 6 | PGRO | Row Data | O | DataRow ('D') | Row data from query results |
| 7 | PGCM | Command Complete | O | CommandComplete ('C') | Command completion marker |
| 8 | PGSYNC | Sync | I | Sync ('S') | Sync in extended query |

### README: Missing PRD-Required Types

Four types from the PRD are NOT in the above table and are deferred:

| PRD Required Type | Status | Rationale |
|------------------|--------|-----------|
| CANC (CancelRequest) | DEFERRED | Cancel is rare in recordings; can be added as a follow-up |
| CLOS (Close) | DEFERRED | Close of prepared statements is implementation detail |
| COPY (CopyIn/CopyOut/COPY) | DEFERRED | COPY streaming is complex; handled as raw data via PGRO |
| NOTC (NoticeResponse) | DEFERRED | Notices are advisory; captured via PGEX or deferred |

These can be added in a Phase 6 without breaking backward compatibility since chunk types are identified by numeric ID.

## 3. Proto Schema

### File Locations

- **Proto definition:** `internal/proto/controller/storage/bsr/pg/v1/pg_chunks.proto`
- **Generated Go:** `internal/bsr/gen/pg/v1/pg_chunks.pb.go`

### Schema Design

```protobuf
syntax = "proto3";
package controller.storage.bsr.pg.v1;
option go_package = "github.com/hashicorp/boundary/internal/bsr/gen/pg/v1";

// BPG4_HEAD — Session header/metadata
message Bpg4Head {
  bytes session_id = 1;
  string target_address = 2;
  uint32 target_port = 3;
  string user_name = 4;
  string database_name = 5;
  int32 server_version = 6;
}

// BPG4_DONE — Session/connection termination
message Bpg4Done {
  string reason = 1;  // e.g., "normal", "error", "timeout"
  uint32 duration_ms = 2;
}

// BPG4_PGST — Startup message
message Bpg4Startup {
  map<string, string> parameters = 1;  // user, database, options, etc.
}

// BPG4_PGQR — Simple query
message Bpg4Query {
  string sql_text = 1;
}

// BPG4_PGBR — Bind/Execute (extended query)
message Bpg4BindExecute {
  string statement_name = 1;
  string portal_name = 2;
  repeated bytes parameter_values = 3;
  repeated bool is_null = 4;  // true if parameter is NULL
}

// BPG4_PGEX — Error response
message Bpg4Error {
  string severity = 1;
  string code = 2;
  string message = 3;
  string detail = 4;
}

// BPG4_PGRO — Row data
message Bpg4RowData {
  repeated bytes column_values = 1;
  repeated bool is_null = 2;
}

// BPG4_PGCM — Command complete
message Bpg4CommandComplete {
  string tag = 1;  // e.g., "INSERT 0 1", "SELECT 100"
  uint64 rows_affected = 2;
}

// BPG4_PGSYNC — Sync
message Bpg4Sync {
  // No payload — presence indicates sync point
}
```

### Null Handling Strategy
- **Binary protocol:** Explicit `is_null` bool per parameter/column
- **Text protocol:** Empty bytes for NULL values (per PG convention)
- The chunk decoder checks `is_null` before attempting type-specific decoding

## 4. Go Package Structure

```
internal/bsr/
  pg/
    chunks/
      chunk.go           — chunk registration, DecodeChunk dispatcher
      head.go            — HEAD chunk type
      done.go            — DONE chunk type
      startup.go         — PGST chunk type
      query.go           — PGQR chunk type
      bind_execute.go    — PGBR chunk type
      error.go           — PGEX chunk type
      row_data.go        — PGRO chunk type
      command_complete.go — PGCM chunk type
      sync.go            — PGSYNC chunk type
    chunk.go             — chunk type constants, BPG4 protocol registration
    convert/
      convert.go          — BPG4 to BSR display format conversion
```

Following the SSH pattern in `internal/bsr/ssh/`.

## 5. BSR Hierarchy

**Unchanged from existing BSR architecture:**

```
Session
  └── Connection
        ├── requests/  (I — inbound, client→server messages)
        │     ├── PGST, PGQR, PGBR, PGSYNC, DONE
        └── messages/ (O — outbound, server→client messages)
              ├── PGEX, PGRO, PGCM
```

HEAD and DONE are stored in the session/connection metadata, not as individual request/response files.

File layout follows BSSH convention exactly.

## 6. Wire Protocol Mapping

### Startup Messages (PGST)
- Captures the PostgreSQL startup packet (no type byte, per PG wire protocol §5.1.1)
- Contains null-terminated key=value pairs (user, database, options, etc.)
- Stored as a BPG4_PGST chunk with parameters map

### Regular Messages (all others)
- **Type byte** encoded as chunk type discriminator
- **Payload** (length + data per PG wire protocol) encoded as chunk data
- The decoder reads the first byte to determine chunk type, then dispatches to the appropriate proto unmarshaling

### Direction Convention
- **Inbound (client→server):** I files (requests)
- **Outbound (server→client):** O files (messages)
- **Note:** This uses `I`/`O` naming. BSR convention uses `up`/`down` (bsr.Direction enum). This should be reconciled to match existing convention.

## 7. Implementation Phases

### Phase 1: Proto + Code Generation
1. Create `internal/proto/controller/storage/bsr/pg/v1/pg_chunks.proto`
2. Run `buf generate` or `make protos` to generate `internal/bsr/gen/pg/v1/pg_chunks.pb.go`
3. Verify: `go build ./internal/bsr/...`

### Phase 2: Chunk Registration + Go Types
1. Create `internal/bsr/pg/chunk.go` — BPG4 protocol registration, chunk type constants
2. Create `internal/bsr/pg/chunks/*.go` — one file per chunk type, each implementing `bsr.Chunk`
3. Register all 9 chunk types with the BSR chunk registry
4. Implement `DecodeChunk` dispatcher following `internal/bsr/ssh/chunk.go` pattern
5. Verify: unit tests for encode/decode round-trip for each type

### Phase 3: Worker Integration
1. Implement PG session recording hook in the worker proxy layer
2. Distinguish OSS vs Enterprise:
   - **Enterprise:** Use `RecordingManager` (which exists)
   - **OSS:** `RecordingManager` is nil — implement no-op pass-through (no recording)
3. Add PG protocol context wiring:
   - `GetHandler` type-URL dispatcher must support `PostgresProtocolContext` type (requires proto definition)
   - **Note:** `PostgresProtocolContext` proto does not yet exist — this phase must create it

### Phase 4: Playback Service
1. Update the session recording service to handle BPG4 chunks
2. Add TypeURL/TypeName mapping for BPG4 chunk types
3. Wire into existing playback/serve endpoints

### Phase 5: Conversion + UI
1. Create BPG4→display format converter in `internal/bsr/pg/convert/`
2. Following pattern from `internal/bsr/convert/ssh.go`
3. Add PG-specific rendering in the admin UI
4. Implement credential column redaction during conversion

## 8. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Credentials in startup message | Startup (PGST) must be captured before KMS wrapping. Password field in startup parameters must be redacted. |
| SQL injection in playback | Chunk data is encoded protobuf; playback decodes via generated code — no SQL execution |
| Sensitive column data | Column detection + redaction in Phase 5 conversion |
| Recording integrity | HEAD chunk contains checksum of subsequent chunks; DONE chunk marks clean termination |

## 9. Open Questions (6)

1. **ErrorResponse handling** — ErrorResponse can have multiple fields (severity, code, message, detail, hint, position). Should all fields be captured, or just the standard subset?
2. **Connection pooling startup** — If the worker uses connection pooling, repeated startup messages for the same session should be deduplicated. How?
3. **Column name extraction** — PGRD (RowDescription) is not a chunk type. Column names need to be captured for meaningful playback. Where?
4. **Describe handling** — The Describe message interrogates prepared statement parameters and row descriptions. Should Describe (and its response, ParameterDescription + RowDescription) be recorded?
5. **Binary column decoding scope** — Which PG types need special binary decoding vs text representation? Initially just text for simplicity.
6. **Storage buffering** — Large sessions may produce gigabytes of row data. Buffering strategy: memory with spill-to-disk threshold.

## 10. References

- `internal/bsr/ssh/` — SSH BSR pattern (chunk registration, 20 chunk types)
- `internal/bsr/bsr.go` — Session/connection hierarchy
- `internal/bsr/chunk_header.go` — Wire format
- `internal/bsr/meta_session.go` — Session metadata fields
- `internal/bsr/convert/ssh.go` — Conversion pattern
- `internal/bsr/types.go` — Summary structs
- Session recording service stub in controller
- Website docs (confirm SSH-only recording currently)
