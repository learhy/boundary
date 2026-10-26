# PostgreSQL Session Recording — Revision RFC

## Status

| Field | Value |
|-------|-------|
| Author | staff-eng (t_ab791d6c) |
| Version | rev2 |
| Protocol ID | BPG4 (Boundary PostgreSQL Generation 4) |
| Lines | 478 |
| Previous rejection | 13 issues (3 blocking, 4 high, 3 medium, 3 low) |

## Protocol ID

**BPG4** (not BPG3, not PGSQ). Follows the BSSH naming pattern: 4-char ID, product prefix + protocol.

## Chunk Types (9)

| ID | Name | Description |
|----|------|-------------|
| 0 | HEAD | Session header/meta |
| 1 | DONE | Session completion |
| 2 | PGST | Startup message (null-terminated k=v pairs, no type byte per PG spec) |
| 3 | PGQR | Simple query (type byte 'Q') |
| 4 | PGBR | Bind/execute (type bytes 'B'/'E') |
| 5 | PGEX | Error response (type byte 'E') |
| 6 | PGRO | Row data (type byte 'D') |
| 7 | PGCM | Command complete (type byte 'C') |
| 8 | PGSYNC | Sync (type byte 'S') |

## Proto Schema

**File:** `internal/proto/controller/storage/bsr/pg/v1/pg_chunks.proto`
**Go generated:** `internal/bsr/gen/pg/v1/pg_chunks.pb.go`

Covers: startup, simple query, bind, execute, row data, command complete.
Null handling via explicit `is_null` bool (binary) vs empty bytes (text).

## Go Package Structure

```
internal/bsr/pg/
  chunks/       — chunk registration
  convert/      — conversion to display format
```

Following the SSH pattern (`internal/bsr/ssh/`).

## BSR Hierarchy

Unchanged — Session > Connection > requests+messages files. File layout identical to BSSH.

## Wire Mapping

- **PGST**: Captures startup as null-terminated k=v pairs (no type byte, per PG spec)
- **All other messages**: Type byte encoded as chunk type, payload (length+data) as chunk data
- **Direction**: client→server → requests (I files), server→client → messages (O files)

## 5 Implementation Phases

1. Proto + buf generate
2. Chunk registration + Go types
3. Worker integration
4. Playback service
5. Conversion/UI

## Security

- Startup message (user/credentials) must be captured before KMS wrapping
- Credential columns must be detected and redacted in Phase 5 conversion

## 6 Open Questions

1. ErrorResponse handling — how to capture multi-field error responses
2. Startup capture with connection pooling — what happens to startup when pool reuses connections
3. Column name extraction — PGRD (describe) chunk content
4. Describe (PgDescribe) handling — statement introspection
5. Binary column decoding scope — which column types need special handling
6. Storage buffering for large sessions — memory vs disk
