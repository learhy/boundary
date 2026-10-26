# PostgreSQL Credential Injection — PRD

**Status:** Draft for review | **Last updated:** 2026-05-29
**Target branch:** `feature/postgres-credential-injection`
**Base branch:** `main` (same base as `feature/ssh-credential-injection`)

---

## 1. Problem Statement

Boundary can currently broker credentials to sessions (username/password from static stores or Vault), but it has no protocol-aware proxy for PostgreSQL. When a user targets a PostgreSQL database through Boundary:

- The TCP proxy forwards bytes blindly — no credential injection
- The user must manually pass credentials to their psql client (via PGPASSFILE or command-line)
- The session recording cannot capture query-level audit logs
- The user's workflow is: `boundary connect postgres` → copy credentials → run psql with PGPASSFILE

This feature closes the gap: **the worker proxy authenticates to the PostgreSQL backend on behalf of the user using the brokered credential, so the user can connect with any client without managing secrets.**

---

## 2. Users and Use Cases

### Primary: DBA Connecting to a Production PostgreSQL Database

1. User authorizes a session against a target with a brokered credential source attached
2. User runs `boundary connect postgres -target-id ttcp_123` (or uses the SDK)
3. Boundary proxies the local port; the PostgreSQL proxy handler intercepts and completes TLS + auth using the brokered credential
4. User runs `psql -h localhost -p 12345` or uses DBeaver/DataGrip — no password entry needed
5. The same proxy layer captures and logs all SQL queries for audit

### Secondary: Application Connection via Connection Pooler

1. An application connects to a local Boundary proxy port
2. Proxy authenticates to the PostgreSQL backend using the brokered credential
3. Application connects as if it were the database — the credential is transparent

### Non-User: Automated Compliance Pipeline

1. A downstream system (SOC2 auditor, anomaly detection pipeline) reads session recording events
2. Captured SQL queries with parameter values provide evidence for CC6.1, CC7.2, AU-2 compliance

---

## 3. Requirements

### 3.1 Functional Requirements

**F-1. PostgreSQL handler registration.** A new `postgres` handler must be registered via `proxy.RegisterHandler()` with a handler name string (e.g. `"postgres"`). The `GetHandler` function in `proxy.go` must be updated to resolve the protocol from `SessionAuthorizationData.type` (which currently returns `"tcp"`, `"ssh"`, etc.) — this may require either a change to how `SessionAuthorizationData.type` is set for database targets, or a different mechanism to pass protocol context.

**F-2. Protocol-aware proxy loop.** The handler must use `jackc/pgproto3/v2` to parse and forward PostgreSQL wire protocol messages in both directions (client→backend and backend→client). The proxy must maintain two pgproto3 sessions:
  - **Client-facing (Frontend):** reads client messages, generates backend-like responses
  - **Backend-facing (Backend):** generates client-like messages to the real database, reads responses

**F-3. TLS termination.** The handler must terminate TLS from the client (presenting a Boundary-issued certificate) and establish a new TLS connection to the backend (validating against the backend's certificate or skipping validation based on configuration). This matches the pattern described in DB_MARKET_RESEARCH.md and used by Teleport.

**F-4. Credential injection at auth time.** When the backend sends an `AuthenticationRequest` message (types 3, 5, or 10), the handler must reply with a `PasswordMessage` using the brokered credential (username + password from `LookupSessionResponse` or `SessionCredential`).

  - **Cleartext (type 3):** Forward the password as-is.
  - **MD5 (type 5):** Compute `md5(hex(md5(password+user)) + salt)` from the brokered credential and the server-provided salt.
  - **SASL / SCRAM-SHA-256 (type 10):** Complete the full SASL exchange using the brokered credential. The lib/pq or pgx libraries already implement this — consider using `pgx/v5/pgconn` for the backend-side auth and extracting the authenticated conn.

**F-5. Credential receipt on the worker.** The handler must receive the brokered credential at session establishment time. The current `Handler` signature includes `*anypb.Any` (protocol_context) which can carry per-connection parameters. When a session is authorized, the worker receives `LookupSessionResponse` which includes `credentials` (deprecated) — but the credential is also present in the `SessionAuthorization.Credentials` that the client receives and forwards to the worker as part of the proxy protocol. The exact credential delivery path must be traced and a `Credential` protobuf message (username/password from `controller.servers.services.v1`) must be available in the handler.

**F-6. Protocol context for connection metadata.** The handler should accept a protocol-context `anypb.Any` message that specifies:
  - Database name to connect to (optional — defaults to user's default database)
  - TLS configuration (whether to skip verify, CA certificate)

**F-7. Graceful passthrough on non-auth errors.** If credential injection fails (wrong password, expired credential, TLS error), the proxy must close the connection and log the error. It must NOT fall through to a blind TCP proxy.

**F-8. Prepared statement handling (optional, future).** The proxy should parse `P` (Parse) and `B` (Bind) messages to reconstruct full parameterized queries with actual values. This is required for audit logging fidelity but is a separate deliverable from credential injection. (Not required for MVP — see Non-Goals.)

### 3.2 Non-Functional Requirements

**NF-1. Latency impact.** Protocol-aware framing must not add more than 1ms per message beyond the TLS termination overhead. Use buffered reads/writes; do not introduce per-message goroutine context switches.

**NF-2. Compatibility.** The handler must work with:
  - `psql` (any version using the v3 wire protocol — PostgreSQL 7.4+)
  - DBeaver, DataGrip, pgAdmin
  - Go `lib/pq` and `pgx` drivers
  - Node.js `pg`, Python `psycopg2`/`asyncpg`, Ruby `pg`
  - PgBouncer in session mode (NOT transaction mode — see NF-6)

**NF-3. TLS verification.** The backend-facing TLS must verify the backend's certificate by default. Skip-verify must be configurable via the target's attributes (currently no target attribute exists for this — may need a new target attribute or session option).

**NF-4. Auth method handling.** The handler must handle all three PostgreSQL auth methods (cleartext, MD5, SASL/SCRAM-SHA-256). On startup, the handler must be prepared for any of the three. SASL is the most complex and is the default for PostgreSQL 10+.

**NF-5. Prepared statement logging.** Bind messages must be correlated with their corresponding Parse message to reconstruct parameter values. The proxy must track `statementName → parsedSQL` and `portalName → statementName + parameters` for each connection. Implemented in the recording layer, not the credential injection layer.

**NF-6. Connection state tracking.** The handler must track per-connection state:
  - Current username (set at auth time)
  - Current database (set in StartupMessage, changed by `\c` or `SET DATABASE`)
  - TLS state (pre-TLS vs post-TLS)
  - Auth state (awaiting, authenticating, authenticated)

---

## 4. Non-Goals (Explicitly Out of Scope)

| Item | Rationale |
|------|-----------|
| MongoDB, MySQL, MSSQL proxy handlers | Separate features on separate branches |
| Query recording / session recording | Requires BSR (Boundary Session Recording) infrastructure that doesn't exist in this fork yet. A separate feature. |
| Prepared statement parameter capture (Bind) | Can be added later to the recording layer; not needed for credential injection MVP |
| Response content logging (row data returned by SELECT) | Not needed for compliance; only query text + params are required |
| Kerberos/GSSAPI auth | Extremely rare in PostgreSQL deployments; not in the top auth methods |
| PostgreSQL-native certificate auth | Out of scope for MVP — only username/password credential injection |
| Transaction-mode connection pooler support | PgBouncer transaction-mode pools cannot reliably attribute queries; document as a known limitation |
| Certificate management for client-facing TLS | Assumes Boundary will provision a per-cluster CA. For MVP: self-signed cert generated at worker startup. |
| Target attribute changes for database type | Would require upstream Boundary proto changes. The immediate approach is to pass the database target type via protocol_context. |

---

## 5. Technical Design Summary

### 5.1 Architecture

```
(same Boundary session plumbing as TCP — handshake, authorization, worker routing)

Client App
  │
  │ (TCP connection to local boundary-proxied port)
  ▼
Boundary Worker (PostgreSQL Proxy Handler)
  │
  │──[client-facing leg]─────────────────────────────┐
  │  Frontend (pgproto3)                             │
  │  - Accepts client StartupMessage                 │
  │  - Handles SSLRequest → TLS termination          │
  │  - Sends auth challenges as server would          │
  │  - Receives PasswordMessage from client           │
  │  - Validates? No — ignores client password         │
  │  - Sends AuthenticationOk to client               │
  │  - Forwards queries to backend-facing leg         │
  ├─────────────────────────────────────────────────┤
  │──[backend-facing leg]────────────────────────────┐│
  │  Backend (pgproto3)                              ││
  │  - Opens raw TCP to backend database              ││
  │  - Handles SSLRequest from worker → TLS to backend││
  │  - Sends StartupMessage with brokered credentials ││
  │  - Responds to auth challenges (cleartext/MD5/SASL)││
  │  - Forwards queries from client-facing leg        ││
  ├─────────────────────────────────────────────────┤
  │──[bridge]────────────────────────────────────────│
  │  After auth on both sides:                        │
  │  client→backend: query messages forwarded          │
  │  backend→client: response messages forwarded       │
  │  Recording events emitted for each query           │
  ▼
Target Database
```

### 5.2 Auth Flow (Detailed)

```
1. Client connects to Boundary-proxied port
2. Client sends SSLRequest (Int32(8), Int32(80877103))
3. Proxy sends 'S' back to client
4. Client↔Proxy TLS handshake (Boundary-issued cert)
5. Client sends StartupMessage { user: "bob", database: "production" }
6. Proxy caches the StartupMessage (for database name), sends AuthenticationOk to client
   → Client is now "connected" as far as it knows

7. At the same time (or before accepting client auth):
   Proxy opens TCP to the backend database
8. Client sends SSLRequest → backend sends 'S'
9. Proxy↔Backend TLS handshake (backend verifies proxy's backend-cert, or skip-verify)
10. Proxy sends StartupMessage { user: "injected_user", database: "production" }
    (username/password from brokered credential)
11. Backend sends AuthenticationMD5Password (type 5) with salt
12. Proxy computes MD5 response and sends PasswordMessage
13. Backend sends AuthenticationOk

14. ReadyForQuery received from backend
15. Proxy sends ReadyForQuery to client → both sides ready
16. Query forwarding begins
```

### 5.3 Key Design Decision: Full Termination

We use **full termination** (proxy maintains independent auth to both sides) rather than **StartupMessage modification** (modify the client's StartupMessage bytes before forwarding) because:

- TLS is clean: client→proxy TLS is entirely separate from proxy→backend TLS
- SASL works: the client's SCRAM nonce and the backend's challenge are in different contexts
- The proxy doesn't need to understand every auth mechanism — it just needs to respond to the backend's challenges with the brokered credential
- Complexity is bounded: the proxy only needs pgproto3.ReadBuffer/WriteBuffer for message framing, plus auth-handling logic for cleartext/MD5/SASL

### 5.4 pgproto3/v2 Usage

The existing indirect dependency `github.com/jackc/pgproto3/v2` provides:

- `StartupMessage` — encode (for proxy→backend) and partial decode (for client→proxy database name)
- `PasswordMessage` — encode for MD5/SASL responses
- `AuthenticationXxx` types — decode all server auth challenges
- `SASLInitialResponse`, `SASLResponse`, `SASLFinal` — for SCRAM-SHA-256 exchange
- `Parse`, `Bind`, `Describe`, `Execute`, `Close`, `Query`, `ReadyForQuery`, `ErrorResponse` — all message types needed for query forwarding
- `Frontend` and `Backend` types — message stream readers/writers

**What pgproto3 does NOT handle:**
- Raw SSLRequest bytes at the TCP level (the proxy must detect Int32(8)/Int32(80877103) before wrapping in pgproto3)
- The TCP-level TLS handshake after the 'S' response
- Client-side message generation for StartupMessage (Frontend reader decodes; Backend writer encodes but you must construct the StartupMessage struct)

---

## 6. Success Criteria

### Required for MVP

1. **`boundary connect postgres` with brokered credential produces a usable psql session.** User runs `psql -h localhost -p $BOUNDARY_PORT` without a PGPASSFILE and can execute SELECT/INSERT/CREATE queries.

2. **All three auth methods are tested:**
   - Cleartext password auth (POSTGRES_AUTH_METHOD=password or `password_encryption=md5` on pre-v10 PG)
   - MD5 password auth (default on PG 9.6 and earlier)
   - SCRAM-SHA-256 password auth (default on PG 10+ with `password_encryption=scram-sha-256`)

3. **TLS works in both directions:**
   - Client→proxy TLS with Boundary CA certificate
   - Proxy→backend TLS with backend certificate verification (or skip-verify)

4. **Non-TLS (plaintext) fallback works:** If the backend does not support TLS, the proxy connects in plaintext and still authenticates.

5. **Wrong credential fails gracefully:** If the brokered credential is invalid, the connection is closed with an appropriate error message.

6. **Multiple concurrent connections work:** The handler is stateless between connections and can handle concurrent PostgreSQL sessions.

### Nice-to-Have (Post-MVP)

7. **Database name passthrough:** The database name from the client's StartupMessage is forwarded to the backend.

8. **User passthrough:** The client's intended username is logged (not used for auth, but recorded for audit).

---

## 7. Open Questions

| # | Question | Who Can Answer | Status |
|---|----------|---------------|--------|
| Q1 | How exactly will the brokered credential (UsernamePassword) reach the handler? Does the worker receive it via the `LookupSessionResponse` credentials field, via the `protocol_context` Any, or via some other mechanism? Need to trace the full path from `AuthorizeSession` → client → proxy protocol → worker. | Staff engineer (implementation-time trace) | OPEN |
| Q2 | Should the session type for a PostgreSQL target be `"tcp"` (current), `"postgres"`, or something else? If `"tcp"`, how does the worker know to select the postgres handler vs the tcp handler? | Upstream decision | OPEN |
| Q3 | Does the `GetHandler` function need to be replaced with one that inspects `SessionAuthorizationData.type` instead of always returning the TCP handler? | Follows from Q2 | OPEN |
| Q4 | For client-facing TLS, what certificate should the proxy present? A per-worker self-signed cert? A per-session cert from the worker's CA? | Staff engineer/MVP scope | OPEN |
| Q5 | Should the backend TLS certificate verification be skippable via a target attribute, or should we hardcode skip-verify for MVP? | Simplicity vs correctness trade-off | OPEN |
| Q6 | What's the SCRAM-SHA-256 implementation path? Use pgx/v5/pgconn internals to complete the SASL exchange, or implement from pgproto3 primitives? pgx already has the SASL client implementation. | Staff engineer | OPEN |
| Q7 | Is there a protocol context proto message already defined for database sessions, or do we need to add one to `worker/proxy/v1/proxy.proto`? | Codebase audit | OPEN |
| Q8 | The `connect postgres` command currently generates a PGPASSFILE and invokes psql. With credential injection on the worker side, does the client still need the password? (No — the client just needs the TCP tunnel.) Does this change the CLI behavior? | Yes — `connect postgres` should ideally skip PGPASSFILE generation when credential injection is enabled for the target. | OPEN |

---

## 8. Prior Art / References

- **Boundary DB Market Research (existing):** `/home/dan.rohan/software/boundary/DB_MARKET_RESEARCH.md` — Comprehensive report covering protocol details, competitive analysis, and implementation sequencing. PostgreSQL is Priority 1.

- **Teleport PostgreSQL Database Access:** [Teleport DB Access docs](https://goteleport.com/docs/database-access/) — Closest architectural analogue. Full protocol proxy with TLS MITM and credential injection. Teleport's implementation is in `gravitational/teleport/lib/srv/db/postgres/`.

- **pgproto3/v2 library:** `github.com/jackc/pgproto3/v2` (MIT) — Already an indirect dependency via pgx v4. Provides Frontend/Backend reader/writer types for all PostgreSQL v3 wire protocol messages.

- **Existing TCP Proxy Handler:** `internal/daemon/worker/proxy/tcp/tcp.go` — The simplest reference handler. Does `io.Copy` in both directions. The postgres handler will replace `io.Copy` with pgproto3 message-level forwarding.

- **Existing Proxy Handler Registration:** `internal/daemon/worker/proxy/proxy.go` — The `RegisterHandler` / `GetHandler` pattern. Currently always returns the TCP handler. Will need modification to dispatch to the postgres handler.

- **Credential Protobuf:** `internal/proto/controller/servers/services/v1/credential.proto` — Defines `UsernamePassword`, `SshPrivateKey`, and `SshCertificate` messages for worker-side credential usage.

- **LookupSessionResponse:** `internal/proto/controller/servers/services/v1/session_service.proto` — The `credential` field (deprecated) on this response carried earlier versions. The current path uses `SessionAuthorization.credentials` from the target API response (`internal/proto/controller/api/resources/targets/v1/target.proto`).

- **Boundary SSH Credential Injection (sibling branch):** `feature/ssh-credential-injection` — Should be reviewed for patterns once implemented, as SSH credential injection shares the same conceptual model (handler-based, protocol-aware, credential from session auth).

---

## 9. File Manifest (Proposed New/Modified Files)

### New Files

```
internal/daemon/worker/proxy/postgres/
├── postgres.go              — Handler registration (+ init), HandleProxy function scaffold
├── postgres_test.go         — Integration test with real PG container
├── auth.go                  — Auth challenge handler (cleartext, MD5, SASL/SCRAM-SHA-256)
├── auth_test.go             — Unit tests for auth response computation (MD5 hash, SASL messages)
├── tls.go                   — TLS termination + backend TLS connection helpers
├── tls_test.go              — TLS negotiation tests
├── bridge.go                — Query forwarding bridge (post-auth message forwarding)
└── session.go               — Per-connection state tracking
```

### Modified Files

```
internal/daemon/worker/proxy/proxy.go
  — Update GetHandler to dispatch to postgres handler when session type is "postgres" (or
    when protocol_context indicates postgres protocol). Must also handle the case where
    the session type is "tcp" (default fallback).

internal/cmd/commands/connect/postgres.go
  — Optionally skip PGPASSFILE generation when the target has credential injection enabled.
  — Or: generate PGPASSFILE only as fallback when no cred injection is available.
```

---

## 10. Implementation Phasing

### Phase 1: Handler Scaffold + Credential Injection (MVP)

- Create `internal/daemon/worker/proxy/postgres/` package
- Register handler via `proxy.RegisterHandler("postgres", handlePostgresProxy)`
- Implement TLS termination on the client side
- Implement backend TLS + credential auth (cleartext, MD5, SASL)
- Implement message bridge after auth
- Wire the credential from LookupSessionResponse/protocol_context into the auth handler
- Update `proxy.GetHandler` to dispatch based on session type

**Deliverable:** A user can `boundary connect postgres -target-id ttcp_123` and run `psql -h localhost -p $PORT` without additional auth setup.

### Phase 2: Query Recording Skeleton

- Add query recording hooks that emit structured JSON events for each query message
- Store recorded events (requires BSR infrastructure or custom session recording storage)

**Deliverable:** Queries are captured and stored.

### Phase 3: Prepared Statement Parameter Capture

- Track `Parse` → `Bind` → `Execute` sequences
- Reconstruct full parameterized query text with actual values
- Correlate by statement name and portal name

**Deliverable:** Prepared statement executions are logged with actual parameter values.

---

## Appendix A: PostgreSQL Wire Protocol — Quick Reference

### StartupMessage
```
Int32 length (excluding self)
Int32 protocol version (3.0 = 196608)
String "user"    String username
String "database" String dbname   (optional)
...
String ""        (terminating null byte)
```

### SSLRequest
```
Int32 8
Int32 80877103
```
Server responds with `S` (yes) or `N` (no).

### AuthenticationRequest
- Type 0: AuthenticationOk
- Type 3: AuthenticationCleartextPassword — client sends PasswordMessage
- Type 5: AuthenticationMD5Password — followed by Int32 salt (4 bytes)
- Type 10: AuthenticationSASL — followed by String array of SASL mechanisms
- Type 11: AuthenticationSASLContinue — followed by server-first SASL data
- Type 12: AuthenticationSASLFinal — followed by server-final SASL data

### PasswordMessage (for cleartext and MD5)
```
Int32 length (including self)
String password   (cleartext) or "md5" + hex(md5(hex(md5(password+user)) + salt))
```
