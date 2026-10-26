# PRD: MySQL Credential Injection in Boundary Worker Proxy

**Status:** Draft
**Author:** Researcher
**Branch:** feature/mysql-credential-injection
**Date:** May 2026

---

## Problem Statement

Boundary currently supports generic TCP proxying and SSH credential injection (via SSH private key / certificate injection into worker-to-endpoint connections). There is no support for MySQL database proxying with credential injection.

Enterprise MySQL deployments commonly use Boundary-managed credentials (brokered or injected via Vault or static stores) to control database access. Without protocol-aware MySQL proxying:

1. Users must pass MySQL credentials out-of-band (copy-paste, CLI args, environment variables) — breaking boundary's credential brokering value proposition.
2. Session recording for MySQL is impossible without protocol awareness — the generic TCP proxy logs bytes, not queries.
3. DBA operations done through Boundary targets lack audit trail at the query level.

This feature adds MySQL wire-protocol support to Boundary's worker proxy layer, enabling credential injection and query capture.

---

## Users and Use Cases

### 1. DBA / Operations User
- Connects to a MySQL target via `mysql --ssl-ca=boundary-ca.pem -h <boundary-proxy> -P <port>`
- Boundary worker intercepts the TCP connection, recognizes MySQL wire protocol, injects credentials (username/password from Vault or static store)
- Worker establishes TLS to the actual MySQL backend
- User is transparently authenticated; queries are logged

### 2. Application / Read-Only User
- Similar flow; credential scope is read-only (controlled by Boundary credential source configuration)
- Cannot use injected credentials to perform DDL operations

### 3. Compliance / Audit Admin
- Can view session recordings showing individual SQL queries and their parameter values
- Can prove which Boundary session executed which query on which database table

---

## Requirements

### Functional Requirements

#### R1 — MySQL Wire Protocol Recognition
The worker proxy handler MUST detect MySQL wire protocol from the initial client handshake packet. The first packet a MySQL client sends after connecting is the HandshakeResponse packet or a capability-flag packet indicating SSL request.

Detection method: Inspect the first bytes received from the client after the TCP connection is established.

- If the client sends an SSL_REQUEST packet (capability flag `CLIENT_SSL = 2048`), the proxy must negotiate TLS with the client before receiving the actual credentials.
- If the client connects without SSL, the proxy may still intercept the credentials but MUST log a warning that credentials are transmitted in cleartext.

#### R2 — MySQL Credential Injection
When a session has injected application credentials of type `username_password`, the worker MUST:

1. Intercept the MySQL protocol handshake between the client and the database.
2. Suppress the real MySQL Handshake packet from the backend.
3. Present a fake MySQL Handshake packet to the client, appearing to be the database server.
4. Receive the client's credentials (username + password, either via native MySQL auth or via the TLS path).
5. Replace the client-supplied credentials with the injected credentials from the session.
6. Forward the replaced credentials to the actual MySQL backend.
7. Complete the handshake transparently so the client is unaware of the substitution.

The proxy MUST handle both MySQL authentication paths:

- **Native MySQL password auth** (`mysql_native_password` / `caching_sha2_password`): The proxy receives the hash challenge from the backend, forwards it to the client, receives the client's hashed response, discards it, computes the correct response using injected credentials, and sends that to the backend.
- **TLS-based auth**: If the backend requires TLS, the proxy establishes TLS to the backend first, then performs the MySQL handshake over the TLS connection, substituting credentials.

#### R3 — Protocol Context from Controller
The controller MUST pass injected application credentials to the worker proxy handler via the `protocol_context` field of `AuthorizeConnectionResponse`. This requires:

- A new protobuf message `MysqlProtocolContext` (packed as `google.protobuf.Any`) containing:
  - `credentials`: The credential(s) for the worker to inject (username/password pair).
- The controller's `getProtocolContext` hook MUST be replaced for MySQL targets to pack these credentials into the response.

Current state: `getProtocolContext` defaults to `noProtocolContext` (returns nil). This must be extended to support `mysql` protocol scheme.

#### R4 — Handler Registration
A new proxy handler package `internal/daemon/worker/proxy/mysql/` MUST register itself via `proxy.RegisterHandler("mysql", handleProxy)` in its `init()`.

The handler registration pattern already exists in the TCP proxy (`tcp/tcp.go`). The MySQL handler follows the same `proxy.Handler` function signature:

```go
type Handler func(
    controlCtx context.Context,
    dataCtx context.Context,
    df DecryptFn,
    c net.Conn,
    pd *ProxyDialer,
    connId string,
    pb *anypb.Any,          // protocol_context (contains MySQL credentials)
    rm RecordingManager,
) (ProxyConnFn, error)
```

#### R5 — Routing: `GetHandler` / `GetProtocolContext`
The worker's `GetHandler` variable (currently `tcpOnly`) MUST be replaced with a function that inspects the `protocol_context` content type. If the `anypb.Any` contains a `MysqlProtocolContext`, the `mysql` handler is returned.

Similarly, the controller's `getProtocolContext` variable (currently `noProtocolContext`) MUST be extended to recognize the `mysql` endpoint scheme and return a `MysqlProtocolContext` packed in `anypb.Any`.

These are package-level variables that can be swapped by the forked code:

```go
// In internal/daemon/worker/proxy/proxy.go — current:
var GetHandler = tcpOnly

// Desired: select handler based on protocol_context content type
var GetHandler = protocolAwareHandler

// In internal/daemon/cluster/handlers/worker_service.go — current:
var getProtocolContext = noProtocolContext

// Desired: inject MySQL credentials when scheme is mysql
var getProtocolContext = protocolContextForScheme
```

#### R6 — TLS Termination
The MySQL proxy MUST handle two TLS scenarios:

- **Client-side TLS (SSL_REQUEST from client):** Terminate the TLS connection from the client (present a certificate signed by the Boundary cluster CA). The client must trust Boundary's CA.
- **Server-side TLS:** Establish a new TLS connection to the MySQL backend using the backend's certificate (standard server verification). The proxy does NOT need to present a client cert to the backend unless required by the backend's TLS configuration.
- **No-TLS both sides:** If neither side uses TLS, the proxy forwards cleartext but MUST emit a security event.

The Boundary worker already handles session-level TLS for incoming connections (the WebSocket-based proxy connection). The MySQL proxy operates inside that tunnel; the MySQL-specific TLS is inside the tunnel (second layer).

#### R7 — Query Capture (Session Recording)
The MySQL proxy MUST capture SQL queries and emit structured session recording events. Capture points:

- `COM_QUERY` (0x03): Simple query — full SQL text as null-terminated string.
- `COM_STMT_PREPARE` (0x16): Prepared statement template — SQL with `?` placeholders.
- `COM_STMT_EXECUTE` (0x17): Prepared statement execution — binary-encoded parameter values.

For session recording compliance, the proxy MUST log:
- SQL query text (with parameter values substituted for prepared statements if binary decoding is supported)
- Database name
- Username used for the connection
- Timestamp
- Error code (if any, from response)

#### R8 — Connection State Tracking
The proxy MUST track per-connection state:

- Current database (`COM_INIT_DB` / USE database statement)
- Username (from handshake)
- Connection ID (from MySQL backend)
- Sequence number (for packet framing)

---

### Non-Functional Requirements

#### NFR1 — Performance
The MySQL proxy MUST add no more than 500 microseconds of latency per round-trip in the common case (read-copy-forward). Prepared statement decoding may add up to 5ms per execution.

#### NFR2 — Security
- Injected credentials MUST never be returned to the client.
- Credential substitution MUST be auditable: each injection attempt MUST be logged as a security event.
- If credential injection fails (e.g., backend rejects the injected credentials), the connection MUST be terminated and logged.

#### NFR3 — Compatibility
- Compatible with MySQL 5.7, 8.0, and 8.4 wire protocol.
- Compatible with MariaDB 10.x+ wire protocol (same protocol; minor extensions are backward-compatible).
- Must handle both `mysql_native_password` and `caching_sha2_password` auth plugins.
- Must handle TLS connections initiated by the client (capability flag based).

#### NFR4 — Error Handling
- If the protocol context is missing or malformed, the handler MUST return an error and close the connection — do NOT fall back to TCP proxy (that would bypass credential injection).
- If the Backend Handshake cannot be parsed, the proxy must emit a structured error event, close the connection, and NOT forward any bytes to the client.

---

## Non-Goals

- **Not implementing other MySQL packet types** beyond `COM_QUERY`, `COM_STMT_PREPARE`, `COM_STMT_EXECUTE`, `COM_INIT_DB`, and the handshake/auth packets. Other commands (`COM_FIELD_LIST`, `COM_PROCEDURE`, etc.) are forwarded verbatim without logging.
- **Not capturing MySQL query result rows** — compliance frameworks require query logging, not data capture.
- **Not handling Kerberos / Windows auth for MySQL** — only native password auth and clear-text password with TLS.
- **Not implementing MySQL replication protocol** — we intercept the client-facing MySQL protocol only.
- **Not embedding a full MySQL parser** — we parse the wire protocol framing and command types, not SQL syntax.
- **Not implementing the `caching_sha2_password` full-client interaction** beyond the fast path (TLS-based exchange). The full server-side challenge-response without TLS is rare and can be deferred.
- **Not supporting MySQL's X Protocol** (port 33060) — only the classic protocol (port 3306).

---

## Open Questions

### Q1: Credential Decryption at the Worker
The `DecryptFn` parameter is passed to proxy handlers. When credentials come through the protocol context as an `anypb.Any`, they will be encrypted at the controller and decrypted at the worker. How exactly does the credential flow from:

- LookupSession (which has `GetCredentials()` returning `[]*pbs.Credential`) 
- into AuthorizeConnectionResponse's protocol_context (which is `*anypb.Any`)

The question is whether the credentials should be:
(a) Packed into the protocol_context by the controller at AuthorizeConnection time, or
(b) Retrieved from the session's `GetCredentials()` at the worker side when the handler runs.

Option (b) seems simpler since the session already has credentials accessible via `GetCredentials()`. But the handler interface receives `*anypb.Any` for protocol context, not the session object. The handler CAN access the session through the `DecryptFn` + protocol context pattern.

**Recommendation:** Use approach (a) — pack the decrypted credentials into the protocol context at the controller. This keeps the handler interface clean and avoids coupling the MySQL handler to the session manager internals. The credentials are encrypted for transit and decrypted by the worker's `credDecryptFn` before the handler receives them.

*Needs architecture decision.*

### Q2: TLS Certificate Management for MySQL Proxy
When the client sends SSL_REQUEST, the proxy needs to present a certificate to the client. Where does this certificate come from?

Options:
(a) Reuse the worker's existing session-level TLS certificate.
(b) Generate a per-session certificate signed by Boundary's internal CA.
(c) Use a self-signed cert per worker, with the client trusting the worker's CA.

The existing SSH credential injection in Boundary's worker uses SSH host keys as the mechanism, not TLS. This is unique to the MySQL proxy.

*Needs architecture decision.* Recommended approach: For MVP, use the worker's existing PKI identity (which is already used for controller-to-worker communication) to sign per-connection short-lived TLS certificates for MySQL. This keeps the trust model internal.

### Q3: Handler Selection Mechanism
How should the worker decide which handler to invoke for a MySQL target?

The current flow:
1. The controller sets `getProtocolContext` which fills `protocol_context` on `AuthorizeConnectionResponse`.
2. The worker calls `GetHandler(workerId, protocolContext)` to select a handler.
3. `GetHandler` is currently `tcpOnly` — always returns TCP handler regardless of protocol context.

For MySQL:
- The controller fills `protocol_context` with `MysqlProtocolContext`.
- The worker inspects `protocol_context` and returns the MySQL handler when it matches.

But the current `tcpOnly` function doesn't inspect the protocol context at all. We need to either:
(a) Make `GetHandler` protocol-aware by checking the type URL in the `anypb.Any`.
(b) Use a different routing mechanism (e.g., register handlers per endpoint scheme, not per protocol context type).

*Recommendation:* Go with (a) — the `GetHandler` function should unpack the `anypb.Any`, check the type URL against registered protocol types, and route to the correct handler. This is extensible for future protocols (PostgreSQL, MSSQL).

### Q4: MySQL Auth Plugin Handling
MySQL 8.0+ defaults to `caching_sha2_password`. The `mysql_native_password` plugin is deprecated but still widely used.

The `caching_sha2_password` auth flow has two paths:
1. **Fast path** (when TLS is enabled): Send password as cleartext over encrypted connection.
2. **Slow path** (no TLS): Require a full server→client challenge-response loop with RSA key exchange.

For the proxy:
- If TLS is established between proxy and client, we should prefer the fast path. The proxy can tell the client via the Handshake packet that the server supports TLS, even if the backend doesn't (the proxy terminates TLS at the proxy).
- If TLS is not used, we need to implement the full caching_sha2 exchange between proxy and backend, then transform for the client.

*Recommendation:* Only implement the fast path (TLS-based) for caching_sha2_password. If the client tries to connect without TLS, require them to upgrade. This is the industry best practice and avoids implementing RSA key exchange.

### Q5: Session Recording Event Schema
What event schema should MySQL query capture use? Does the existing BSR (Boundary Session Recording) format support structured query events, or does it only capture raw bytes?

*Needs investigation of existing BSR implementation.*

### Q6: Connection Pooling Interaction
How should the MySQL proxy handle connection pooling (e.g., ProxySQL, MySQL Router, application-side HikariCP)?

- Connection pools reuse TCP connections for many queries across multiple logical sessions.
- Each connection maps to a single Boundary session.
- Query attribution is to the Boundary session, not to individual application users behind the pool.

*Document this as a known limitation.* The MySQL proxy logs queries per connection. Application-level user attribution requires application-side logging.

---

## Success Criteria

1. **Credential injection works end-to-end:**
   - Start a Boundary target with mysql:// endpoint and injected application credentials (Vault or static).
   - Connect via `mysql -h <worker-proxy> -P <proxy-port> -u anyuser` (password ignored).
   - User is transparently authed with the injected credentials.
   - Database shows the injected username, not the one the client typed.

2. **Query capture works:**
   - Simple queries (SELECT, INSERT, UPDATE, DELETE) are captured as session recording events.
   - Prepared statements are captured (template + parameter values).
   - Database name changes are tracked (USE statements).

3. **Security boundaries hold:**
   - Injected credentials never appear in query logs or client responses.
   - If credential injection fails, the connection is terminated with a log event.
   - Cleartext connections without TLS produce a security warning.

4. **TLS negotiation works in all combinations:**
   - Client→proxy TLS + proxy→backend TLS
   - Client→proxy TLS + proxy→backend cleartext
   - Client→proxy cleartext + proxy→backend cleartext (with warning)
   - (Client→proxy cleartext + proxy→backend TLS is not a valid path — if backend requires TLS, proxy must require client TLS too)

5. **Tests pass:**
   - Unit tests for MySQL protocol packet parsing (handshake, auth, queries, prepared statements)
   - Unit tests for credential substitution logic
   - Integration test with a real MySQL backend (Docker container)
   - Test with `mysql_native_password` and `caching_sha2_password` auth plugins

---

## Prior Art / References

### Boundary Codebase
- `internal/daemon/worker/proxy/tcp/tcp.go` — existing TCP proxy handler (reference for handler registration pattern)
- `internal/daemon/worker/proxy/proxy.go` — Handler type definition, RegisterHandler, GetHandler
- `internal/daemon/worker/handler.go` — how the worker wires proxy handlers into the HTTP server
- `internal/daemon/worker/proxy/options.go` — WithInjectedApplicationCredentials option
- `internal/daemon/cluster/handlers/worker_service.go` — controller-side noProtocolContext → `getProtocolContext` to be replaced
- `internal/credential/credential.go` — credential types (UsernamePassword, etc.)
- `internal/proto/controller/servers/services/v1/credential.proto` — protobuf credential definitions

### MySQL Wire Protocol References
- MySQL Internal Manual: https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
- MySQL Client/Server Protocol: https://dev.mysql.com/doc/internals/en/client-server-protocol.html
- caching_sha2_password specification: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_caching_sha2_password.html

### Go Libraries
- `vitessio/vitess/go/mysql` (Apache 2.0) — production-grade MySQL protocol parser from Vitess. YouTube/Google-scale battle-tested. Covers: handshake, auth, COM_QUERY, COM_STMT_PREPARE, COM_STMT_EXECUTE, TLS capability negotiation.
- `github.com/golang/mock` — for mocking
- `github.com/stretchr/testify` — Boundary already uses this for tests

### PAM Vendor MySQL Support
- **Teleport:** Full MySQL protocol support (query logging, credential injection). Added second after PostgreSQL. Validates market demand.
- **CyberArk:** Agent-based MySQL session recording (PSM for Databases). No wire-protocol proxy.
- **StrongDM:** Wire-protocol MySQL proxy with session recording (closest commercial analogue).

See `DB_MARKET_RESEARCH.md` in the boundary repo for full competitive analysis.

---

## Implementation Phasing (Suggested)

### Phase 1: Protocol Parse & Handshake Intercept
- New package: `internal/daemon/worker/proxy/mysql/`
- Adopt `vitessio/vitess/go/mysql` for packet parsing
- Parse MySQL handshake from backend
- Implement fake handshake to client
- Intercept client handshake response (capture client username/password attempt)
- Discard client credentials, substitute injected credentials
- No TLS handling yet (cleartext only)
- Tests: handshake parsing, credential substitution, error cases

### Phase 2: TLS Support
- Client-side SSL_REQUEST recognition
- Terminate TLS from client
- Establish TLS to backend
- Fast-path caching_sha2_password support
- Tests: TLS/* handshake with credential substitution

### Phase 3: Query Recording
- Parse COM_QUERY, COM_STMT_PREPARE, COM_STMT_EXECUTE
- Emit structured session recording events
- Track per-connection state (database, user)
- Tests: query capture, prepared statement parameter capture

### Phase 4: Controller Integration
- Replace `getProtocolContext` to pack MySQL credentials
- Replace `GetHandler` to route to MySQL handler
- Wire through existing credential source configuration
- End-to-end integration tests

### Phase 5: Hardening
- Edge case handling (sessions that fail authentication, multiple simultaneous connections)
- Benchmarking and latency profiling
- Connection pooling documentation
- Security audit of credential flow

---

## Design Review Points for Staff Engineer

1. **Protocol dependency:** The vitess MySQL library is ~50MB+ (entire Vitess layer). Do we vendor the full library or implement a stripped-down packet parser? Recommend stripping to only what we need (handshake, auth, query commands).

2. **Handler selection architecture:** The current `GetHandler = tcpOnly` approach routes all traffic through TCP. The MySQL handler needs to intercept BEFORE the TCP handler runs. The simplest approach: make `GetHandler` check `protocol_context` type and route accordingly.

3. **Credential flow:** Will credentials be packed into protocol_context on the controller side (which means the controller must decrypt them first) or will the worker handler fetch them from the session object? The former keeps the handler interface stateless; the latter is simpler but couples the handler to session internals.

4. **TLS certificate authority:** For the proxy→client TLS termination, we need an internal CA to sign proxy certificates. Should this be the same CA used for session certificates, or a separate MySQL-specific CA? Using the same CA is simpler but means any Boundary session certificate could proxy MySQL traffic. A separate CA provides isolation but requires additional infrastructure.
