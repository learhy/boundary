# RFC: MySQL Credential Injection — Worker Proxy Layer

**Status:** Draft
**Author:** Staff Engineer
**Date:** May 2026
**Supersedes:** N/A
**Branch:** `feature/postgres-credential-injection` (co-located with Postgres credential injection work)

---

## Summary

This RFC describes the design for adding MySQL wire-protocol support to Boundary's worker proxy layer. The feature enables two capabilities: (1) injecting Boundary-managed credentials (username/password) into MySQL connections transparently to the client, and (2) capturing SQL query events for session recording. The design follows the existing TCP handler registration pattern, introduces a new `proxy/mysql` package, and extends the controller-side `getProtocolContext` hook to deliver credentials to workers via the existing `AuthorizeConnectionResponse.protocol_context` field.

---

## Background

### Existing Architecture

Boundary's worker proxy layer (`internal/daemon/worker/proxy/`) routes connections to targets through protocol-specific handlers. Currently only one handler exists:

- `proxy/tcp/tcp.go` registers as `"tcp"` via `proxy.RegisterHandler` in `init()`. It performs straight bidirectional copy after dialing the endpoint.
- The worker selects a handler via the package-level variable `proxy.GetHandler`, which is currently set to `tcpOnly` — a function that ignores its arguments and always returns the TCP handler.
- The controller side (`internal/daemon/cluster/handlers/worker_service.go`) has `getProtocolContext = noProtocolContext`, which returns `nil, nil` for all TCP sessions.

The `AuthorizeConnectionResponse` message contains a `google.protobuf.Any protocol_context` field (line 102 of `session_service.proto`). This field is currently always `nil`. It is the intended vehicle for passing protocol-specific data from controller to worker.

### What This Feature Adds

1. A new `MysqlProtocolContext` protobuf message containing the injected username/password, packed into `anypb.Any` by the controller.
2. A new `proxy/mysql` handler that intercepts the MySQL handshake, substitutes credentials, and captures queries.
3. A protocol-aware `GetHandler` that inspects `anypb.Any.TypeUrl` to route to the correct handler.
4. A `getProtocolContext` replacement that packs credentials for MySQL targets.

---

## Open Questions — Decisions Made

### Q1: Credential Flow

**Decision: Approach (a) — pack credentials into `protocol_context` at the controller.**

Rationale: The handler interface receives `*anypb.Any` for protocol context, not the session object. Approach (a) keeps the handler stateless and interface-clean. The controller decrypts credentials via its KMS and packs them into `MysqlProtocolContext`, which is then encrypted for the worker-to-controller transport channel and decrypted by the worker's `credDecryptFn` before the handler runs. No coupling between the MySQL handler and session manager internals.

Implementation: The controller calls the session's `GetCredentials()` for `InjectedApplicationPurpose`, extracts the `UsernamePassword` credential, populates `MysqlProtocolContext`, marshals it into `anypb.Any`, and returns it in `AuthorizeConnectionResponse`.

### Q2: TLS Certificate Authority

**Decision: Reuse worker PKI identity for MVP.**

Rationale: The worker already holds a PKI identity used for controller-to-worker gRPC TLS. For the client-facing MySQL TLS termination, the worker will sign short-lived per-connection certificates using its existing identity key and certificate. The client's trust store is configured to trust the Boundary cluster CA, which signs the worker identity cert. This keeps the trust model internal and avoids introducing a new CA.

Limitation: Any Boundary worker identity cert can terminate MySQL TLS for any MySQL target. For production hardening, a separate MySQL-specific internal CA provides better isolation.

Implementation: Generate an in-memory X.509 certificate on each new client TLS connection. Populate `Subject.AlternativeName` with the target hostname. Sign with the worker's existing TLS key. Re-use the worker's existing `crypto/tls` `tls.Config` with a `GetCertificate` callback that generates this ephemeral cert.

### Q3: Handler Selection Mechanism

**Decision: Option (a) — `GetHandler` inspects `anypb.Any` type URL.**

Rationale: The type URL pattern is extensible — future protocols (PostgreSQL, MSSQL) add new message types to the same field without changing the routing logic. It centralizes protocol routing in one function rather than splitting it across registration schemes. The existing handler map already stores handlers by protocol name string; we add a parallel registry mapping type URLs to protocol names.

Implementation: Replace `tcpOnly` with `protocolAwareHandler` that checks `pb.TypeUrl` against a `typeUrlToProtocol sync.Map`. If matched, look up the handler in `handlers`. If not matched (nil context or unknown type), fall back to TCP. This preserves backward compatibility with existing TCP-only deployments.

### Q4: `caching_sha2_password` Slow Path

**Decision: Defer the non-TLS slow path.**

Rationale: The vast majority of MySQL 8.0+ clients connecting through a credential injection proxy will use TLS (enforced or at least offered). The slow path requires implementing an RSA key exchange with a full server→client challenge-response loop. Industry best practice is to require TLS for credential-injection workflows. Clients without TLS can be rejected with a clear error message.

Implementation: If the client connects without `CLIENT_SSL` capability, the proxy logs a security warning event and closes the connection with an error message indicating TLS is required for credential injection.

### Q5: BSR Event Schema for MySQL Queries

**Decision: Extend the existing BSR event format with a new `MysqlQueryEvent` variant.**

The existing BSR format uses a typed event envelope with a `EventMetadata` header (session_id, connection_id, timestamp, event_type). The MySQL proxy will emit events of type `MYSQL_QUERY` with payload:

```
MysqlQueryEvent {
  string   query           // full SQL text, or prepared statement template
  string   database        // current database at time of query (from USE or handshake)
  string   username        // authenticated username (from handshake)
  uint32   connection_id   // MySQL per-connection ID (from handshake)
  uint32   error_code      // 0 if OK
  string   error_message   // empty if OK
  repeated ParameterBinding parameters  // for COM_STMT_EXECUTE only
}
```

The existing `RecordingManager` interface in `proxy/proxy.go` is a `type RecordingManager any` — a marker type. The BSR implementation details are out of scope for this RFC, but the MySQL handler will call the appropriate recording API (to be determined in Phase 3) using the structured event above.

### Q6: Connection Pooling Interaction

**Decision: Document as a known limitation; no code change.**

When application-side connection pools (HikariCP, ProxySQL, MySQL Router) multiplex multiple logical users over a single TCP connection, each connection maps to one Boundary session. Query attribution is to the session, not to the individual application-level user behind the pool. This is documented as a known limitation in the non-goals and in the user-facing documentation. Application-level attribution requires application-side logging.

---

## Package Structure

```
internal/daemon/worker/proxy/mysql/
├── handler.go         # handleProxy — implements proxy.Handler
├── conn.go            # mysqlConn — wraps net.Conn, tracks state
├── handshake.go       # handshake interception logic
├── auth.go            # credential substitution + auth response handling
├── packet.go          # packet framing (4-byte header: length[3] + packet_num)
├── parser.go          # COM_QUERY, COM_STMT_PREPARE, COM_STMT_EXECUTE parsing
├── tls.go             # TLS termination (client-side) + TLS to backend
├── event.go           # BSR event emission
└── constants.go       # MySQL protocol constants (command types, capability flags)

internal/proto/worker/proxy/v1/
├── mysql.proto        # MysqlProtocolContext message (new file)
```

### New Proto File: `internal/proto/worker/proxy/v1/mysql.proto`

Follows the same pattern as `ssh.proto` in the SSH credential injection design.
The message is marshaled into `google.protobuf.Any` with type URL
`type.googleapis.com/worker.proxy.v1.MysqlProtocolContext`. The worker
unmarshals it using the type URL to determine the handler.

```protobuf
syntax = "proto3";

package worker.proxy.v1;

option go_package = "github.com/hashicorp/boundary/internal/proxy";

// MysqlProtocolContext is packed into google.protobuf.Any and sent to the worker
// as AuthorizeConnectionResponse.protocol_context for MySQL targets. It contains
// the credentials the worker will inject into the MySQL handshake on behalf of
// the client. It mirrors the SshProtocolContext pattern from the SSH design.
message MysqlProtocolContext {
  // username is the MySQL username to inject into the handshake.
  string username = 1;

  // password is the MySQL password to inject into the handshake.
  string password = 2;

  // default_database is the database to connect to on the target MySQL server.
  // Optional. If not set, no default database is selected.
  string default_database = 3;

  // require_ssl indicates whether to require TLS for the connection to the
  // target MySQL server. If the target does not support SSL and this is true,
  // the connection fails.
  bool require_ssl = 4;
}
```

The proto file must be added to `buf.work.yaml` in the appropriate workspace, then regenerated. The generated Go package lands at `github.com/hashicorp/boundary/internal/gen/controller/servers/services/v1`.

---

## Architecture and Data Flow

```
Client                     Worker Proxy (mysql/)                MySQL Backend
  |                              |                                  |
  |-- TCP connect -------------->|                                  |
  |                              |-- TCP connect ------------------>|
  |                              |                                  |
  |                   Phase 1: Handshake Interception              |
  |                              |                                  |
  |  (no TLS case: close conn)   |                                  |
  |<-- SSL_REQUEST? -------- ----|-- TLS handshake (client side) -->|
  |<-- TLS server hello ----------|                                  |
  |                              |                                  |
  |  (read first packet)         |                                  |
  |<-- fake Handshake v10 -------|  (intercepted from backend,      |
  |                              |   server_version / salt modified)|
  |-- HandshakeResponse41 ------->|                                  |
  |  (client creds discarded)    |                                  |
  |                              |-- HandshakeResponse41 --------->|
  |                              |  (injected creds substituted)   |
  |                              |<-- OK / Error -------------------|
  |<-- OK / Error ----------------|                                  |
  |                              |                                  |
  |                   Phase 2: Query Forwarding                    |
  |                              |                                  |
  |-- COM_QUERY -------------->| |-- COM_QUERY ------------------->|
  |  (SQL text captured)        |   (forward verbatim)              |
  |<-- Resultset ----------------|   (forward verbatim)             |
  |                              |                                  |
  |-- COM_STMT_PREPARE -------->| |-- COM_STMT_PREPARE ------------>|
  |  (template captured)        |   (forward verbatim)              |
  |<-- COM_STMT_PREPARE_OK -----|   (forward verbatim)             |
  |                              |                                  |
  |-- COM_STMT_EXECUTE -------->| |-- COM_STMT_EXECUTE ------------>|
  |  (stmt_id + params cap.)    |   (forward verbatim)              |
  |<-- Resultset ----------------|   (forward verbatim)             |
```

---

## Detailed Protocol Flow

### TLS Upgrade (Client → Proxy)

1. Client opens TCP connection to the worker proxy.
2. Worker reads the first packet. MySQL packets start with a 4-byte header: `[length:3][packet_num:1]`.
3. Worker parses the first packet as a `HandshakeResponse41` (or `SSL_REQUEST`).
4. **If `CLIENT_SSL` is set in the capability flags:** Worker begins TLS on the client connection using the ephemeral cert signed by the worker PKI identity.
5. After TLS is established, the client sends the actual `HandshakeResponse41` over the TLS connection.
6. **If `CLIENT_SSL` is not set:** Proxy logs a security event and closes the connection with error `"TLS required for credential injection"`.

### Handshake Interception

1. Worker dials the MySQL backend (cleartext or TLS depending on target config).
2. Worker reads the backend's `HandshakeV10` packet. Captures `server_version`, `connection_id`, `auth_plugin_name`, and the scramble/challenge string.
3. Worker crafts a `HandshakeResponse41` to send to the client:
   - Copy `server_version` and scramble from the real backend packet.
   - Set `server_capabilities` to advertise `CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH`.
   - Set `auth_plugin_name` to match the backend's.
4. Worker sends the fake handshake to the client.
5. Client responds with `HandshakeResponse41` containing its username and auth response (password hash).
6. **Credential substitution:** Worker discards the client's auth response. It computes the correct auth response using the injected `username` + `password` and the backend's scramble string (via the same algorithm the backend used). For `mysql_native_password`: `SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))`. For `caching_sha2_password` over TLS: use the cleartext password via `auth_fast_auth_ok` path.
7. Worker sends the computed auth response to the backend using the real connection.
8. Backend responds with `OK` (auth success) or `ERR` (auth failure).
9. Worker forwards the response to the client verbatim. If `ERR`, the proxy closes the connection.

### Query Capture

After auth, the proxy enters the forward loop:

1. Read a packet from the client.
2. Packet number `0x03` = `COM_QUERY`:
   - Parse the SQL text (null-terminated string after the command byte).
   - Emit a `MysqlQueryEvent` with `query`, current `database`, `username`, `connection_id`.
   - Forward the packet to the backend verbatim.
3. Packet number `0x16` = `COM_STMT_PREPARE`:
   - Parse the SQL template (text after command byte).
   - Emit a `MysqlQueryEvent` with `query = template`, `statement_type = "prepare"`.
   - Track `stmt_id` from the backend's `COM_STMT_PREPARE_OK` response for later correlation.
4. Packet number `0x17` = `COM_STMT_EXECUTE`:
   - Parse `stmt_id` + `flags` + `iteration_count` + `null_bitmap` + `param_type` + `param_values`.
   - Emit a `MysqlQueryEvent` with the bound parameter values included.
5. Packet number `0x02` = `COM_INIT_DB`:
   - Parse the database name.
   - Update `conn.database`.
   - Emit a `MysqlQueryEvent` with `query = "USE <db>"`, `database = <new_db>`.
6. All other packets: forward verbatim without logging.

### Connection State

The `mysqlConn` struct tracks per-connection state:

```go
type mysqlConn struct {
    net.Conn
    username       string
    database       string
    connectionId   uint32
    sequenceNumber uint8
    backendConn    net.Conn
    tlsClient      bool   // client connected with TLS
    tlsBackend     bool   // backend connection is TLS
}
```

---

## TLS Termination Design

### Client-Side (Proxy terminates TLS from client)

```go
// In tls.go
func (h *mysqlHandler) upgradeClientTLS(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
    return tls.Server(conn, cfg), nil
}
```

`cfg` is built from the worker's existing PKI identity key + cert, with a `GetCertificate` callback that generates ephemeral per-connection certs with the target hostname in SAN.

### Server-Side (Proxy establishes TLS to backend)

```go
// In tls.go
func tlsDialBackend(addr string, tlsConfig *tls.Config) (net.Conn, error) {
    return tls.Dial("tcp", addr, tlsConfig)
}
```

`tlsConfig` uses the standard MySQL server verification: `InsecureSkipVerify: false` with the MySQL server's CA in `RootCAs`.

### TLS Requirement Matrix

| Client → Proxy | Proxy → Backend | Behavior |
|---|---|---|
| TLS | TLS | Full security. Preferred. |
| TLS | Cleartext | Proxy→backend is internal network only. Logged as a warning. |
| Cleartext | Cleartext | Rejected — credentials in cleartext. Proxy closes connection with security error. |
| Cleartext | TLS | Invalid — if backend requires TLS, client must also use TLS. |

---

## BSR Event Schema

Each MySQL event is emitted as a BSR `Event` with:

```
EventType: MYSQL_QUERY
SessionId: <Boundary session ID>
ConnectionId: <Boundary connection ID>
Timestamp: <wall clock at time of capture>
Payload (MysqlQueryEvent):
  - query:          SQL text or prepared statement template
  - database:       current database
  - username:       authenticated MySQL user
  - connection_id:  MySQL per-connection ID (from handshake)
  - error_code:     MySQL error code (0 = success)
  - error_message:  MySQL error message (empty if success)
  - statement_type: "query" | "prepare" | "execute" | "use"
  - parameters:     []byte (binary-encoded params from COM_STMT_EXECUTE)
```

Events are emitted to the `RecordingManager` asynchronously (non-blocking write to avoid adding latency to the forward path). If the recording channel blocks, the proxy continues forwarding — recording failures do not interrupt the session.

---

## Implementation Phasing

### Phase 1: Protocol Parsing + Handshake Interception (No TLS)

Files: `constants.go`, `packet.go`, `handshake.go`, `auth.go`, `handler.go`

- Register `proxy.RegisterHandler("mysql", handleProxy)` in `init()`.
- Implement `mysqlConn` state tracking.
- Read backend `HandshakeV10`, craft fake `HandshakeResponse41` for client.
- On receiving client `HandshakeResponse41`, substitute injected `username`/`password`.
- Compute auth response using injected credentials + backend scramble.
- Handle both `mysql_native_password` (SHA1 XOR) and `caching_sha2_password` fast path (cleartext over in-memory TLS).
- No TLS yet — cleartext only. Reject non-TLS clients with security error.
- **Tests:** Handshake parsing unit tests, credential substitution unit tests, end-to-end Docker test with `mysql_native_password`.

### Phase 2: TLS Support

Files: `tls.go` (additions), `auth.go` (update)

- Implement client-side TLS termination (ephemeral cert from worker PKI).
- Implement backend-side TLS establishment.
- Support both client-TLS and client-cleartext paths per the requirement matrix.
- **Tests:** TLS handshake integration tests against MySQL 8.0 with `caching_sha2_password`.

### Phase 3: Query Recording

Files: `parser.go`, `event.go`

- Parse `COM_QUERY`, `COM_STMT_PREPARE`, `COM_STMT_EXECUTE`, `COM_INIT_DB`.
- Emit structured `MysqlQueryEvent` BSR events.
- Track database changes.
- **Tests:** Query capture unit tests, integration tests verifying events appear in session recording.

### Phase 4: Controller Integration

Files: `internal/proto/controller/servers/services/v1/mysql.proto` (new)
Files: `internal/daemon/cluster/handlers/worker_service.go` (update)
Files: `internal/daemon/worker/proxy/proxy.go` (update)

- Define `MysqlProtocolContext` proto, regenerate.
- Replace `getProtocolContext = noProtocolContext` with a function that checks `endpointScheme == "mysql"` and returns a packed `MysqlProtocolContext`.
- Replace `GetHandler = tcpOnly` with `protocolAwareHandler` that inspects `anypb.Any.TypeUrl`.
- Wire through `WithInjectedApplicationCredentials` from the existing options.
- **Tests:** Controller unit tests, end-to-end integration tests with Vault credential broker.

### Phase 5: Hardening

- Edge cases: failed auth, backend disconnects mid-handshake, malformed packets.
- Benchmarking: profile handshake latency to stay under 500µs target.
- Security audit: verify injected credentials never appear in logs or responses.
- Connection pooling documentation.

---

## Testing Strategy

### Unit Tests (`proxy/mysql/*_test.go`)

- **Packet framing:** Test parsing of valid and malformed MySQL packet headers.
- **Handshake parsing:** Test extraction of `server_version`, `connection_id`, scramble, auth plugin name from `HandshakeV10`.
- **Credential substitution:** Test correct auth response computation for both `mysql_native_password` and `caching_sha2_password`.
- **COM_QUERY parsing:** Test SQL text extraction, statement type classification.
- **COM_STMT_PREPARE/EXECUTE parsing:** Test template extraction, parameter binding decoding.
- **TLS rejection:** Test that non-TLS clients are correctly rejected with the right error.

### Integration Tests (Docker-based)

Use `testcontainers-go` or a Docker-compose setup with:
- MySQL 8.0 (default `caching_sha2_password`).
- MySQL 5.7 (`mysql_native_password`).
- A Boundary worker + controller (or a mock controller that sends the right `AuthorizeConnectionResponse`).

Test cases:
1. Client connects with TLS → credentials injected → query captured → correct results returned.
2. Client connects without TLS → connection rejected with security error.
3. `COM_STMT_PREPARE` + `COM_STMT_EXECUTE` round-trip → both events captured.
4. Auth failure from backend → proxy closes connection → error event logged.

---

## Security Considerations

1. **Credential injection audit:** Every credential substitution logs a security event with: timestamp, session_id, connection_id, injected_username (never the password), success/failure.
2. **Cleartext credential rejection:** Connections without TLS from the client are rejected. The proxy never forwards the client's actual credentials — it always discards them.
3. **Injected credentials never in logs:** The injected password never appears in any log output or BSR event. Only the username is included in query events.
4. **TLS trust model:** Clients must trust the Boundary cluster CA. Workers present certs signed by their identity, which is signed by the cluster CA.
5. **Backend credential failure:** If the backend rejects the injected credentials, the proxy sends an `ERR` packet to the client and closes the connection. The client sees a generic auth failure — it does not learn whether the problem was the injected creds or the backend.
6. **Packet injection prevention:** The proxy only modifies auth-response packets during the handshake phase. All subsequent packets pass through unmodified. This limits the attack surface.

---

## Alternatives Considered

### Custom Packet Parser vs. vitess

A stripped-down custom parser was considered to avoid the vitess dependency. However, vitess's `vitess.io/vitess/go/mysql` package provides:
- Correct handshake packet parsing (version-aware, capability flag handling).
- Auth plugin implementations (`mysql_native_password`, `caching_sha2_password` fast path).
- Prepared statement framing.

Vendor only the specific files needed (`handshake.go`, `auth.go`, `constants.go` from vitess) rather than the full ~50MB library. This is the same approach HashiCorp uses for other Go dependencies — selective vendoring of well-tested code.

### Option (b) for Q1 — Fetch from session at worker

This would require the handler to hold a reference to the session manager and call `GetCredentials()` inside `handleProxy`. This couples the MySQL handler to session internals and makes the handler non-reentrant (it would need a session lookup per connection). Option (a) is cleaner.

### Option (b) for Q3 — Register per endpoint scheme

Registering handlers per endpoint scheme requires the worker to map `scheme` → handler before receiving `protocol_context` from the controller. The current call site in `handler.go` gets the handler **after** receiving `AuthorizeConnectionResponse` (which contains `protocol_context`). Option (a) fits the existing flow better.

---

## Open Questions for Researcher Review

1. **BSR recording API:** The `RecordingManager` is a `type RecordingManager any` marker. Is there an existing BSR event emission API the MySQL handler should call? Or does this need to be designed in Phase 3?
2. **MySQL target registration:** How does a target indicate it speaks MySQL? Is there an `endpoint_scheme` field on the target, or does the worker infer it from the port? This affects how `getProtocolContext` decides when to return `MysqlProtocolContext`.
3. **ProxyDialer TLS config:** The `ProxyDialer` is constructed in `handler.go` before the handler runs. Does the existing `ProxyDialer` support TLS to the backend, or does the MySQL handler need to re-dial with TLS?

---

## References

- MySQL Client/Server Protocol: https://dev.mysql.com/doc/internals/en/client-server-protocol.html
- `caching_sha2_password` fast path: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_caching_sha2_password.html
- `internal/daemon/worker/proxy/proxy.go` — Handler type, RegisterHandler, GetHandler (lines 1–66)
- `internal/daemon/worker/proxy/tcp/tcp.go` — reference handler implementation (lines 1–62)
- `internal/daemon/cluster/handlers/worker_service.go` — getProtocolContext, noProtocolContext (lines 46–65, 384–396, 584–657)
- `internal/daemon/worker/proxy/options.go` — WithInjectedApplicationCredentials (lines 1–53)
- `internal/proto/controller/servers/services/v1/session_service.proto` — AuthorizeConnectionResponse.protocol_context (line 102)
- `internal/credential/credential.go` — UsernamePassword type, InjectedApplicationPurpose (lines 1–156)
- vitess: `vitess.io/vitess/go/mysql` — production-grade MySQL protocol parser (Apache 2.0)