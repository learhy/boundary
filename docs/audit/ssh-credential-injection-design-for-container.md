# SSH Credential Injection — Design Doc

## Summary

Implement SSH credential injection in the Boundary worker so that sessions to SSH targets authenticate to the target host using injected credentials (username/password, SSH private key, SSH certificate) rather than acting as a raw TCP proxy. The worker receives encrypted credentials from the controller via `AuthorizeConnectionResponse.ProtocolContext`, decrypts them using the worker's node enrollment key, translates them into an `ssh.ClientConfig`, connects to the target SSH server, and proxies bidirectional SSH traffic. TCP targets are unaffected.

## Background

### Existing Architecture

The proxy layer in `internal/daemon/worker/proxy/` has two extension points intended for protocol-specific behavior:

1. **`proxyHandlers.GetHandler`** (`internal/daemon/worker/proxy/proxy.go:31`) — currently `tcpOnly`, returns the TCP handler for all sessions regardless of protocol context.
2. **`proxyHandlers.GetEndpointDialer`** (`internal/daemon/worker/proxy/proxydialer.go:18`) — currently `directDialer`, creates a raw TCP `ProxyDialer`.

The `AuthorizeConnectionResponse` carries `protocol_context *anypb.Any` (field 40 of `session_service.proto`) that the controller can use to deliver protocol-specific data. The worker reads this in `handler.go:286` and passes it to `GetHandler`. The current `tcpOnly` implementation ignores it.

Injected application credentials are already wired end-to-end but never consumed:
- Controller stores credentials via `AddSessionCredentials` → `session_credential` table.
- `LookupSessionResponse` includes `credentials []*services.Credential` (encrypted).
- `sess.GetCredentials()` in `internal/daemon/worker/session/session.go:264` returns them.
- `proxy.WithInjectedApplicationCredentials` and `proxy.WithPostConnectionHook` are defined in `internal/daemon/worker/proxy/options.go` but `directDialer` never passes them to the dial function.
- The worker has a `credDecryptFn` in `handler.go:331` that decrypts via `nodeenrollment.DecryptMessage`.

### Existing Credential Types

Defined in `internal/proto/controller/servers/services/v1/credential.proto`:
- `UsernamePassword`: `username` + `password`
- `SshPrivateKey`: `username` + `private_key` + optional `private_key_passphrase`
- `SshCertificate`: `username` + `private_key` + `certificate`

### Existing SSH Code

`golang.org/x/crypto/ssh` is already used in the codebase for BSR SSH recording chunks and credential store SSH certificate support. No new external dependencies are needed.

Session host keys are available via `sess.GetHostKeys()` — returns `[]crypto.Signer` from PKCS#8-encoded host key blobs in `LookupSessionResponse.Pkcs8HostKeys`.

---

## Data Model

### Proto Definition

**File:** `internal/proto/worker/proxy/v1/ssh.proto`
**Package:** `worker.proxy.v1`
**Go package:** `github.com/hashicorp/boundary/internal/proxy` (same as existing `proxy.proto` — both generate into `internal/proxy/`)

```protobuf
syntax = "proto3";

package worker.proxy.v1;

option go_package = "github.com/hashicorp/boundary/internal/proxy";

enum HostKeyCheckStrategy {
  HOST_KEY_CHECK_STRATEGY_UNSPECIFIED = 0;
  // Verify the target's host key against the session's GetHostKeys() PKCS#8 blobs.
  // Reject connection if the target's host key does not match any known key.
  HOST_KEY_CHECK_STRATEGY_KNOWN_HOST_KEYS = 1;
  // Accept any host key without verification. Use for development only.
  HOST_KEY_CHECK_STRATEGY_INSECURE_ACCEPT_ANY = 2;
}

enum CredentialStrategy {
  CREDENTIAL_STRATEGY_UNSPECIFIED = 0;
  // Try each credential in order until one succeeds.
  CREDENTIAL_STRATEGY_TRY_EACH = 1;
  // Use the first credential only; fail if it does not authenticate.
  CREDENTIAL_STRATEGY_PICK_FIRST = 2;
}

// SshProtocolContext is the ProtocolContext payload for SSH target connections.
// It is marshaled into google.protobuf.Any with type URL:
//   type.googleapis.com/worker.proxy.v1.SshProtocolContext
message SshProtocolContext {
  // Credentials to use for authentication. Decrypted by the worker before use.
  repeated github.com/hashicorp.boundary.internal.gen.controller.servers.services.Credential credentials = 1;

  // Strategy for selecting which credential to use when multiple are present.
  CredentialStrategy credential_strategy = 2;

  // Strategy for verifying the target's SSH host key.
  HostKeyCheckStrategy host_key_check_strategy = 3;
}
```

> **Note:** The `credential` field in `SshProtocolContext` carries the raw encrypted credential blobs (same `services.Credential` type used in `LookupSessionResponse`). The worker decrypts each credential using the per-connection `decryptFn` before translating to `ssh.AuthMethod`. This keeps the proto definition simple and avoids duplicating the credential message definition.

### No Database Changes

All credential data is already persisted. `ssh.proto` adds a new worker-side message only — no new tables, no schema changes.

---

## API Changes

### Controller Side: `getProtocolContext` Override

In `internal/daemon/cluster/handlers/worker_service.go`, the `getProtocolContext` global var (line 61) is currently set to `noProtocolContext`. This must be overridden for SSH targets.

**Implementation:** Create a new function `sshProtocolContext` in `internal/daemon/cluster/handlers/ssh_protocol_context.go` that:
1. Looks up the session to determine its target type (or checks endpoint scheme).
2. For SSH targets: marshals an `SshProtocolContext` into `*anypb.Any` and returns it.
3. For TCP targets: returns `nil` (falls back to `nilProtocolContext` on the worker side).

The `getProtocolContext` global is overridden in `worker_proxy_service.go` (or a new `proxy_init.go`) to point to `sshProtocolContext` when the SSH credential injection feature is enabled.

**No proto changes required on the controller** — `AuthorizeConnectionResponse.ProtocolContext *anypb.Any` already exists. The controller marshals `SshProtocolContext` into it.

#### Open Question 1 (OQ1): How does the controller identify SSH targets?

Options:
- **A)** Check `target.type` field (requires SSH target type enumeration). Adds a new target type `ssh` alongside `tcp`.
- **B)** Check the endpoint URL scheme (e.g., `ssh://host:port`). No database changes needed. The controller already knows the endpoint from the session.

**Decision needed:** Which scheme is used for SSH targets in the controller data model? The design assumes scheme-based detection (option B) — the endpoint URL scheme is `ssh` for SSH targets. Confirm this.

### Worker Side: `AuthorizeConnectionResponse` Processing

No changes to how the worker receives `AuthorizeConnectionResponse` — it already reads `acResp.GetProtocolContext()` in `handler.go:268`. The routing change in `GetHandler` below drives the protocol-specific behavior.

---

## Worker Routing

### Replace `tcpOnly` with a Type-URL Dispatcher

In `internal/daemon/worker/proxy/proxy.go`, replace:

```go
// GetHandler returns the handler registered for the provided worker and
// protocolContext. If a protocol cannot be determined or the protocol is
// not registered nil, ErrUnknownProtocol is returned.
GetHandler = tcpOnly
```

With:

```go
// GetHandler returns the handler registered for the provided protocol context.
// For nil or unrecognized type URLs, falls back to the TCP handler.
// It reads the TypeUrl from the anypb.Any message to dispatch to the correct
// handler.
GetHandler = dispatchByTypeUrl
```

The `dispatchByTypeUrl` function:

```go
func dispatchByTypeUrl(workerId string, ctx proto.Message) (Handler, error) {
    if ctx == nil {
        return tcpOnly(workerId, nil)
    }
    any, ok := ctx.(*anypb.Any)
    if !ok {
        return tcpOnly(workerId, nil)
    }
    switch any.TypeUrl {
    case "type.googleapis.com/worker.proxy.v1.SshProtocolContext":
        handler, ok := handlers.Load("ssh")
        if !ok {
            return nil, ErrUnknownProtocol
        }
        return handler.(Handler), nil
    default:
        // Unknown type URL — fall back to TCP
        return tcpOnly(workerId, nil)
    }
}
```

The existing `tcpOnly` is retained as the fallback for `nil` protocol context (TCP targets) and for unknown type URLs.

**Key decision:** Type-URL routing over extending `GetProtocolContext`. Using `*anypb.Any.TypeUrl` is the standard protobuf pattern and requires no changes to the controller's `AuthorizeConnectionResponse` proto definition.

---

## Endpoint Dialer Override

### `sshDialer` Function

In `internal/daemon/worker/proxy/proxydialer.go`, add a new override:

```go
// GetEndpointDialer returns a ProxyDialer which, when Dial() is called
// returns a net.Conn which reaches the provided endpoint.
var GetEndpointDialer = directDialer
```

For SSH targets, `GetEndpointDialer` is overridden to `sshDialer` when the feature is enabled. `sshDialer` reads the `SshProtocolContext` from the `AuthorizeConnectionResponse` to extract credentials, then creates a `ProxyDialer` that uses those credentials.

**Override location:** Same pattern as `GetHandler` — set in a new file `internal/daemon/worker/proxy/ssh/ssh_init.go` or in the worker proxy service initialization.

**Signature compatibility:** `GetEndpointDialer`'s signature is:
```go
var GetEndpointDialer func(ctx context.Context, endpoint string, workerId string, connInfo proto.Message, downstreams interface{}) (*ProxyDialer, error)
```
The `connInfo proto.Message` argument is the full `AuthorizeConnectionResponse`. The `sshDialer` narrows this to `*pbs.AuthorizeConnectionResponse`, extracts `SshProtocolContext`, and builds the dial function accordingly.

---

## SSH Protocol Handler

### New Package: `internal/daemon/worker/proxy/ssh/`

Created alongside existing `tcp/` package. Files:

```
ssh/
  ssh.go         — main handler, sshHandler type, protocol negotiation
  auth.go        — credential → ssh.AuthMethod translation
  hostkey.go     — host key verification against session host keys
  channels.go    — SSH channel multiplexing (session, direct-tcpip)
  proxy.go       — bidirectional io.Copy bridge
  ssh_init.go    — handler registration and GetEndpointDialer override
```

### `ssh.go` — Main Handler

The handler function signature (`proxy.Handler`) is:
```go
func(controlCtx, dataCtx, proxy.DecryptFn, net.Conn, *proxy.ProxyDialer, connId string, *anypb.Any, proxy.RecordingManager) (proxy.ProxyConnFn, error)
```

**Flow:**

1. **Unmarshal protocol context.** Deserialize `*anypb.Any` into `proxy.SshProtocolContext`.

2. **Decrypt credentials.** For each `Credential` in `sshCtx.GetCredentials()`, call `decryptFn(dataCtx, encryptedBytes, &services.Credential{})` to get the plaintext credential. Cache the decrypted credentials.

3. **Translate to SSH auth methods.** Call `translateCredentials(creds, strategy)` (from `auth.go`) to produce `[]ssh.AuthMethod`.

4. **Resolve endpoint.** Call `proxyDialer.Dial(dataCtx)` — the dialer has already been configured with the SSH endpoint and credentials (see Endpoint Dialer Override above). Wait for the raw TCP connection to the SSH server.

5. **Verify host key.** Call `verifyHostKey(rawConn, sshCtx.GetHostKeyCheckStrategy(), sess)` (from `hostkey.go`). For `KNOWN_HOST_KEYS`, compare against `sess.GetHostKeys()`. For `INSECURE_ACCEPT_ANY`, skip verification.

6. **Perform SSH handshake.** Use `golang.org/x/crypto/ssh`:
   - Client: `ssh.NewClient(rawConn, chans, reqs)` with the translated auth methods.
   - Server (present to the client): `ssh.ServerConfig` with no auth required (the client has already authenticated to Boundary via TLS client cert).
   - `ssh.ServerConn` wraps the `net.Conn` from the WebSocket.

7. **Wait for session channel.** The Boundary client speaks SSH to the worker. The worker must accept a `session` channel open request.

8. **Start proxying.** Call `proxySessionChannels(clientChans, serverChans)` — for the first `session` channel, do bidirectional `io.Copy`. Direct-tcpip channels are proxied through `proxyDirectTcpip`.

9. **Return `ProxyConnFn`.** The returned function blocks until both SSH directions are closed.

### `auth.go` — Credential Translation

```
translateCredentials(creds []*services.Credential, strategy CredentialStrategy) []ssh.AuthMethod
```

- `UsernamePassword` → `ssh.Password(cred.GetPassword())` + `ssh.KeyboardInteractive(username, func(...)...)` that answers with the password (handles servers that always use keyboard-interactive for passwords).
- `SshPrivateKey` → Parse the private key PEM. If passphrase is present, use `ssh.DecodePEMWithPassphrase`. Then `ssh.PublicKeys(signer)`.
- `SshCertificate` → Same as SshPrivateKey but include the certificate: `ssh.Certificates{Certificate: parsedCert}` + the private key signer.

Returns all auth methods in order. For `TRY_EACH`, the `ssh.Client` will try each auth method until one succeeds. For `PICK_FIRST`, return only the first auth method.

### `hostkey.go` — Host Key Verification

For `KNOWN_HOST_KEYS` strategy:
1. The session's host keys are `sess.GetHostKeys()` — `[]crypto.Signer`.
2. On the raw TCP connection, after the server's identification banner, read the server's `ssh.ServerConfig` negotiation to get its public key.
3. Compare the server's public key against all session host keys using `ssh.Signer` equality.
4. If no match: return an error, close the connection.

> **Implementation detail:** `golang.org/x/crypto/ssh` requires a `ssh.HostKeyCallback` at client construction time. The callback receives the server's hostname, remote IP, and the server's `ssh.PublicKey`. Compare `ssh.Marshal(pk) == ssh.Marshal(sessHostKey.Public())` for each session host key.

### `channels.go` — Channel Handling

The worker receives an SSH connection from the client and makes an SSH connection to the target. Both directions have channels:
- `session` channel: exec, shell, subsystem. The first `session` channel gets proxied. Additional channels can be rejected or proxied similarly.
- `direct-tcpip` channel: port forwarding. Proxied via separate `io.Copy` pairs.

---

## Credential Decryption and Injection Flow

1. **Controller** stores credentials (encrypted by the worker's node enrollment public key) in `session_credential` table.
2. **Controller** includes `SshProtocolContext` with credential blobs in `AuthorizeConnectionResponse.ProtocolContext` (marshaled as `*anypb.Any`).
3. **Worker** receives the response in `handler.go`. The `decryptFn` is available from `w.credDecryptFn(ctx)`.
4. **SSH handler** calls `decryptFn(dataCtx, credBlob, &services.Credential{})` for each credential.
5. **Translated auth methods** are passed to `ssh.NewClient` which attempts authentication against the target.

---

## Key Design Decisions (Made)

| Decision | Choice | Rationale |
|---|---|---|
| Protocol context routing | Type-URL dispatcher on `*anypb.Any.TypeUrl` | Standard protobuf pattern; controller proto unchanged; no ambiguity between handlers |
| SSH library | `golang.org/x/crypto/ssh` | Already in use; no external dependencies added |
| Credential strategy default | `TRY_EACH` | Resilient; handles targets that reject certain auth methods |
| Host key verification default | `KNOWN_HOST_KEYS` | Secure; uses session host keys from controller |
| Auth failure behavior | Fail on all credential failures | No brokered fallback; consistent with Boundary's session termination on error |
| Session recording (BSR) | Deferred — tracked separately in OQ6 | BSR integration requires additional design work |

---

## Open Questions

### OQ1: How does the controller identify SSH targets?

The controller's `sshProtocolContext` function needs to know whether to populate `SshProtocolContext`. Options: endpoint URL scheme (`ssh://` vs `tcp://`) or target type field. **Decision needed from product requirements or from reviewing the existing target data model.**

### OQ2: Confirm credential strategy default

`TRY_EACH` vs `PICK_FIRST`. `TRY_EACH` is more resilient — most SSH servers support multiple auth methods. `PICK_FIRST` is simpler and may be preferred for environments with single credential types. **Decision needed.**

### OQ3: Confirm host key strategy default

`KNOWN_HOST_KEYS` requires the controller to populate session host keys. If the controller does not provide them (e.g., existing sessions), the worker must handle this gracefully. Options:
- Fail if host keys are unavailable and strategy is `KNOWN_HOST_KEYS`.
- Fall back to `INSECURE_ACCEPT_ANY` only when host keys are absent.

**Decision needed from product requirements or from reviewing what `LookupSessionResponse.Pkcs8HostKeys` contains for existing sessions.**

### OQ4: Confirm failure behavior

The design assumes fail-fast on auth failure (close connection, report error). Alternative: brokered fallback (terminate worker-side session, allow client to retry with different credentials). **Decision needed.**

### OQ5: SSH target type enumeration

Should SSH targets be a distinct enumeration value alongside `tcp`, or should the distinction be based solely on endpoint scheme? **Decision affects whether proto changes are needed on the controller's target resource.**

### OQ6: Session recording (BSR) integration

SSH sessions can be recorded via the BSR SSH chunk protocol (`internal/bsr/proto/ssh/v1/`). The current design defers this to a follow-on task. **Tracked separately.**

---

## Implementation Guidance

### Phase 1: Proto and Types
1. Create `internal/proto/worker/proxy/v1/ssh.proto` with `SshProtocolContext`, `HostKeyCheckStrategy`, `CredentialStrategy`.
2. Run `make protos` (or equivalent `buf generate`) to generate `internal/proxy/proxy.pb.go`.
3. Verify generated types compile: `go build ./internal/proxy/...`.

### Phase 2: Worker Routing
1. Add `dispatchByTypeUrl` to `internal/daemon/worker/proxy/proxy.go` alongside existing `tcpOnly`.
2. Replace `GetHandler = tcpOnly` with `GetHandler = dispatchByTypeUrl`.
3. Add `ssh` handler registration in `internal/daemon/worker/proxy/ssh/ssh_init.go`:
   ```go
   func init() {
       proxy.RegisterHandler("ssh", sshHandler)
   }
   ```
4. Verify TCP targets still work: existing test suite passes.

### Phase 3: SSH Handler
1. Create `internal/daemon/worker/proxy/ssh/auth.go` — credential translation.
2. Create `internal/daemon/worker/proxy/ssh/hostkey.go` — host key verification.
3. Create `internal/daemon/worker/proxy/ssh/ssh.go` — main handler.
4. Create `internal/daemon/worker/proxy/ssh/channels.go` — channel handling.
5. Wire `sshDialer` in `ssh_init.go`:
   ```go
   proxyHandlers.GetEndpointDialer = sshDialer
   ```
   The `sshDialer` creates a `ProxyDialer` whose dial function reads `SshProtocolContext` from the `AuthorizeConnectionResponse`, decrypts credentials, and returns a raw `net.Conn` to the SSH server with the host key callback and auth methods configured.

### Phase 4: Controller Side
1. Create `internal/daemon/cluster/handlers/ssh_protocol_context.go` with `sshProtocolContext`.
2. Override `getProtocolContext` in `internal/daemon/cluster/handlers/worker_proxy_service.go` (or a new initialization file).
3. Test: Create an SSH target with injected credentials, start a session, verify auth to the target.

### Phase 5: Testing
1. Unit tests for `translateCredentials` — all credential types.
2. Unit tests for host key verification (mock session with known host keys).
3. Integration test: SSH target + injected SshPrivateKey credential + session start.
4. Regression tests: TCP targets remain unaffected.

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Credential leakage | Credentials arrive encrypted (node enrollment); worker decrypts only during session setup; plaintext never logged or stored |
| Host key spoofing | `KNOWN_HOST_KEYS` strategy verifies target against controller-provided host keys |
| Auth method enumeration | Worker does not disclose which auth methods the target supports; `TRY_EACH` is ordered by credential type preference |
| Proxy credential exposure | `ssh.ClientConfig` is constructed per-session, not retained; the dial function captures credentials only for the duration of `Dial()` |

---

## References

- **Parent PRD:** `t_a4ca096c` — SSH Credential Injection PRD
- **Research brief:** `docs/design/ssh-credential-injection-research.md`
- **Existing proxy architecture:** `internal/daemon/worker/proxy/proxy.go`, `proxydialer.go`, `options.go`
- **Worker handler:** `internal/daemon/worker/handler.go`
- **Session credentials:** `internal/daemon/worker/session/session.go:GetCredentials()`, `GetHostKeys()`
- **Controller worker service:** `internal/daemon/cluster/handlers/worker_service.go`
- **Controller credential proto:** `internal/proto/controller/servers/services/v1/credential.proto`
- **Worker proxy proto:** `internal/proto/worker/proxy/v1/proxy.proto`
- **SSH library:** `golang.org/x/crypto/ssh` (stdlib, already in use for BSR)
- **BSR SSH chunks:** `internal/bsr/proto/ssh/v1/ssh_chunks.proto`