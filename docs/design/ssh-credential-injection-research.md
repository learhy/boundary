# SSH Credential Injection — Research Brief

## Overview
This brief covers the architecture and requirements for implementing SSH credential injection in a Boundary v0.13.1 fork. The worker will receive SSH credentials (username/password, SSH private keys, SSH certificates) from the controller and authenticate to SSH targets on behalf of the user.

## Protocol-Level: SSH Authentication (RFC 4252)
SSH uses an Authentication Protocol that negotiates methods between client and server. The relevant methods for credential injection:

| Method | Use Case | Boundary Credential Type |
|--------|----------|-------------------------|
| `password` | Simple username+password auth | `UsernamePassword` |
| `publickey` | Private key auth, optionally with certificate | `SshPrivateKey`, `SshCertificate` |
| `keyboard-interactive` | Challenge-response (many servers fall back to this for password) | Handled via `password` with proper channel |
| `hostbased` | Host-trust based (not relevant for user sessions) | Not applicable |

The Go `golang.org/x/crypto/ssh` package supports all of these methods out of the box via `ssh.ClientConfig.Auth` with `ssh.Password()`, `ssh.PublicKeys()`, and `ssh.KeyboardInteractive()`.

## What Already Exists in the Codebase

### Credential Types (proto + Go interfaces)
- **Proto** (`internal/proto/controller/servers/services/v1/credential.proto`): `Credential` is a `oneof` containing `UsernamePassword`, `SshPrivateKey`, and `SshCertificate`
- **Go interfaces** (`internal/credential/credential.go`): `UsernamePassword` (Username+Password), `SshPrivateKey` (Username+PrivateKey+Passphrase), `SshCertificate` (SshPrivateKey+Certificate) 
- **Credential types in stores**: Static (`internal/credential/static/`) and Vault (`internal/credential/vault/`) stores already support SSH certificate credential libraries.

### Proxy Architecture
- **Handler registration**: `proxy.RegisterHandler(protocolName, handler)` at `internal/daemon/worker/proxy/proxy.go` — extensible plugin model
- **Current handlers**: Only `"tcp"` is registered via `internal/daemon/worker/proxy/tcp/tcp.go`
- **Handler function signature**: `func(controlCtx, dataCtx, DecryptFn, net.Conn, *ProxyDialer, connId, *anypb.Any, RecordingManager) (ProxyConnFn, error)`
- **Session credentials**: `sess.GetCredentials()` returns `[]*pbs.Credential` — credentials are part of the LookupSessionResponse
- **Endpoint dialing**: `proxyHandlers.GetEndpointDialer()` returns a `ProxyDialer` that connects to the target endpoint
- **DecryptFn**: Available in the handler to decrypt credential data from the controller

### Session Lifecycle Flow (from `internal/daemon/worker/handler.go`)
1. Client connects via WebSocket with TLS client cert containing session ID
2. Websocket upgrade, tofu token validation, session activation
3. `AuthorizeConnection` RPC → gets connection ID + protocol context
4. Client ↔ Worker byte counting connection wraps the WebSocket as `net.Conn`
5. `GetEndpointDialer()` resolves target endpoint
6. `GetHandler()` resolves protocol handler via protocol context
7. Handler is called: receives decrypted credential data, client conn, endpoint dialer
8. Handler creates a `ProxyConnFn` that blocks until proxying completes
9. `ConnectConnection` RPC marks the connection established
10. `ProxyConnFn` runs — bytes flow bidirectionally
11. On completion, `CloseConnection` RPC reports byte counts

## Implementation Approach

### SSH Protocol-Aware Handler
Create a new handler registered as `"ssh"` (instead of the generic `"tcp"` handler) that:

1. Receives the `net.Conn` from the client-side WebSocket wrapper
2. Receives credentials via `DecryptFn` from the protocol context
3. **Dials the endpoint** (SSH server) via `ProxyDialer` — this gives us a raw `net.Conn` to the SSH target
4. **Wraps the endpoint connection** with `golang.org/x/crypto/ssh.Client` using the decrypted credential
5. **Wraps the client WebSocket** with `golang.org/x/crypto/ssh.ServerConfig` to present as an SSH server to the client
6. Bridges the two SSH connections by copying channels back and forth

### Alternative: Credential Injection via SSH ClientConfig
A simpler approach: use `ssh.Dial()` with the credential to create an authenticated SSH client connection to the target, then bridge raw TCP from the client through to the established SSH session. The user's Boundary client authenticates to the worker, and the worker authenticates to the target.

### Protocol Context Changes
The controller's `AuthorizeConnectionResponse` includes a `protocol_context` field (`*anypb.Any`). For SSH credential injection, this needs to carry:
- Which credential type to use (from those available in the session)
- The credential itself (encrypted)

Currently `GetProtocolContext = nilProtocolContext` — always returns nil. The controller-side code needs to populate this for SSH targets.

### Target Type Considerations
Currently targets have an `Type` field (e.g., `"tcp"`). For SSH credential injection, we need either:
- A new `"ssh"` target type, or
- A protocol attribute on existing TCP targets

### Key Implementation Challenges
1. **SSH connection multiplexing**: SSH connections carry multiple channels (shell, exec, direct-tcpip, etc.). The proxy handler must handle this multiplexing between two SSH connections.
2. **Host key verification**: The worker must verify the SSH target's host key. Currently Boundary has `GetHostKeys()` on sessions (PKCS8 host keys for worker authentication).
3. **Keyboard-interactive auth**: Many SSH servers always use keyboard-interactive even for password auth. The handler must handle both `password` and `keyboard-interactive` methods.
4. **Session channel handling**: The worker needs to handle `session` channels specially (shell, exec, subsystem, env, pty_req, window_change, signal, etc.) for proper SSH session support.
5. **Connection close semantics**: SSH has clean close semantics via SSH_MSG_DISCONNECT vs TCP-level RST.
6. **SSH extensions**: agent forwarding, X11 forwarding, TCP/IP forwarding — these add complexity.

## OSS Libraries
- `golang.org/x/crypto/ssh` — comprehensive SSH client and server implementation in Go
- Already used in the codebase for:
  - BSR SSH recording chunks
  - Credential store SSH certificate support
  - Static SSH private key credential parsing

## Next Steps
1. Design the SSH protocol handler data model (proto changes, new handler)
2. Design the controller-side changes (protocol context population, target type)
3. Implement the SSH handler in `internal/daemon/worker/proxy/ssh/`
4. Wire up credential decryption and injection
5. Add tests
