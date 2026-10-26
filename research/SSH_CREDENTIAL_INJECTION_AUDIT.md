# Design Audit: SSH Credential Injection

**Document audited:** `/home/dan.rohan/ssh_credential_injection_design_document.md`
**Reference standard:** `PRD_mysql_credential_injection.md` (same task family)
**Date:** 2026-05-29
**Auditor:** Researcher

---

## Summary Verdict: REJECTED — Design-Void

This document does not reach the standard of a design document. It is a generic template shell with placeholder content. It contains zero architectural decisions, zero protocol-specific analysis, zero integration points with the existing codebase, and zero mention of SSH wire protocol or the Boundary SSH infrastructure. It must be substantially rewritten before a staff engineer can produce an RFC against it.

---

## 1. Structural Gaps (Missing Sections)

The MySQL PRD has 11 substantive sections. This document has 6 vague ones. Missing:

| # | Section | Why it's critical |
|---|---------|-------------------|
| 1 | **Use Cases** (users and what they do) | Without this, nobody can reason about what success looks like. SSH credential injection has fundamentally different use cases than MySQL — CLI-based `boundary connect ssh` flow, Vault SSH certs, etc. |
| 2 | **Requirements (functional)** | The doc lists high-level wants ("inject SSH credentials") but no testable requirements — no packet interception spec, no credential substitution logic, no auth flow handling. |
| 3 | **Requirements (non-functional)** | No latency, security, or compatibility targets. |
| 4 | **Non-Goals** | What is explicitly out of scope (e.g., SFTP recording? SCP? X11 forwarding through the proxy?). |
| 5 | **Open Questions** | The MySQL PRD has 6 open questions (credential flow, TLS certs, handler selection, auth plugins, BSR events, connection pooling). This doc has zero. Zero open questions means zero deep thinking has happened. |
| 6 | **Success Criteria** | No end-to-end testable criteria. |
| 7 | **Implementation Phasing** | No suggested order of implementation. |
| 8 | **Prior Art / References** | No code paths referenced, no RFCs, no protocol specs. |

---

## 2. Technical Gaps

### 2.1 No Wire Protocol Analysis

SSH has a well-defined wire protocol (RFC 4251-4254) with:
- Transport layer (key exchange, encryption, MAC, compression)
- Authentication layer (publickey, password, hostbased, none, keyboard-interactive)
- Connection layer (channels, sessions, port forwarding, X11, signals)

The design doc mentions none of this. It treats "inject SSH credentials" as a single operation, when in reality there are multiple distinct injection points:

1. **Authentication-level injection** — intercept the SSH auth exchange and replace the client's auth attempt with the brokered credential (username+password or public key)
2. **Connection-level injection** — use the brokered credential to authenticate to the SSH server on the client's behalf
3. **Host-key verification** — either suppress or replace host key checking (the SSH proxy must handle the host key the client expects vs the one the actual server presents)

The MySQL PRD dedicates R2 (6 bullet points) to exactly this kind of handshake interception analysis. The SSH doc has nothing.

### 2.2 No Credential Type Analysis

SSH credentials come in multiple types that the existing Boundary codebase already models:

| Type | Proto message | Purpose |
|------|--------------|---------|
| Username/password | `UsernamePassword` | Brokered/injected |
| SSH private key | `SshPrivateKey` | Brokered/injected |
| SSH certificate | `SshCertificate` | Vault-generated, injected |
| JSON | `JsonType` | Brokered (generic) |

The design doc says "support multiple SSH credential types" but doesn't say which ones or how they're handled differently. SSH key injection is architecturally very different from password injection — keys require the worker to act as an SSH agent, hold the decrypted key in memory, and pass it during auth; passwords require the worker to intercept the auth exchange and substitute the password string.

### 2.3 No Credential Strategy Analysis

Boundary supports two credential purposes:
- `brokered` — credentials returned to the client (the user's SSH CLI uses them)
- `injected_application` — credentials used by the worker to authenticate to the endpoint

Currently, SSH operates almost entirely via **brokered** credentials. The `boundary connect ssh` CLI flow:
1. Gets brokered credentials (SSH private key file or username/password)
2. Writes the key to a temp file
3. Invokes `ssh -i <keyfile> ...` or `sshpass`

For **injected application** credentials (the goal of this feature), the worker would need to:
1. Intercept the SSH connection from the client
2. Authenticate to the SSH server using the injected credential
3. Present a proxy-verified host key to the client
4. Pipe data bidirectionally

This is architecturally similar to how MySQL credential injection works (worker sits in the TLS+auth path), but the SSH wire protocol is totally different. The doc doesn't even use the terms "brokered" or "injected_application".

### 2.4 No TRY_EACH Strategy

The task body asks to audit against "credential strategies (TRY_EACH)". Boundary's credential source configuration supports multiple credential sources per target, and the worker/TCP handler doesn't have a "try each" mechanism because it doesn't do protocol-aware credential injection at all (it's blind TCP proxying).

For SSH credential injection to support TRY_EACH (trying multiple credentials against the endpoint until one works), the design must specify:
1. How multiple credentials are packed in the protocol context
2. The try-ordering (priority order from credential sources, or round-robin)
3. Failure semantics — if credential 1 fails auth, do we close the connection or try credential 2?
4. Logging of which credential succeeded for audit trail

This is entirely absent from the design.

### 2.5 No Handler Architecture

The document suggests creating three Python files (`ssh_credential_store.py`, `ssh_credential_injector.py`, `boundary_integration.py`). This is fundamentally wrong on two levels:

1. **Boundary is written in Go**, not Python. The worker proxy handlers live in `internal/daemon/worker/proxy/` and are written in Go. Creating Python files is a non-starter.
2. **The handler must be a registered `proxy.Handler`** following the existing pattern in `tcp/tcp.go`:
   ```go
   func init() {
       proxy.RegisterHandler(proxy.TcpHandlerName, handleProxy)
   }
   func handleProxy(controlCtx, dataCtx context.Context, df proxy.DecryptFn,
       conn net.Conn, pd *proxy.ProxyDialer, connId string,
       pb *anypb.Any, rm proxy.RecordingManager) (proxy.ProxyConnFn, error)
   ```

The design should specify a new Go package like `internal/daemon/worker/proxy/ssh/` that registers an `"ssh"` handler. The MySQL PRD (R4) does exactly this for MySQL — why doesn't the SSH doc?

### 2.6 No SSH Authentication Protocol Handling

SSH supports multiple auth methods:
- `publickey` — client proves possession of a private key
- `password` — client sends password in plaintext (over encrypted channel)
- `keyboard-interactive` — challenge-response (PAM, 2FA)
- `hostbased` — host-level auth (rare)
- `none` — anonymous probe

For a credential-injecting SSH proxy, the critical design questions are:
1. Which auth methods does the proxy support?
2. For password auth: does the proxy intercept the `userauth_request` and substitute the password?
3. For publickey auth: does the proxy hold the private key and sign the auth challenge?
4. What happens if the client uses `keyboard-interactive` (which PAM may require)?
5. Does the proxy strip auth methods it doesn't support from the server's banner?

The MySQL PRD addresses MySQL auth plugins (`mysql_native_password`, `caching_sha2_password`, TLS fast path vs slow path). The SSH doc addresses none of this.

### 2.7 No Host Key Handling

SSH's security model depends on host-key verification. An SSH proxy presents a host key to the client. Design questions:
1. Does the proxy generate a per-session host key?
2. Does it use the worker's existing PKI identity to sign SSH host certificates?
3. Does it forward the actual server's host key (requiring the client's known_hosts to match the endpoint)?
4. Does it disable host key checking entirely (the current `boundary connect ssh` does `NoHostAuthenticationForLocalhost=yes`)?
5. How does the proxy verify the actual server's host key?

This is a fundamental SSH proxy design issue and is completely absent.

### 2.8 No Session Recording Analysis

The existing BSR (Boundary Session Recording) infrastructure already supports SSH. The `internal/bsr/ssh/` package registers 19 chunk types for SSH (DATA, SESS, PTYR, EXEC, SHLL, ENVR, SUBS, etc.) under protocol `"BSSH"`.

If SSH credential injection is expected to also produce session recordings:
1. Does the new SSH proxy handler use the existing BSR recording infrastructure?
2. Does it emit `BSSH` chunks (DATA, PTYR, etc.) like the existing SSH recording code?
3. Or does it need a new recording schema?
4. What is the relationship between the credential-injecting SSH proxy and the recording-only SSH proxy that exists in enterprise?

The MySQL PRD has section R7 (Query Capture) with specific capture points and an open question (Q5) about BSR schema compatibility. The SSH doc has nothing.

### 2.9 No TLS/Tunneling Analysis

SSH connections through Boundary currently work via:
1. Client connects to a local proxy port (Boundary-managed TLS tunnel)
2. Client runs `ssh user@localhost -p <proxy-port>`
3. The worker's TCP handler blindly forwards bytes to the SSH server

For credential injection:
1. The worker must distinguish SSH traffic from the TLS tunnel
2. The SSH proxy must decrypt the SSH transport layer, authenticate, then re-encrypt to the client
3. Two layers of encryption: Boundary session TLS outer + SSH transport encryption inner

None of this is addressed. The MySQL PRD has R6 (TLS Termination) with three distinct scenarios and an open question (Q2) about cert management.

### 2.10 No Controller Integration

The document says "integrate the SSH Credential Injector with the Boundary API" but gives no specifics:

1. How does the controller pass injected credentials to the worker?
2. Does the `getProtocolContext` hook (`worker_service.go`) need to be extended for SSH?
3. Does the `GetHandler` variable need to be made protocol-aware (same question asked in MySQL PRD Q3)?
4. What protobuf message defines `SshProtocolContext`?

The MySQL PRD specifies R3 (Protocol Context) and R5 (GetHandler/GetProtocolContext routing) explicitly.

---

## 3. File & Implementation Issues

### 3.1 Python Files in a Go Codebase

The design lists four Python files:
- `ssh_credential_store.py`
- `ssh_credential_injector.py`
- `boundary_integration.py`
- `boundary_api.py`

Boundary is entirely Go. The worker proxy handlers are Go packages under `internal/daemon/worker/proxy/`. Python cannot be used. This indicates the author was unaware of the codebase structure.

### 3.2 No Existing Code Reference

The MySQL PRD references 13 specific file paths in the Boundary codebase. The SSH doc references zero. A design doc must ground its proposals in the existing file structure so the staff engineer knows what to change.

---

## 4. Examples of What Should Be Specified

For comparison, here is what a minimal SSH credential injection design should specify for a single use case:

### Example: Password Auth Injection

**Goal:** User connects to an SSH target via `boundary connect ssh -target-id ttcp_123`. The worker uses an injected username+password credential to authenticate to the SSH server.

**Flow:**
1. Controller resolves the target, looks up injected application credentials, packs an `SshProtocolContext` into `AuthorizeConnectionResponse.protocol_context`.
2. Worker's `GetHandler` (now protocol-aware) inspects protocol_context, returns the `ssh` handler.
3. SSH handler starts reading bytes from the client connection.
4. Client sends TCP connection bytes → worker identifies SSH banner ("SSH-2.0-...").
5. Worker completes SSH transport layer with client (key exchange, encryption negotiation).
6. Worker completes SSH transport layer with server (key exchange, encryption negotiation).
7. Client sends `userauth_request` with "password" method for userX.
8. Worker discards client's password, sends `userauth_request` with injected username+pw to server.
9. Server returns `userauth_success` (or failure).
10. Worker translates success back to client (or closes with error).
11. Channel-level proxying proceeds (session, exec, shell, etc.).

**Requirements:**
- R1: Must support password auth method only (publickey and keyboard-interactive are non-goals for MVP).
- R2: Must forward server's host key to client with `NoHostAuthenticationForLocalhost=yes` (same as current CLI).
- R3: Must log which credential was used and whether auth succeeded.
- R4: If all injected credentials fail auth, must close the connection and emit a security event.
- R5: Must support up to 5 credentials in TRY_EACH order.

This is the level of specificity a design doc needs. The current document has zero requirements at this level.

---

## 5. Recommendations

### Minimum Required Before Staff Engineer Can Design

1. **Rewrite the document** using the MySQL PRD as the template (same task family, same expectations).
2. **Define core use cases** — at least 2: (a) SSH private key injection via `boundary connect ssh`, (b) password-based SSH auth injection.
3. **Specify auth methods** — which SSH auth methods the proxy supports (password, publickey), which are deferred.
4. **Design the protocol context** — define `SshProtocolContext` protobuf message shape (credentials list, host key policy, try_each ordering).
5. **Specify handler registration** — `internal/daemon/worker/proxy/ssh/` package, `proxy.RegisterHandler("ssh", ...)`.
6. **Address host key handling** — worker host key generation or pass-through.
7. **Specify BSR recording integration** — does the new handler use existing `internal/bsr/ssh/` chunk types?
8. **Define controller integration** — extend `getProtocolContext` and `GetHandler` for SSH.
9. **Add non-goals** — X11 forwarding, port forwarding, SCP/SFTP recording, keyboard-interactive auth.
10. **Add open questions** — at minimum: credential flow (session object vs protocol context pack), host key CA, TRY_EACH order semantics, auth method stripping.
