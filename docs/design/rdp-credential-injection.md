# RDP Credential Injection — Design Doc

**Status:** Implementation in progress
**Target branch:** `feature/rdp-credential-injection`
**Base:** `main` (same base as `feature/postgres-credential-injection`)

---

## Summary

Implement RDP credential injection for Windows Server targets joined to Active Directory Domain Services. The Boundary worker proxies connections to RDP targets (TCP port 3389 by default) and injects brokered credentials (username + password + **domain**) so users can connect without managing secrets. The handler launches the native RDP client (mstsc.exe on Windows, xfreerdp on Linux, Microsoft Remote Desktop on macOS) with the credential pre-staged via OS-native credential stores.

This design follows the handler-registry and `RegisterHandler` dispatch pattern established by SSH and PostgreSQL credential injection.

---

## Background

### Why RDP Credential Injection

Boundary currently brokers credentials to sessions but RDP sessions forward bytes blindly — no protocol awareness, no credential injection. A user connecting to a Windows Server target must:

1. Run `boundary connect rdp -target-id tttcp_xxx`
2. Observe the session address
3. Open `mstsc.exe`, enter target address, enter credentials manually

With credential injection: Boundary handles steps 2–3. The credential (including the AD **domain**) is brokered to the worker, which pre-stages it in Windows Credential Manager (`cmdkey`) and launches `mstsc.exe` with a generated `.rdp` file pointing at the target.

### Existing Proxy Architecture

The proxy layer in `internal/daemon/worker/proxy/` has two extension points:

1. **`proxy.GetHandler`** (`proxy.go:46`) — currently `tcpOnly`, returns the TCP handler for all sessions. The `Handler` signature:

   ```go
   type Handler func(
       controlCtx context.Context,
       dataCtx context.Context,
       df DecryptFn,
       c net.Conn,            // client connection
       pd *ProxyDialer,       // endpoint dialer
       connId string,
       pb *anypb.Any,         // protocol context (from controller)
       rm RecordingManager,
   ) (ProxyConnFn, error)
   ```

2. **`proxy.GetEndpointDialer`** (`proxydialer.go:16`) — `directDialer`, creates a raw TCP `ProxyDialer` to the target endpoint.

Credentials arrive at the handler via `pd.Opts.WithInjectedApplicationCredentials` (`[]*services.Credential`), populated by the worker at session authorization time from `LookupSessionResponse.credentials`. Each credential is encrypted and decrypted using `df DecryptFn`.

### Existing Credential Data Model

The current `services.UsernamePassword` protobuf message carries:

```protobuf
message UsernamePassword {
  string username = 10; // @gotags: `class:"public"`
  string password = 20; // @gotags: `class:"secret"`
}
```

For AD-joined targets, the credential must also carry the **domain** (`CORP` or `corp.example.com`). This field is currently missing. Adding it is the primary schema change.

---

## Data Model

### 1. Service Proto — Add Domain to UsernamePassword

**File:** `internal/proto/controller/servers/services/v1/credential.proto`

Add field 30 to `UsernamePassword`:

```protobuf
// UsernamePassword is a credential containing a username and a password.
message UsernamePassword {
  // The username of the credential
  string username = 10; // @gotags: `class:"public"`

  // The password of the credential
  string password = 20; // @gotags: `class:"secret"`

  // The Active Directory domain for this credential.
  // For AD-joined targets, this is required and takes the form "DOMAIN"
  // or "corp.example.com". For local accounts, leave empty.
  // Stored as plaintext (not secret-classified) because it is
  // comparable in sensitivity to the username.
  string domain = 30; // @gotags: `class:"public"`
}
```

Regenerate: `make protos` from the repo root, or `buf generate` from `internal/proto/`.

### 2. API Resource Proto — Add Domain to UsernamePasswordAttributes

**File:** `internal/proto/controller/api/resources/credentials/v1/credential.proto`

Add field 40 to `UsernamePasswordAttributes`:

```protobuf
message UsernamePasswordAttributes {
  google.protobuf.StringValue username = 10 [...];
  google.protobuf.StringValue password = 20 [...];
  string password_hmac = 30 [...];

  // The Active Directory domain for this credential.
  // Required for RDP targets joined to AD.
  google.protobuf.StringValue domain = 40 [
    (custom_options.v1.generate_sdk_option) = true,
    (custom_options.v1.mask_mapping) = {
      this: "attributes.domain"
      that: "Domain"
    }
  ]; // @gotags: `class:"public"`
}
```

### 3. Storage Proto — Add Domain to UsernamePasswordCredential

**File:** `internal/proto/controller/storage/credential/store/v1/credential.proto`

The storage proto defines the database schema for `credential_static_username_password_credential`. Add:

```protobuf
// In the existing UsernamePasswordCredential message definition:
message UsernamePasswordCredential {
  string public_id = 1;
  // ... existing fields 2-12 ...
  string key_id = 12; // not_null

  // The Active Directory domain for this credential.
  string domain = 13; // gorm:"default:null"

  // HMAC of the domain for integrity comparison (domain is stored in plaintext).
  bytes domain_hmac = 14; // not_null
}
```

### 4. Go Interface — Add Domain() to UsernamePassword

**File:** `internal/credential/credential.go`

```go
// UsernamePassword is a credential containing a username and a password.
type UsernamePassword interface {
    Credential
    Username() string
    Password() Password
    // Domain returns the Active Directory domain for this credential.
    // For AD-joined targets: "CORP" or "corp.example.com".
    // For local accounts: "".
    Domain() string
}
```

### 5. Static Credential Struct — Add Domain Support

**File:** `internal/credential/static/usernamepassword_credential.go`

The struct wraps `*store.UsernamePasswordCredential`. The store proto (step 3) adds `Domain` and `DomainHmac` fields; the wrapper struct auto-inherits them.

`NewUsernamePasswordCredential` gains a `WithDomain` option:

```go
// NewUsernamePasswordCredential creates a new in-memory static Credential containing a
// username, password, and optional domain that is assigned to storeId.
func NewUsernamePasswordCredential(
    storeId string,
    username string,
    password credential.Password,
    opt ...Option,
) (*UsernamePasswordCredential, error) {
    opts := getOpts(opt...)
    l := &UsernamePasswordCredential{
        UsernamePasswordCredential: &store.UsernamePasswordCredential{
            StoreId:     storeId,
            Name:        opts.withName,
            Description: opts.withDescription,
            Username:    username,
            Password:    []byte(password),
            Domain:      opts.withDomain,  // NEW
        },
    }
    return l, nil
}
```

**File:** `internal/credential/static/options.go` — add `withDomain string` to `options` struct and `WithDomain(opt)` function.

**File:** `internal/credential/static/fields.go` — add `domainField = "Domain"` constant.

**File:** `internal/credential/static/usernamepassword_credential.go` — add `hmacDomain` method, call from `encrypt`:

```go
func (c *UsernamePasswordCredential) hmacDomain(ctx context.Context, cipher wrapping.Wrapper) error {
    const op = "static.(UsernamePasswordCredential).hmacDomain"
    if cipher == nil {
        return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
    }
    hm, err := crypto.HmacSha256(ctx, []byte(c.Domain), cipher, []byte(c.StoreId), nil, crypto.WithEd25519())
    if err != nil {
        return errors.Wrap(ctx, err, op)
    }
    c.DomainHmac = []byte(hm)
    return nil
}

func (c *UsernamePasswordCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
    // ... existing password encryption ...
    if err := c.hmacDomain(ctx, cipher); err != nil {  // NEW
        return errors.Wrap(ctx, err, op)
    }
    return nil
}
```

### 6. Repository — Domain in UsernamePassword Lookup

**File:** `internal/credential/static/repository_credential.go`

- `CreateUsernamePasswordCredential`: accept domain (no validation required — empty string is valid), compute `DomainHmac`, store.
- Clear `c.Domain` on return — only `DomainHmac` is returned in the DB response.
- `Lister` query: include `userpass.domain` in select columns.

---

## Handler Design

### File: `internal/daemon/worker/proxy/rdp/rdp.go`

New package `rdp` under the worker proxy package.

#### ProtocolContext Proto

**File:** `internal/proto/worker/proxy/v1/rdp.proto`

```protobuf
syntax = "proto3";

package worker.proxy.v1;

option go_package = "github.com/hashicorp/boundary/internal/proxy;";

import "controller/servers/services/v1/credential.proto";

// RdpProtocolContext is the ProtocolContext payload for RDP target connections.
message RdpProtocolContext {
  // Target address resolved from the session's endpoint.
  string target_host = 1;
  uint32 target_port = 2;  // default 3389

  // Optional: direct resolution — worker resolves target without going through
  // the worker TCP proxy (target is reachable from worker host directly).
  string resolve_host = 3;
  uint32 resolve_port = 4;

  // Session dimensions.
  uint32 width = 10;
  uint32 height = 11;
}
```

#### init() — Registration

```go
func init() {
    err := proxy.RegisterHandler(RdpHandlerName, handleRdp)
    if err != nil {
        panic(err)
    }
}

const RdpHandlerName = "rdp"
```

#### handleRdp Handler

```go
func handleRdp(
    controlCtx context.Context,
    _ context.Context,
    _ proxy.DecryptFn,
    conn net.Conn,
    pd *proxy.ProxyDialer,
    connId string,
    protocolCtx *anypb.Any,
    _ proxy.RecordingManager,
) (proxy.ProxyConnFn, error)
```

**Credential extraction** — from `pd.Opts.WithInjectedApplicationCredentials`:

```go
creds := pd.Opts.WithInjectedApplicationCredentials
var username, password, domain string
for _, cred := range creds {
    if up := cred.GetUsernamePassword(); up != nil {
        username = up.Username
        password = up.Password
        domain = up.Domain
        break
    }
}
if username == "" {
    return nil, errors.New(controlCtx, errors.InvalidParameter, op, "no username/password credential for rdp handler")
}
```

#### Platform-Specific Launch

**Windows (`runtime.GOOS == "windows"`):**

1. **Generate `.rdp` file** at `%TEMP%\boundary_rdp_{connId}.rdp`:

```
full address:s:{targetHost}:{targetPort}
username:s:{domain}\{username}
authentication level:i:2
prompt for credentials:i:0
```

When `domain` is empty (local account), use `username:s:{username}` without the domain prefix.

2. **Stage credential in Windows Credential Manager**:

```bash
cmdkey.exe /generic:TERMSRV/{targetHost} /user:{domain}\{username} /pass:{password}
```

3. **Launch `mstsc.exe`**:

```bash
mstsc.exe "{rdpFilePath}"
```

Delete the `.rdp` file immediately after launch. Return a `ProxyConnFn` that blocks until `mstsc.exe` exits.

**Linux (`runtime.GOOS == "linux"`):**

```bash
xfreerdp /v:{targetHost}:{targetPort} /u:{username} /d:{domain} /p:{password} /h:{height} /w:{width}
```

When `domain` is empty, omit `/d:{domain}`.

Check `exec.LookPath("xfreerdp")` before launching. Return clear error if binary not found.

**macOS (`runtime.GOOS == "darwin"`):**

```bash
open "rdp://user={username}&domain={domain}&password={password}&host={targetHost}&port={targetPort}"
```

#### Endpoint Resolution

1. From `protocolCtx` (`RdpProtocolContext.resolve_host/resolve_port`) — for direct worker-to-target connectivity.
2. From `pd.LastConnectionAddr()` — for connections proxied through the worker (client -> worker -> target).
3. From the session's original endpoint (from `connId` context, via the worker's session manager).

---

## Implementation Plan

### Phase 1: Proto Changes + Go Interface (independent review)

1. `internal/proto/controller/servers/services/v1/credential.proto` — add `domain` field 30 to `UsernamePassword`.
2. Run `make protos` or `buf generate` to regenerate `credential.pb.go`.
3. `internal/credential/credential.go` — add `Domain() string` to `UsernamePassword` interface.
4. `internal/proto/controller/api/resources/credentials/v1/credential.proto` — add `domain` field 40 to `UsernamePasswordAttributes`.
5. `internal/proto/controller/storage/credential/store/v1/credential.proto` — add `domain` field 13 and `domain_hmac` field 14.
6. Run `make protos` to regenerate storage proto.

### Phase 2: Static Credential Storage

7. `internal/credential/static/fields.go` — add `domainField = "Domain"`.
8. `internal/credential/static/options.go` — add `withDomain string` and `WithDomain(opt)` function.
9. `internal/credential/static/usernamepassword_credential.go`:
   - `NewUsernamePasswordCredential` uses `opts.withDomain`
   - Add `hmacDomain` method
   - `encrypt` calls `hmacDomain`
   - On create: `c.DomainHmac` is computed and stored
10. `internal/credential/static/repository_credential.go`:
    - `CreateUsernamePasswordCredential`: accept domain, compute hmac, store, clear domain on return
    - Lister query: include domain in SELECT

### Phase 3: RDP Handler

11. Create `internal/proto/worker/proxy/v1/rdp.proto` with `RdpProtocolContext`.
12. Run `make protos` to generate `rdp.pb.go`.
13. Create `internal/daemon/worker/proxy/rdp/rdp.go`:
    - `init()` registers `RdpHandlerName = "rdp"`
    - `handleRdp` implements `proxy.Handler` signature
    - Platform-specific: `launchWindows`, `launchLinux`, `launchMacOS`
    - `generateRdpFile`, `stageWindowsCredential`, `deleteRdpFile`
14. Create `internal/daemon/worker/proxy/rdp/rdp_test.go`.

### Phase 4: Handler Dispatch

15. Update `internal/daemon/worker/proxy/proxy.go` — modify `GetHandler` dispatch to handle the "rdp" protocol. This requires tracing `SessionAuthorizationData.type` and session protocol resolution in `internal/daemon/worker/handler.go` to determine the dispatch key for RDP sessions.

---

## Security Considerations

### Credential Handling

- **Password** (`class:"secret"`) is already handled via encrypted field.
- **Domain** is NOT a secret — equivalent in sensitivity to username. Stored in plaintext in DB; HMAC stored for integrity. No `class:"secret"` tag.
- **Windows**: `cmdkey.exe` stages credential in Windows Credential Manager before `mstsc.exe` launches. This is the same credential flow that AD itself uses.
- **Linux**: password appears in xfreerdp process arguments. This is inherent to FreeRDP's CLI interface. Document this in the security notes.

### Trust Boundaries

- Worker receives credentials from controller over mTLS (node enrollment).
- Credentials decrypted by worker using node enrollment key.
- RDP handler runs on worker host — credentials exposed to OS credential store and RDP client process.

### File Permissions

- Generated `.rdp` file in `%TEMP%` (Windows) — per-user directory.
- File contains credential data. **Deleted immediately after `mstsc.exe` is launched**, not on exit, to avoid leaving plaintext on disk indefinitely.
- On Linux: no temp file needed; credentials are in process arguments.

---

## Testing Strategy

### Unit Tests

1. **`internal/credential/static/usernamepassword_credential_test.go`**:
   - Test `NewUsernamePasswordCredential` with `WithDomain` — verify `c.Domain` is set.
   - Test `encrypt`/`decrypt` round-trip: domain preserved through encryption.
   - Test `hmacDomain`: same domain produces same HMAC with same key.

2. **`internal/credential/static/repository_credential_test.go`**:
   - Test `CreateUsernamePasswordCredential` with domain set.
   - Test domain is cleared from returned credential (only HMAC in DB).

3. **`internal/daemon/worker/proxy/rdp/rdp_test.go`**:
   - Test `.rdp` file generation: `full address`, `username:s:` fields.
   - Test username with domain: `DOMAIN\user` format in `.rdp` file.
   - Test username without domain: plain `username` in `.rdp` file.
   - Test credential extraction from `pd.Opts.WithInjectedApplicationCredentials`.

### Integration Tests

4. **E2E RDP test** (requires Windows worker + AD target):
   - Create static credential with domain.
   - Authorize session against Windows target.
   - Connect via `boundary connect rdp -target-id xxx`.
   - Verify `mstsc.exe` launches with correct `.rdp` file and `cmdkey` staging.

---

## Open Questions

1. **Protocol dispatch for RDP**: How does the worker determine that a session should use the RDP handler vs. TCP? The `GetHandler` function currently uses `tcpOnly`. It needs to be updated to dispatch on session protocol type. **Action:** Investigate `internal/daemon/worker/handler.go` and session authorization response.

2. **Domain field propagation through the CLI**: When a user runs `boundary connect rdp -target-id xxx`, the CLI currently does not accept a domain flag. The domain must come from the credential store. **Action:** Verify that `boundary connect rdp` reads credentials from the session authorization response.

3. **Credential count validation**: RDP sessions require exactly one credential. The handler should validate that exactly one `UsernamePassword` credential is present. **Action:** Add validation in `handleRdp`.

4. **Linux FreeRDP availability**: Not all Linux systems have `xfreerdp` installed. The handler should return a clear error if the binary is not found. **Action:** Check `exec.LookPath("xfreerdp")` before launching.

---

## References

- Existing design doc: `docs/design/postgresql-credential-injection.md`
- TCP handler pattern: `internal/daemon/worker/proxy/tcp/tcp.go`
- Service proto: `internal/proto/controller/servers/services/v1/credential.proto`
- Storage proto: `internal/proto/controller/storage/credential/store/v1/credential.proto`
- Credential interface: `internal/credential/credential.go`
- Static credential: `internal/credential/static/usernamepassword_credential.go`
- Worker proxy registry: `internal/daemon/worker/proxy/proxy.go`
- xfreerdp docs: https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface
- mstsc.exe .rdp file format: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc
- cmdkey.exe: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey