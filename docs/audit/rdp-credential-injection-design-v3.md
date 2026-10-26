# RDP Credential Injection — Design Doc v3

Extracted from staff-eng task t_55fe8e2c completion (original v3 written at /workspace/RDP_CREDENTIAL_INJECTION.md, lost to Docker GC).

## Overview

Implement RDP credential injection for Boundary sessions. Users can inject a username/password credential into RDP targets, enabling automated authentication without manual credential entry.

## Platform Support

### Linux: xfreerdp

- `defaultExec()` returns `"xfreerdp"`
- `buildArgs` passes `/u:<username> /p:<password> /v:<addr>` directly on the CLI
- LookPath check in `handleExec` before running
- Install hint printed if xfreerdp not found

### Windows: cmdkey + mstsc

- `buildArgs` runs `cmdkey.exe /generic:<addr> /user:<username> /pass:<password>` before launching `mstsc.exe /v <addr>`
- Cleanup registered: `cmdkey.exe /delete:<addr>` on session end

## Credential Validation

- Exactly 1 `UsernamePassword` credential consumed
- `ssh_private_key` and other credential types error with clear message
- 0 credentials → proceed without injection (client prompted for credentials)

## Completion

- `rdpOptions` completion set expanded to include `"xfreerdp"`

## Non-Goals

- **AD vs non-AD**: The design accepts any `UsernamePassword`. AD vs non-AD distinction is not in the target model, and injection is harmless on non-AD targets (RDP server handles validation).
- **Worker-hosted RDP**: Explicitly out of scope — the design covers CLI-with-`-exec` (user-local client) only.

## NLA Enforcement

Network Level Authentication (NLA) must be enabled on the RDP target for credential injection to work. Without NLA, credentials are not accepted before the full RDP handshake.

## Deployment Model

PAW (Privileged Access Workstation) / session-manager pattern: The Boundary client runs on the user's workstation. RDP is launched via `-exec` which spawns a local process. The credential injection happens via CLI arguments (Linux) or cmdkey (Windows).

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Credential leakage via process listing | Credentials are passed via CLI args which are visible in process listings. Mitigation: use session-scoped temp files if available, document the risk. |
| Credential persistence (Windows cmdkey) | Cleanup hook registered to delete cmdkey entries on session end. |
| Unencrypted RDP | Must enforce TLS/NLA for production use. Document as requirement. |
