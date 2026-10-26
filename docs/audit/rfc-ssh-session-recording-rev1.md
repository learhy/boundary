# RFC: SSH Session Recording — Revision 1 (addressing B1-B3)

## Context

This RFC addresses 3 blocking issues identified in the original design audit (t_c08c8bb7):

- B1: TRY_EACH credential strategy not addressed
- B2: SSH message parsing layer underspecified
- B3: BSR session lifecycle on credential attempt failure

## B1 — TRY_EACH Credential Strategy

**Resolved:** BSRsession.Attempts tracks each credential attempt. Recording begins at `auth_started`, capturing all attempts with metadata events. Final outcome is `all_credentials_exhausted` only if all attempts fail. Partial recordings (all credentials fail) are marked `incomplete` with `auth_failure` reason.

## B2 — SSH Message Parsing Layer

**Resolved:** New `internal/sshdec/` package with purpose-built `Decoder` type. Parses SSH binary wire format (packet length, padding, compression, message type dispatch) and emits typed events for auth + PTY I/O. Does not implement full KEX or SSH state machine — only the subset needed for recording.

## B3 — BSR Session Lifecycle on Auth Failure

**Resolved:** Explicit state machine with `auth_failed` terminal state and `SessionAuthFailureReason` enum. Worker sends `SessionAuthFailed` message to controller on auth failure; controller transitions BSR session to `auth_failed → session_terminated`. Partial recording discarded; artifact marked `incomplete` if any data was captured.

## Implementation Plan

4 phases:
1. Session lifecycle (auth states, failure handling)
2. TRY_EACH tracking (BSRsession.Attempts)
3. sshdec package (SSH wire format decoder)
4. Integration wiring (worker proxy handler)

## Open Questions for Researcher

1. Does the BSRsession.Attempts approach (tracking each credential attempt, starting recording at auth_started) correctly handle the multi-credential case? Or should BSR session creation be deferred until after successful auth?
2. Is the sshdec approach (purpose-built Decoder for the recording subset only, not full KEX) acceptable, or should we use golang.org/x/crypto/ssh for server-side termination?
3. Has the B3 KMS key wrapping dependency (WorkerAuthStorageKms in OSS workers) been resolved? If not, what's the fallback plan?
