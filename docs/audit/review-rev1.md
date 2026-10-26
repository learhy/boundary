# Review: SSH Session Recording — Rev1 (addressing B1-B3)

**Reviewer:** Researcher
**Date:** 2026-05-30
**Document:** `/home/dan.rohan/software/boundary/docs/audit/rfc-ssh-session-recording-rev1.md`
**Original RFC:** `docs/design/ssh-session-recording.md` (598 lines)
**Previous audit:** `~/.hermes/kanban/workspaces/t_c08c8bb7/audit-ssh-session-recording-design.md`

---

## Verdict: APPROVED

All 3 blocking issues from the original audit are adequately resolved in principle. The rev1 RFC provides the right architectural decisions. I approve the approaches for B1, B2, and B3.

However, I surfaced **2 new blocking dependencies** and **3 advisories** that need to be tracked before implementation starts.

---

## B1 — BSRsession.Attempts (APPROVED with advisory)

**Proposal:** BSRsession.Attempts tracks each credential attempt. Recording begins at `auth_started`, capturing all attempts with metadata events. Final outcome is `all_credentials_exhausted` only if all attempts fail. Partial recordings are marked `incomplete`.

**Verdict:** APPROVED. This correctly handles the multi-credential case. The key insight is:
- Recording starts at `auth_started` (per-connection auth start), not at session creation
- Each failed credential attempt generates a metadata event (not a partial recording)
- Only on `all_credentials_exhausted` is the session marked as `auth_failure`
- A successful attempt mid-stream transitions to normal recording seamlessly

**Advisory A1:** The rev1 mentions "BSRsesson.Attempts" (one 's'). This looks like a typo for `BSRsession.Attempts` (the `Attempts` field on a BSR session struct). In the original design's `bsrSession` struct, there's no `Attempts` field currently. Confirm the exact struct name and field naming in the updated design RFC.

**Advisory A2:** "Metadata events" — what type of events? The BSR chunk system doesn't have a generic "metadata event" chunk type. If you're recording attempts purely at the DB level (controller-side state machine transitions), that's different from recording them as BSR file chunks. Clarify whether this is a BSR-level recording (new chunk type needed?) or controller-level DB state tracking.

---

## B2 — sshdec package (APPROVED with critical caveat)

**Proposal:** New `internal/sshdec/` package with purpose-built `Decoder` type. Parses SSH binary wire format (packet length, padding, compression, message type dispatch) and emits typed events for auth + PTY I/O. Does not implement full KEX — only the recording subset.

**Verdict:** APPROVED IN PRINCIPLE. The sshdec approach is architecturally sound for the recording use case. A purpose-built SSH wire format decoder that operates on *already-decrypted* bytes is the right approach — it's lightweight, doesn't need full KEX state machine, and only needs to understand the subset of SSH messages relevant to recording.

**BLOCKING DEPENDENCY D1 — sshdec requires decrypted content:**
This is the critical caveat from B2: the sshdec decoder receives *decrypted SSH wire bytes*. This means the SSH credential injection handler must exist FIRST and must terminate SSH at the worker (providing decrypted message bytes to sshdec). The `sshdec` package is NOT a substitute for SSH termination — it's a layer that sits *above* termination.

The SSH credential injection design rewrite (staff-eng task `t_00fbdd05`) is listed as producing a 753-line design at `docs/design/ssh-credential-injection-DESIGN.md` on `feature/ssh-credential-injection`, but **that file does not exist on disk** (checked all paths). The SSH credential injection PRD exists at `PRD_SSH_CREDENTIAL_INJECTION.md` from my previous audit.

**Implementation order must be:**
1. SSH credential injection (implements SSH termination at the worker)
2. sshdec package (parses decrypted bytes from step 1)
3. SSH session recording handler (wires steps 1+2 to BSR)

Attempting to build the recording handler before credential injection is built will result in a handler that has no way to access decrypted SSH bytes.

**Advisory A3 — Alternative approach not ruled out:**
The rev1 RFC's implicit rejection of `golang.org/x/crypto/ssh` (for server-side termination) is correct for the *recording* use case specifically. However, the SSH credential injection design might choose `golang.org/x/crypto/ssh` for its own purposes (which would be a reasonable choice — it's well-tested, handles KEX, encryption, auth). If credential injection uses `golang.org/x/crypto/ssh` to terminate the SSH connection, then sshdec would parse message bytes from that library's internals. The rev1 should acknowledge this: sshdec is valid whether credential injection uses raw crypto/ssh or golang.org/x/crypto/ssh — the key input is decrypted SSH wire bytes either way.

---

## B3 — Auth Failure State Machine (APPROVED with dependency)

**Proposal:** Explicit state machine with `auth_failed` terminal state and `SessionAuthFailureReason` enum. Worker sends `SessionAuthFailed` message to controller on auth failure; controller transitions BSR session. Partial recording discarded; artifact marked `incomplete`.

**Verdict:** APPROVED. The `auth_failed` → `session_terminated` state machine correctly handles the case where all credentials are exhausted. The `discard partial recording` behavior prevents orphan BSR files for failed auth attempts.

**BLOCKING DEPENDENCY D2 — KMS key wrapping for BSR sessions:**
The original design (B3) asked: does the OSS worker have access to a KMS wrapper for BSR key creation? The original design referenced `WorkerAuthStorageKms`. The rev1 RFC does not resolve this — it lists it as open question 3.

**I investigated the codebase and found:**
- `base.Server` (embedded in worker `Config`) already has a `BsrKms wrapping.Wrapper` field (line 88 of `servers.go`), populated via the `bsr` KMS purpose in the config.
- The BSR KMS package `kms.CreateKeys()` takes a generic `bsrWrapper wrapping.Wrapper` — any wrapper works.
- The controller already uses `c.conf.BsrKms` for its KMS setup (`controller.go:324`).
- **The worker never references `BsrKms`** — it only uses `WorkerAuthStorageKms`.

**Resolution:** The worker should use `w.conf.BsrKms` (which already exists in the config struct) as the wrapper for `bsr.NewSession`. If `BsrKms` is nil (user didn't configure a `bsr` KMS block), fall back to generating local keys without KMS wrapping using `aead.NewWrapper()` with a random AES-256 key (less secure but functional for OSS). **This is implementable today** — no new infrastructure needed.

Update the RFC to:
1. Use `w.conf.BsrKms` for key wrapping (not `WorkerAuthStorageKms`)
2. Add a fallback path for when `BsrKms` is nil
3. Remove this from open questions since it's resolvable

---

## Advisory Issues from Original Audit Still Open

The following advisories from the original audit (t_c08c8bb7) are not addressed in the rev1 and should be tracked:

| ID | Issue | Original audit ref |
|---|---|---|
| A1 | Chunk count: 20 not 18 | A1 in audit |
| A5 | Auth redaction scope table | A5 in audit |
| A6 | PRD gaps: checksums (FR4), flush timing (FR5), reconnect behavior (AT7), error isolation (NFR4) | A6 in audit |
| Protocol gap | Missing chunk types for CHANNEL_OPEN_FAILURE / CHANNEL_SUCCESS | Audit protocol coverage section |

These should be addressed in the updated design RFC when the rev1 is merged into the main design document.

---

## Summary

| Issue | Status |
|---|---|
| B1 (TRY_EACH) | APPROVED — BSRsession.Attempts is the right approach |
| B2 (SSH layering) | APPROVED in principle — sshdec is the right approach |
| B3 (auth failure lifecycle) | APPROVED — state machine is correct |
| D1 (sshdec needs decrypted bytes) | BLOCKING — SSH credential injection must exist first |
| D2 (KMS key wrapping) | RESOLVED — use w.conf.BsrKms with fallback; update RFC |

### Go/no-go for implementation

**Go if:**
1. The KMS resolution (D2) is written into the design RFC
2. The implementation sequencing acknowledges D1 (credential injection must ship first or in parallel)
3. The 5 unanswered advisories are acknowledged as tracked items (can be addressed in a follow-up)

**No-go if:**
The sshdec package or recording handler is implemented before the credential injection handler exists to provide decrypted SSH bytes — they will have nothing to decode.
