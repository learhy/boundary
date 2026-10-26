# Design Audit: PostgreSQL Session Recording

## Audit Summary

Auditing the design doc at `docs/design/postgresql-session-recording.md` against the PRD at `PRD-postgres-session-recording.md` (and the earlier research at `t_5dde9a0d`).

**Verdict: Needs changes before design-verified.** 1 blocking issue, 3 significant gaps, and 6 recommendations.

---

## 1. MISMATCH: Protocol Identifier

**Blocking — must resolve before implementation.**

| Document | Protocol |
|----------|----------|
| PRD (§5.1) | `"BPG4"` (Boundary PG v4) |
| Design Doc (§Chunk Protocol) | `"PGSQ"` |

These are different strings. Either pick one and document the choice, or accept that both documents are out of sync. The 4-char limit is satisfied by both, but they must be consistent.

**Recommendation:** Use `"PGSQ"` (shorter, self-documenting as "PostgreSQL query recording"). "BPG4" encodes versioning that may not be meaningful — if the protocol format changes, the chunk type IDs change with it, not the protocol prefix. Confirm with staff engineer.

---

## 2. MISMATCH: Chunk Type IDs

Several chunk types differ between the two documents:

| Chunk | PRD ID | Design Doc ID | Issue |
|-------|--------|---------------|-------|
| Query | `"QUER"` | `"QRY"` | Different |
| Exec | N/A | `"EXEC"` | Conflicts with SSH `"EXEC"` (ExecRequest). BSR `RegisterChunkType` is keyed by `(Protocol, ChunkType)` so collision is within `PGSQ`/`BPG4` namespace only — still confusing for tooling that searches by type ID. |
| Bind | `"BIND"` | `"BIND"` (but w/ different pillar layout) | Same ID, different proto message shapes |
| Close | `"CLOS"` | Not in design doc | Missing from design doc |
| Cancel | `"CANC"` | Not in design doc | Missing from design doc |
| Copy | `"COPY"` | Not in design doc | Missing from design doc (PRD F8 requires CopyIn/CopyOut metadata) |
| Notice | `"NOTC"` | Not in design doc | Missing from design doc |
| Terminate | `"TERM"` | `"DONE"` | Different |

**Design doc omits:** CloseChunk, CancelChunk, CopyChunk, NoticeChunk, and the dedicated TerminateChunk (uses "DONE" instead). The PRD explicitly requires these (F8, F9).

**Counter-argument for design doc's approach:** Design doc uses `"DONE"` for session end and `"DATA"` for fallback, which mirrors SSH's own convention (`"DONE"` for session end marker). But SSH doesn't have a Terminate message type — it uses `"DONE"` for both the end-of-stream *chunk* (`ChunkEnd`) and session termination. For PostgreSQL, a `Terminate` is a specific protocol message distinct from a connection close. PRD's `"TERM"` is cleaner.

**Recommendation:** Merge the two tables. Keep PRD's dedicated Cancel/Copy/Close/Notice/Terminate types. Add them to the design doc's chunk table. Only keep "DONE" as the connection-level `ChunkEnd` marker (not a data chunk).

---

## 3. GAP: QueryChunk Protobuf Shape

The PRD defines `QueryChunk` with fields: `sql_text`, `statement_name`, `portal_name`, `is_simple_query`. The design doc defines `QueryChunk` with: `query`, `database`, `is_simple`. These have different field semantics:

- **PRD** includes `statement_name` and `portal_name` for cross-referencing prepared statements. This is critical — without `statement_name`, a BindChunk references a Parse that may have different SQL, and playback tools can't link them.
- **Design doc** includes `database` inline. The PRD does not. The PRD's position (and SSH's convention) is that database name is in session/connection metadata, not each chunk.

**Recommendation:** Follow the PRD. Omit `database` from chunk protos (use metadata-only). Include `statement_name` and `portal_name` on QueryChunk for correlation.

---

## 4. GAP: BindChunk Protobuf Shape

**PRD BindChunk** includes `sql_text` as a convenience field (denormalized). This is a design decision worth noting — it means every BindChunk duplicates the SQL template from the corresponding Parse, making chunks self-describing but slightly larger.

**Design doc BindChunk** includes `param_types` (OIDs), `database`, and `param_values` as `repeated bytes`. 

**Recommendation:** The PRD's approach of `repeated string parameters` (human-readable decoded values) is superior for compliance use cases. The design doc's `repeated bytes` preserves fidelity but requires downstream binary-to-string conversion. For audit and compliance, strings win. Keep the denormalized `sql_text` as well — the overhead is negligible per-chunk and it dramatically simplifies playback tools. Clarify in the design doc: parameter values are decoded using `pgtype` OID resolution (already in the PRD as a dependency).

---

## 5. GAP: TRY_EACH / Credential Strategy

The task asks to review "credential strategies (TRY_EACH)". Neither the PRD nor the design doc mentions `TRY_EACH` credential strategy or multiple-injection handling.

The existing Boundary credential injection code has a `credential_strategy` concept (from `InternalCredentialStore`):
- `credential_strategy = 1` (single credential): Pick the first credential, inject it.
- `credential_strategy = 2` (TRY_EACH): Try each credential in order until one succeeds against the database.

This is relevant because:
1. If a user has multiple credential sources configured for a PostgreSQL target, the proxy needs to handle TRY_EACH — try cred1, if auth fails against postgres, fall back to cred2, etc.
2. The design doc assumes a single credential with no fallback path.
3. The `startupParams` map after credential injection may need to be rewritten if the username changes between TRY_EACH attempts.

**Recommendation:** Add a section to the design doc on credential strategy handling. For TRY_EACH:
- Perform auth as part of the proxy handler (not a separate phase) so the handler can retry with different credentials if the first attempt fails.
- Only enter "recording mode" after the credential strategy is exhausted and auth succeeds.
- If all TRY_EACH attempts fail, write an error chunk and close the connection — don't record a partial session.

---

## 6. GAP: GetHandler / GetProtocolContext Wiring

**Critical finding:** The design doc says `GetHandler` (proxy.go) dispatches to handlers by `*anypb.Any.TypeUrl`, but the current `GetHandler` is `tcpOnly()` — it ignores the protocol type and always returns the TCP handler. The design doc assumes `PostgresProtocolContext` exists and can be routed to.

In this OSS fork:
- `GetHandler = tcpOnly` (hardcoded, line 31 of proxy.go)
- `GetProtocolContext = nilProtocolContext` (line 37 of handler.go)
- `PostgresProtocolContext` protobuf message does not exist
- No credential injection handler exists for postgres

**Impact:** The design doc's Phase 2 and Phase 3 are premature. The credential injection handler (the prerequisite) does not exist in this codebase. The design doc correctly states "Depends on: feature/postgres-credential-injection" but doesn't account for the OSS status — there is no `PostgresProtocolContext` proto, no handler dispatch for postgres, and no TLS termination logic.

**Recommendation:** Either:
   A. Remove the "design doc" framing from this document and convert it to an implementation spec that explicitly calls out the prerequisite work first. Mark every section that depends on credential injection as "DOES NOT EXIST — must be built first".
   B. Or write a companion "prerequisite" document that defines PostgresProtocolContext, replaces GetHandler, and implements credential injection.

---

## 7. GAP: RecordingManager — OSS nil Factory

The design doc opens OQ2 and OQ3 asking about RecordingManager type. The answer is: `recorderManager` (the local interface in `worker.go`) will be `nil` in the OSS fork because `recorderManagerFactory` is never assigned.

From `worker.go:128`: `recorderManager recorderManager` is a nil interface.
From `handler.go:297`: `w.recorderManager` is passed as `proxy.RecordingManager` (which is `any`). It will be `nil`.

The design doc's Phase 2 (RecordingManager Wiring) and its fallback behavior ("If rm is nil -> fall back to plain message forward") is correct for an enterprise build, but **doesn't address the OSS case**: in OSS, recording is impossible because the recorder system doesn't exist. The doc should clarify:
- OSS: recording is a no-op (`rm` is always nil, pass-through only).
- Enterprise: `rm` is a concrete type from the enterprise recorder package — but the design doc can't spec it for this fork.

**Recommendation:** Add a note that this design is for an enterprise-only feature path. The OSS fork will get the handler with credential injection but recording will always be pass-through until the enterprise recorder infrastructure is added.

---

## 8. GAP: CopyIn/CopyOut — Missing from Design Doc

PRD requirement F8: "Proxy must capture CopyIn/CopyOut operations with metadata (log table name, operation type; do NOT log data rows)."

The design doc's chunk table has no Copy chunk. The proto definitions don't include CopyChunk or CopyData handling. `pgproto3.CopyData`, `pgproto3.CopyDone`, `pgproto3.CopyInResponse`, `pgproto3.CopyOutResponse` are not mentioned in the capture point table.

**Recommendation:** Add a `COPY` chunk type (matching the PRD), and handle CopyInResponse/CopyOutResponse to capture table metadata. Explicitly log metadata only (not data rows, per PRD F8). This is P1 per the PRD but omitting it from the design means the implementer won't know to handle it.

---

## 9. GAP: pg_stat_statements / LISTEN/NOTIFY — Not Mentioned

PRD open questions Q11 (pg_stat_statements) and Q12 (LISTEN/NOTIFY) are not discussed in the design doc. These are lower priority but should be acknowledged.

**Recommendation:** Add a "non-chunked messages" section listing messages that intentionally produce no chunk (Like `Describe`, `Flush`, `FunctionCall` — and explicitly LISTEN, NOTIFY, CopyData). This prevents future ambiguity.

---

## 10. MISMATCH: BSR Direction Naming

| Document | Client→Server | Server→Client |
|----------|--------------|---------------|
| PRD (fig, §7.3) | `messages-inbound.data` | `messages-outbound.data` |
| Design Doc (§Container Hierarchy) | `messages-up.data` | `messages-down.data` |

The actual BSR convention uses `up` / `down` (see `bsr.Direction` enum in `internal/bsr/bsr.go`). The PRD's `inbound/outbound` is user-friendly but doesn't match the existing code. The design doc gets this right with `up`/`down`.

**Recommendation:** The design doc is correct here. Update the PRD to match.

---

## 11. RECOMMENDATION: No Channels — Design Doc is Correct

The design doc correctly states PostgreSQL doesn't use channel containers. Each TCP connection = one `bsr.Connection`. The PRD confirms this (Q3). No issue.

---

## 12. RECOMMENDATION: Auth Transparency

Design doc section 6.7 (auth message forwarding) says the proxy forwards auth messages transparently. This is true for the "recording" phase but **not** for the credential injection prerequisite — the inspector must either:
- Intercept and substitute credentials (requiring full auth parsing), or
- Do the auth itself by directly authenticating to the backend.

The PRD correctly calls out that credential injection requires active participation in auth (not transparent forwarding). The design doc should include a note that during the prerequisite phase, auth is NOT transparent — it's intercepted. Only AFTER credential injection succeeds does the bridge become transparent.

---

## 13. RECOMMENDATION: TLS Certificate Handling

Neither document fully resolves the TLS cert provisioning question (PRD Q2). The design doc's self-signed CA approach is pragmatic for POC but has real implications:

- `PGSSLROOTCERT` must be distributed to every psql client
- For application connections (not psql), this requires adding the Boundary CA to the trust store
- No mention of cert rotation or CA key management

**Recommendation:** This is acceptable for a design doc — mark it as a pre-implementation decision point. Add a reference to the Vault PKI integration as the production path.

---

## 14. RECOMMENDATION: Recording Failure Behavior

PRD NF5: "Graceful degradation when recording storage is unavailable — Connection proceeds without recording; error is logged."

Design doc §Alternatives/OQ5 raises this but describes current SSH behavior as "if recording fails, the session terminates" — which contradicts NF5.

**Recommendation:** Resolve this contradiction. NF5 says continue; current SSH behavior says terminate. The design doc should pick one and document the decision. Given NF5 is a non-functional requirement, the design should match. However, this creates a compliance problem: if recording is mandatory for audit, silently proceeding without it defeats the purpose. The actual behavior should be configurable: `recording_mode = required | optional`.

---

## 15. RECOMMENDATION: Sensitive Parameter Redaction

PRD mentions (Q4) that `BindChunk` stores decoded parameter values. The design doc acknowledges this as OQ5 (OQ4 in the design doc's numbering). Neither resolves it.

**Recommendation:** Add a redaction section to the design doc. At minimum: exclude columns named `password`, `secret`, `token`, `key` from BindChunk. Store a redacted marker `"***"` instead. This mitigates the compliance risk of recording PII in query parameters.

---

## Summary Table

| # | Severity | Issue | Document | Status |
|---|----------|-------|----------|--------|
| 1 | **BLOCKING** | Protocol ID mismatch: "BPG4" vs "PGSQ" | Both | Must pick one |
| 2 | **HIGH** | Chunk type IDs mismatch across 7+ types | Both | Must reconcile |
| 3 | **HIGH** | QueryChunk/BindChunk proto field mismatch | Both | Must reconcile |
| 4 | **HIGH** | TRY_EACH credential strategy not addressed | Neither | Must add |
| 5 | **HIGH** | GetHandler= tcpOnly; PostgresProtocolContext doesn't exist | Design Doc | Prerequisite gap |
| 6 | **HIGH** | RecordingManager is nil in OSS; recording not possible here | Design Doc | Must clarify scope |
| 7 | **MEDIUM** | CopyIn/CopyOut omitted from chunk types | Design Doc | Missing P1 requirement |
| 8 | **MEDIUM** | Cancel/Close/Notice chunks missing | Design Doc | Missing PRD requirements |
| 9 | **MEDIUM** | Recording failure: NF5 ("continue") contradicts SSH behavior ("terminate") | Both | Must resolve |
| 10 | **LOW** | BSR direction naming: "inbound/outbound" vs "up/down" | PRD | PRD should match codebase |
| 11 | **LOW** | Sensitive parameter redaction not resolved | Both | Recommendation only |
| 12 | **LOW** | Auth transparency assumption needs clarification | Design Doc | References prerequisite |
| 13 | **LOW** | LISTEN/NOTIFY and other non-chunked messages not listed | Design Doc | Recommendation only |

---

## Verdict

**DO NOT APPROVE as design-verified.** The design doc and PRD disagree on fundamental identifiers (protocol name, chunk type IDs, proto field shapes). The prerequisite infrastructure (PostgresProtocolContext, handler dispatch, credential injection) does not exist in this OSS fork. And the TRY_EACH strategy is entirely missing.

Recommended path:
1. Resolve protocol identifier conflict (1st blocking issue).
2. Reconcile chunk type table between PRD and design doc.
3. Either add prerequisite document or convert this design to a combined "credential injection + recording" spec.
4. Tag as `design-verified` only after items 1-6 from the summary table are resolved.
