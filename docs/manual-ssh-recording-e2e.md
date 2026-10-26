# Manual SSH Session Recording E2E Test

This is the procedure to manually exercise SSH session recording end-to-end and produce a BSR (Boundary Session Recording) on disk.

## What this tests

The full data path used by the worker when proxying an SSH session:

```
client (ssh/boundary)  →  worker TCP/WS endpoint  →  target SSH server
                              ↓
                       SSH handler (handleProxy)
                              ↓
                       pipe + InterceptingConn
                              ↓
                   BSR ConnectionRecorder (both directions)
                              ↓
                       SshRecordingManager
                              ↓
                       BSR files on disk
```

A BSR is a directory containing cryptographic key material, SHA256 checksums, and the recorded `messages-inbound.data` / `messages-outbound.data` files for each connection.

## Prerequisites

- Linux host with `ssh` and `sshd` available
- Built boundary binary at `/home/dan.rohan/software/boundary/bin/boundary` (post-`9dcbf654b` — has the `oss_recording_storage.OpenFile` fix that honors `WithCreateFile`)
- The repo at `/home/dan.rohan/software/boundary`
- `boundary` CLI in `$PATH` (or referenced via the bin path above)
- A workspace directory for the BSR output, e.g. `/tmp/boundary-bsr/`

## Important constraint

**OSS Boundary 0.13.1 does not support `boundary targets create ssh`.** The CLI reports:

```
Subcommands:
    ssh    Create a ssh-type target (HCP only)
    tcp    Create a tcp-type target
```

This means **a fully live `boundary connect ssh` → worker → target SSH server flow is not possible in OSS 0.13.1.** SSH targets are an HCP-only feature in this release.

There are two workable paths for a manual end-to-end test:

- **Path A (live HCP / future OSS release):** run the full `boundary connect ssh` against a real SSH target. This is the production flow.
- **Path B (OSS 0.13.1):** run the in-process `go test` end-to-end test. This exercises the same `handleProxy` → `pipe` → `InterceptingConn` → `SshRecordingManager` → BSR path that the worker uses, with a Go-level SSH server standing in for a real target.

Path B is what the rest of this document focuses on. Path A is included at the end for future use.

---

## Path B — In-process E2E (OSS 0.13.1)

### B1. Confirm the fix is in the test binary

The fix to `oss_recording_storage.OpenFile` is required; without it the BSR session fails to create the `.journal` file and **no BSR is produced**.

```bash
cd /home/dan.rohan/software/boundary
git log --oneline -1
# expected: 9dcbf654b Fix oss_recording_storage OpenFile to honor WithCreateFile; add e2e BSR test
```

If the commit is not on top, cherry-pick or rebase:

```bash
git cherry-pick 9dcbf654b
```

### B2. Run the e2e test

```bash
cd /home/dan.rohan/software/boundary
rm -rf /tmp/boundary-bsr-e2e
go test -count=1 -timeout 60s -v -run TestE2ESshSessionRecordingProducesBsrFile \
  ./internal/daemon/worker/proxy/ssh/
```

Expected output (last lines):

```
=== RUN   TestE2ESshSessionRecordingProducesBsrFile
    e2e_bsr_test.go:174: BSR E2E artifact: /tmp/boundary-bsr-e2e/recordings/s_e2e_smoke01.bsr
    e2e_bsr_test.go:175: BSR session files: [...12 files including bsrKey.pub, session-meta.json, .journal, SHA256SUM, ...]
    e2e_bsr_test.go:176: BSR connection files: [...7 files including messages-inbound.data, messages-outbound.data, .journal, ...]
--- PASS: TestE2ESshSessionRecordingProducesBsrFile (0.51s)
PASS
ok  github.com/hashicorp/boundary/internal/daemon/worker/proxy/ssh  0.525s
```

### B3. Inspect the produced BSR

```bash
BSR=/tmp/boundary-bsr-e2e/recordings/s_e2e_smoke01.bsr
ls -la $BSR
ls -la $BSR/cr_e2e_smoke01.connection
```

Expected files in `$BSR` (session-level):

- `bsrKey.pub` — BSR public key
- `wrappedBsrKey` — KMS-wrapped BSR symmetric key
- `wrappedPrivKey` — wrapped BSR private key
- `pubKeyBsrSignature.sign` — BSR key signature
- `pubKeySelfSignature.sign` — self-signature
- `session-meta.json` — public_id, user, target, worker, credentials
- `session-recording.meta` — protocol/session id metadata
- `session-recording-summary.json` — end-of-session summary
- `SHA256SUM` and `SHA256SUM.sig` — checksums + signature
- `.journal` — operation journal
- `cr_e2e_smoke01.connection/` — connection subdirectory

Expected files in `$BSR/cr_e2e_smoke01.connection/`:

- `connection-recording.meta` — connection id + timestamps
- `connection-recording-summary.json` — bytes-up/bytes-down summary
- `messages-inbound.data` — gzip-compressed BSR chunks of target→client data
- `messages-outbound.data` — gzip-compressed BSR chunks of client→target data
- `SHA256SUM` and `SHA256SUM.sig`
- `.journal`

### B4. Verify the recording captures real data

```bash
# Confirm both directions were recorded.
test -s $BSR/cr_e2e_smoke01.connection/messages-inbound.data \
  && echo "OK: inbound data present" \
  || echo "FAIL: inbound data missing"

test -s $BSR/cr_e2e_smoke01.connection/messages-outbound.data \
  && echo "OK: outbound data present" \
  || echo "FAIL: outbound data missing"

# Inspect the journal for the operations performed.
cat $BSR/.journal
echo "---"
cat $BSR/cr_e2e_smoke01.connection/.journal
```

You should see a sequence of `CREATING ... / CREATED ... / CLOSING ... / CLOSED ...` lines in each journal, with `messages-inbound.data` and `messages-outbound.data` both being created, written, and closed.

### B5. Verify the session metadata is correct

```bash
cat $BSR/session-meta.json | python3 -m json.tool | head -20
```

Expected fields populated (this is the metadata `SetSessionMeta` wrote):

- `PublicId`: `s_e2e_smoke01`
- `Endpoint`: `tcp://127.0.0.1:22`
- `User.PublicId`: `u_smoke`, `User.Name`: `smoketest`
- `Target.PublicId`: `ttcp_smoke`, `Target.Name`: `SmokeTest SSH`, `Target.DefaultPort`: `22`
- `Worker.PublicId`: `w_smoke`
- `StaticUsernamePasswordCredentials[0].PublicId`: `cred_smoke`, `Username`: `boundarytest`

### B6. Verify the cryptographic chain

```bash
# Check that the SHA256SUM file exists and is non-empty.
ls -la $BSR/SHA256SUM $BSR/SHA256SUM.sig
# Spot-check: SHA256SUM should list every other file in $BSR.
cat $BSR/SHA256SUM | head
```

### B7. (Optional) Re-run and confirm idempotency

```bash
# A second run overwrites files in the same dir? No — the test does
# os.RemoveAll first. So this just confirms a fresh BSR is produced.
rm -rf /tmp/boundary-bsr-e2e
go test -count=1 -run TestE2ESshSessionRecordingProducesBsrFile \
  ./internal/daemon/worker/proxy/ssh/
ls /tmp/boundary-bsr-e2e/recordings/s_e2e_smoke01.bsr/cr_e2e_smoke01.connection/
```

### What this test does NOT cover (and why)

- **No real `boundary` CLI / `boundary connect ssh` flow.** OSS 0.13.1 cannot create an SSH target, so the live CLI→worker→target path is not exercisable in OSS. The test directly drives the same in-process code path the worker uses internally (`pipe` + `InterceptingConn` + `SshRecordingManager`).
- **No real PKI / mTLS handshake on the worker endpoint.** The test bypasses the worker's `/v1/proxy` HTTP/WS endpoint and calls `handleProxy` (via the pipe) directly. The TLS handshake was already verified in earlier test runs against the dev server.
- **No controller-side session authorization.** The test skips `sess.RequestAuthorizeConnection` and the controller's protocol-context dispatch. That dispatch path was verified end-to-end against the dev server in earlier work — the dev server logs showed the SSH handler being selected and `SshProtocolContext` matching the type-URL dispatcher.

---

## Path A — Full live flow (HCP or future OSS release)

Use this procedure once HCP is wired up or once a future OSS release supports `boundary targets create ssh`.

### A1. Start an SSH target server

```bash
# Start a debug sshd on a non-default port to keep things clean.
sudo cp /etc/ssh/sshd_config /tmp/sshd_config.test
sudo sed -i 's/^Port .*/Port 2222/' /tmp/sshd_config.test
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /tmp/sshd_config.test
# Make sure the host key exists.
sudo ssh-keygen -A
sudo /usr/sbin/sshd -f /tmp/sshd_config.test -E /tmp/sshd.log
# Confirm it's listening.
ss -ltn | grep 2222
```

### A2. Start the boundary dev server

```bash
cd /home/dan.rohan/software/boundary
mkdir -p /tmp/boundary-bsr
rm -rf /tmp/boundary-bsr/*  # fresh start

./bin/boundary dev \
  -api-listen-address=127.0.0.1:9200 \
  -cluster-listen-address=127.0.0.1:9201 \
  -proxy-listen-address=127.0.0.1:9202 \
  -worker-recording-storage-dir=/tmp/boundary-bsr \
  -login-name=admin \
  -password=password \
  -log-level=DEBUG \
  > /tmp/boundary-dev.log 2>&1 &
BOUNDARY_PID=$!
echo "boundary pid: $BOUNDARY_PID"

# Wait for the API to be ready.
for i in {1..30}; do
  curl -ks -u admin:password https://127.0.0.1:9200/v1/auth-methods >/dev/null 2>&1 && break
  sleep 1
done
```

### A3. Authenticate the boundary CLI

```bash
export BOUNDARY_ADDR=https://127.0.0.1:9200
export BOUNDARY_TLS_INSECURE=true
export BOUNDARY_AUTH_METHOD_ID=ampw_1234567890

BOUNDARY_PASSWORD=password ./bin/boundary authenticate password \
  -auth-method-id $BOUNDARY_AUTH_METHOD_ID \
  -login-name admin \
  -password env://BOUNDARY_PASSWORD
# Save the printed token into BOUNDARY_TOKEN, e.g.:
export BOUNDARY_TOKEN=at_...
```

### A4. Create an SSH target

(Requires HCP or a future OSS release that supports `boundary targets create ssh`.)

```bash
./bin/boundary targets create ssh \
  -scope-id p_1234567890 \
  -name "manual-ssh-test" \
  -address 127.0.0.1 \
  -default-port 2222 \
  -format=json

# Note the target id from the output: at_...
export TARGET_ID=at_...
```

### A5. Connect with the boundary CLI

```bash
./bin/boundary connect ssh -target-id $TARGET_ID -style=ssh
# This drops you into an SSH session. Run some commands.
whoami
ls -la
exit
```

### A6. Inspect the produced BSR

```bash
ls -R /tmp/boundary-bsr/
# The session id (s_...) is the subdir name. Inside it is cr_...connection/
# with messages-inbound.data, messages-outbound.data, etc.
```

### A7. Stop the dev server

```bash
kill $BOUNDARY_PID
```

---

## Troubleshooting

### `messages-outbound.data` is missing

The BSR chunk encoder is lazily initialized per direction. If no outbound data was recorded, the file is not created (by design). Check that the test really wrote to the client side (`c2.Write` in the test, or that the SSH client actually sent data in Path A).

### `session-meta.json` is empty / has empty PublicId

`SetSessionMeta` stores the metadata in memory but does not currently rewrite the on-disk `session-meta.json` file. The BSR will still be valid — it just has the placeholder values from session creation. This is a known follow-up bug, not a blocker for the e2e test.

### `failed to create BSR session: open .../.journal: no such file or directory`

The `oss_recording_storage.OpenFile` bug is back. Confirm `9dcbf654b` is on top of the branch and the binary was rebuilt:

```bash
cd /home/dan.rohan/software/boundary
git log --oneline -1
go build -o ./bin/boundary ./cmd/boundary
# For Path B, no rebuild needed — the test compiles on the fly.
```

### Dev server's `targets create ssh` returns "Unknown type provided"

You're on OSS 0.13.1. SSH targets are HCP-only in this release. Use Path B (the in-process test) for now.

### BSR directory is empty

The dev server's `worker-recording-storage-dir` only writes BSR for sessions that use a recording-enabled worker. The recording path is wired up via the SSH session recording work (commits on `feature/ssh-session-recording`). Confirm the running binary was built from that branch:

```bash
strings /home/dan.rohan/software/boundary/bin/boundary | grep -E 'SshProtocolContext|SshRecordingManager' | head -3
```

If empty, the binary is from before the SSH recording work landed. Rebuild:

```bash
cd /home/dan.rohan/software/boundary
git checkout feature/ssh-session-recording
go build -o ./bin/boundary ./cmd/boundary
```

### Inspecting BSR chunks

The `messages-*.data` files are gzip-compressed BSR chunks. To peek at the raw structure:

```bash
# Decompress and inspect the first chunk
zcat $BSR/cr_e2e_smoke01.connection/messages-inbound.data | head -c 200 | xxd | head
# Or use the BSR CLI tool if installed:
boundary session-recordings read $BSR
```

## Quick reference

| What | Where |
|---|---|
| Fix commit | `9dcbf654b` |
| E2E test | `internal/daemon/worker/proxy/ssh/e2e_bsr_test.go` |
| Bug fix file | `internal/storage/oss_recording_storage.go` (`OpenFile` honors `WithCreateFile`) |
| BSR output (Path B) | `/tmp/boundary-bsr-e2e/recordings/s_e2e_smoke01.bsr/` |
| BSR output (Path A) | `/tmp/boundary-bsr/recordings/s_*.bsr/` |
| Dev server log | `/tmp/boundary-dev.log` |
| Dev server | `http://127.0.0.1:9200`, login `admin` / `password` |
