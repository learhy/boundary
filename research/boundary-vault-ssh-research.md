# Boundary + Vault SSH at Scale - HashiCorp Discuss Research

**Searched:** discuss.hashicorp.com (Boundary + Vault forums)
**Date:** 2026-06-03
**Queries used (representative):**
- `boundary dynamic user ssh` / `boundary vault ssh scale` / `boundary credential brokering ssh`
- `boundary injected application credential ssh` / `boundary vault ssh secret engine`
- `boundary jit linux` / `boundary ldap sudo` / `boundary centrify` / `boundary delinea`
- `boundary pam ssh` / `boundary host catalog aws` / `boundary ssh thousands hosts`
- `vault ssh role scale` / `vault signed ssh boundary`

> No threads surfaced on **Centrify** or **Delinea** specifically - the
> community treats Boundary as a greenfield replacement for those PAM
> tools rather than a migration target. Cross-cutting section covers
> what to do if you are coming off Centrify/Delinea.

---

## TL;DR - The 4 patterns that actually scale

| # | Pattern | Boundary/Vault feature | Anchor thread |
|---|---|---|---|
| 1 | Signed SSH certs brokered by Vault (worker injects the cert - never hands it to the user) | `vault-ssh-certificate` credential library; cert *injection* is HCP/Enterprise only | 18699, 50620, 52447, 54074, 41085, **70251** |
| 2 | Dynamic credentials with per-user templating so audit trails show real users, not "token" | Vault credential library `http_request_body` with `{{ .Account.Name }}` etc. (added in Boundary 0.11.1) | **47283** |
| 3 | Dynamic Host Catalogs (DHC) so you don't maintain thousands of static host entries | AWS / Azure plugins, worker tags as filters | 71234, 62383, 38285, 56931 |
| 4 | JIT / time-bound access via OIDC managed groups -> Boundary roles | No native approval workflow - push approval into your IDP | 47454, 34938, 30116 |

Scale risks called out by the community: UI 500-errors past ~60 hosts
in a host set (**76550**), DB load with many workers (**54464**), and a
critical Vault CVE that bites SSH-engine users (**70251** - HCSEC-2024-20).

---

## Thread-by-thread digest

### 1. Leveraging Boundary and Vault to use SSH signed certificates (4 posts)
URL: https://discuss.hashicorp.com/t/leveraging-boundary-and-vault-to-use-ssh-signed-certificates/18699
**Question (paraphrased):** Will Boundary broker Vault-issued SSH *signed
certificates* so users don't have to manage per-host keys? Is this on the
roadmap?
**Best answer - Paul Pacent (PM, HashiCorp):** Yes. "Our goal is for
Boundary users, once authenticated, to be able to seamlessly access their
targets with secrets brokered by Boundary from Vault … such that the
secrets don't need to be managed by the user. Making use of Vault's ssh
signed certificates to securely ssh to Boundary targets is a great
example of a possible use-case for this scenario." Vault-integration was
#2 on the public roadmap (after OIDC). Founding thread for the SSH-cert-
injection story.

### 2. Authenticate users without giving them an ssh key for servers via boundary (6 posts)
URL: https://discuss.hashicorp.com/t/authenticate-users-without-giving-them-an-ssh-key-for-servers-via-boundary/20625
**Question:** Can Boundary connect me to a target *without* me having
the host's SSH key?
**Best answer - Paul Pacent (PM, HashiCorp):** Two pieces needed -
"(1) Boundary needs to be able to manage target credentials and/or
broker them from a secure secrets management solution. (2) Boundary
workers needs to be able to **inject** the credential into a session
so that they're not passed back to the user." Both tracked under the
**JIT access** roadmap pillar.

### 3. How to create a credential library to provide ssh credentials to sessions (9 posts)
URL: https://discuss.hashicorp.com/t/how-to-create-a-credential-library-to-provide-ssh-credentials-to-sessions/26754
**Question:** Doc example only covers DB; how to wire Vault's SSH secret
engine into Boundary as a credential library?
**Best answer (community-validated, staff-acknowledged):**
```
boundary credential-libraries create vault \
  -credential-store-id $CSVLT_ID \
  -vault-path "PATH OF YOUR SSH SECRET" \
  -vault-http-method "POST" \
  -vault-http-request-body '{"ip":"<host-ip>"}'
```
**Critical caveat from @mgaffney (HashiCorp):** "Currently, there is no
good solution to solve this problem [of putting the *dynamic* host IP
into the POST body], but we are aware of it being a pain point."
Workaround is one credential library per host - **does not scale** past
a handful of hosts.

### 4. How to use Vault as Boundary Credential Store to keep hosts ssh static credentials (4 posts)
URL: https://discuss.hashicorp.com/t/how-to-use-vault-as-boundary-credential-store-to-keep-hosts-ssh-static-credentials/30562
**Question:** Why does Boundary show me the Vault secret but not *use*
it during `boundary connect ssh`?
**Best answer - Paul Pacent (PM, HashiCorp):** "Currently static
credentials are passed directly back to users to copy and paste into
sessions. This workflow is something we are investigating to improve in
future Boundary offerings. In the meantime, **for best security
practices we recommend using a single use password, such as Vault's
OTP secrets engine** for your Boundary credential library." Pragmatic
near-term fix = Vault SSH OTP, not password reuse.

### 5. Temporary "time-boxed" access to a target (3 posts)
URL: https://discuss.hashicorp.com/t/temporary-time-boxed-access-to-a-target/34938
**Question:** Can I bind a target grant to a user with a TTL?
**Best answer - Paul Pacent (PM, HashiCorp):** "Timebound and/or
conditional access to targets … is an area we're interested in
investing in the future." Today you only have session TTLs, not grant
TTLs.

### 6. SSH Signed Certificates with host principal validation (10 posts)
URL: https://discuss.hashicorp.com/t/ssh-signed-certificates-with-host-principal-validation/41085
**Question:** How do I make Vault sign an SSH cert with the right
`valid_principals` so user Jim can only land on server Ceres and Naomi
only on Tycho?
**Best answer - community (stuart-c):** Use Vault SSH roles to stamp a
*role group* into the cert's `valid_principals`, then on the host:
```
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
AuthorizedPrincipalsFile /etc/ssh/authorized_principals
```
where `authorized_principals` contains a group label per host (e.g.
`product-dev-ingest`). The user picks the role when requesting a cert:
```
vault write -field=signed_key ssh/sign/mygroup \
  public_key=@$HOME/.ssh/id_ed25519.pub \
  valid_principals="mygroup" > ~/temp-key-mygroup
```
A wrapper script hides the cert call from the user. **This is the
canonical "scale SSH with Vault" pattern** that Boundary 0.13+ sits
on top of.

### 7. Boundary vault integration - dynamic credential username_templating (20 posts) - MOST IMPORTANT
URL: https://discuss.hashicorp.com/t/boundary-vault-integration-dynamic-credential-username-templating/47283
**Question:** All dynamic creds from Vault come back under user
`token-token_xxxxx`; how do I make the DB / SSH username track the
actual human (`amos.c`) for audit?
**Best answer - Paul Pacent (PM, HashiCorp):** Shipped in **0.11.1** -
Vault credential library paths and POST bodies accept Go-template
parameters tied to the account on whose behalf Boundary is calling:
```
{{ .User.Id }}  {{ .User.Name }}  {{ .User.FullName }}  {{ .User.Email }}
{{ .Account.Id }}  {{ .Account.Name }}  {{ .Account.LoginName }}
{{ .Account.Subject }}  {{ .Account.Email }}
{{ truncateFrom .Account.Email "@" }}   # -> "foo" from "foo@bar.com"
```
**Pattern at scale (HCL):**
```hcl
resource "boundary_credential_library_vault" "ssh" {
  credential_store_id = boundary_credential_store_vault.foo.id
  path                = "ssh/sign/{{ .Account.LoginName }}"
  http_method         = "POST"
  http_request_body   = jsonencode({
    public_key      = "...",
    valid_principals = ["{{ .Account.LoginName }}"]
  })
}
```
*Auditor caveat (raised by @maxb on the companion thread):* even with
this, if `valid_principals` is left empty in the Vault role, the signed
cert authenticates as **any user including root** on the host. This is
exactly the CVE in #15 below - non-negotiable, pin it on every role.

### 8. Boundary support for temp grant/role assignment (4 posts)
URL: https://discuss.hashicorp.com/t/boundary-support-for-temp-grant-role-assignment/47454
**Question:** Slack/email-style approval flow for 30-min elevation?
**Best answer - Paul Pacent (PM, HashiCorp):** "Have you considered
OIDC **managed groups**? … At login time to Boundary, Boundary reads
the JWT from the IDP and dynamically assigns them a group membership
based on their time-bound authorization." No first-party approval
workflow exists; push the approval into your IDP and let managed
groups sync the result.

### 9. Boundary audit Logs and ssh Session recording (10 posts)
URL: https://discuss.hashicorp.com/t/boundary-audit-logs-and-ssh-session-recording/47835
**Question:** Are commands/keystrokes recorded for compliance?
**Best answer - Adam Bouhmad (HashiCorp, staff):** Session recording
of keystrokes is "actively exploring over the next fiscal year" (2022-
2023 era). HCP Boundary streams audit events to Datadog / CloudWatch.
**On-prem Boundary OSS still has no command-level keystroke recording**
as of the last surveyed post - major gap if you're evaluating Boundary
as a Centrify/Teleport replacement for compliance-mandated recording.

### 10. SSH-CA credential-library host requirements and configuration details (3 posts)
URL: https://discuss.hashicorp.com/t/ssh-ca-credential-library-host-requirements-and-configuration-details/50620
**Question:** Step-by-step for the new `vault-ssh-certificate` library.
**Best answer - @tmessi (HashiCorp):** Full recipe:
1. `vault secrets enable ssh` -> generate or upload CA -> create a role.
2. Distribute the CA pubkey to every host; in `sshd_config`:
   `TrustedUserCAKeys /etc/ssh/user_ca.pub`.
3. Create the Boundary library:
```
boundary credential-libraries create vault-ssh-certificate \
  -credential-store-id=$CSVLT_ID -name=ssh-example \
  -username=foo -vault-path=ssh/sign/foo -key-type=ed25519 \
  -extension permit-pty
```
**Gotcha:** "create a ssh-type target (HCP only)" - **SSH CA credential
injection is HCP-only** even though credential *brokering* (paste the
cert yourself) is OSS.

### 11. SSH Certificate Injection with OSS? (3 posts)
URL: https://discuss.hashicorp.com/t/ssh-certificate-injection-with-oss/52447
**Question:** Is cert injection coming to OSS Boundary?
**Best answer - Anando Chatterjee (HashiCorp, staff):** "SSH credential
injection is an **enterprise-only** feature and we have **no plans to
introduce enterprise features within Boundary OSS**. … Credential
brokering is still available within Boundary OSS and if you are using
a Boundary helper function within the CLI (e.g. `boundary connect ssh`),
Boundary would pass the brokered credential on to the target without any
user intervention, offering a near-passwordless experience."
*Implication: on-prem shops that need true zero-touch cert injection
need HCP or Boundary Enterprise - there is no OSS workaround.*

### 12. Using Boundary to Grant Authentication Time-Bound Certificates to Projects (4 posts)
URL: https://discuss.hashicorp.com/t/using-boundary-to-grant-authentication-time-bound-certificates-to-projects/54074
**Question:** Can Boundary broker a time-bound SSH cert, signed by an
HCP-Vault CA, that the user just presents to the host? End-to-end UX?
**Best answer (community, Mac Miranda):** Maps the ask to the SSH cert
injection docs and points to the *HCP-only* "SSH Certificate Injection
with HCP Boundary" tutorial. *"Credential injection" = HCP Enterprise
feature.* This thread is the clearest plain-English description of the
target end-state and which pieces require which tier.

### 13. Suboptimal Boundary database load (9 posts)
URL: https://discuss.hashicorp.com/t/suboptimal-boundary-database-load/54464
**Question:** 3 controllers + a `db.t4g.xlarge` Postgres taking 7-10 s
to list targets, 1 vCPU pinned.
**Best answer - Matt Malnick (HashiCorp, staff):** "We've had a chance
to review this with the engineering team. … It would help us if you
could run an `EXPLAIN ANALYZE` for the top two queries." HashiCorp
engineering opened a PR with a fix.
**Operational lesson for scale:** the target-list query degrades as
`session_connection` rows accumulate - track session retention, and
size the DB higher than the "t3.micro reference architecture" suggests
once you exceed a few thousand active connections.

### 14. Boundary Dynamic Linux User Creation (1 post, no staff answer)
URL: https://discuss.hashicorp.com/t/boundary-dynamic-linux-user-creation/66809
**Question:** Can Boundary define policies that *create* a Linux user
on the target at session-start (e.g. "User A gets read-only first,
then on policy change a sudo user is provisioned")?
**Status:** No HashiCorp response in-thread. The poster references the
"Scaling SSH Access with HashiCorp Vault" Medium article - which still
requires pre-existing local users. **This is the open hole in
"fully automated JIT Linux user provisioning"** - Boundary brokers
creds, but the Linux account itself must still exist. Real-world
workarounds:
- Vault SSH-signed certs + `authorized_principals` mapping on the host
  (no local user needed beyond the principal label).
- First-boot `cloud-init` / config-mgmt step that creates a `boundary`
  service account on every new VM.
No Boundary-native dynamic Linux-user creation exists as of 0.19.x.

### 15. HCSEC-2024-20 - Vault SSH Secrets Engine Configuration Did Not Restrict Valid Principals By Default (staff bulletin)
URL: https://discuss.hashicorp.com/t/hcsec-2024-20-vault-ssh-secrets-engine-configuration-did-not-restrict-valid-principals-by-default/70251
**Affected:** Vault CE 1.7.7 -> 1.17.5 (fixed 1.17.6), Vault Enterprise
1.7.7 -> 1.17.5 / 1.16.9 / 1.15.14 (fixed 1.17.6 / 1.16.10 / 1.15.15).
**CVE-2024-7594:** If `valid_principals` and `default_user` are unset on
the SSH role, an authorized user can get a cert valid for *any*
principal (including root) on the host.
**Mitigation:** new `allow_empty_principals` config, default `false`.
**Operational must-do for any Boundary+Vault SSH deployment:**
explicitly set `valid_principals` on every role, then audit with
`vault read ssh/roles/<name>`.

### 16. Boundary UI Error 500 with larger host sets - v0.19.3 (8 posts)
URL: https://discuss.hashicorp.com/t/boundary-ui-error-500-with-larger-host-sets-cli-works-fine-v0-19-3-rke2-ubuntu-24-04/76550
**Question:** UI returns 500 on the Hosts tab once a host set has ~40-60
hosts. CLI works fine even with 250 hosts.
**Best answer - @hashicc (HashiCorp, staff):** "From what I can tell
this isn't something we've seen before. … I tried a quick test with
60+ hosts … and wasn't able to hit any issues with the UI." Asked for
HAR / network-trace data. **Practical takeaway:** at scale, drive host
management from the **CLI / API / Terraform** and treat the UI as a
diagnostic tool. The user verified the issue persists on 0.20.0 as well.

---

## Cross-cutting answers to the original question

### "Scaling Vault SSH roles to thousands of hosts"
- The Vault side scales fine - one CA, many roles, short-lived certs.
- The **Boundary** side hits a wall at ~60 hosts per static host set
  (UI 500s, thread 76550). Use **Dynamic Host Catalogs** (AWS/Azure
  plugins, threads 38285, 71234, 62383) instead of static host sets,
  and use **worker tags** to fan out load.

### "Dynamic Linux user provisioning"
- Out of the box: **no**. Boundary brokers credentials, it does not
  create local Linux accounts.
- The two production patterns are:
  1. **Vault SSH signed certs** + `AuthorizedPrincipalsFile` on each
     host - the "user" is the principal string in the cert, no local
     account needed (threads 41085, 50620).
  2. **First-boot `cloud-init` / config-mgmt** that creates a
     `boundary-svc` account that everyone logs in as; `sudo` rules in
     `/etc/sudoers.d/boundary` are bound to that account (or to LDAP
     groups synced from the IDP).

### "LDAP / sudo mapping on Boundary targets"
- No first-party LDAP integration on Boundary targets - and no
  Centrify/Delinea threads surfaced. The community-standard answer is
  to put your LDAP/IDP at the **front door** (OIDC auth into Boundary,
  managed groups into Boundary roles - thread 47454), and let host-
  side `sssd` / `nslcd` pull the user's groups into `sudoers.d` for
  fine-grained escalation.
- For sudoers specifically, a common pattern is a single sudo rule
  tied to a Boundary-brokered principal + an LDAP group, e.g.
  `%boundary-admins ALL=(ALL) NOPASSWD: ALL` - the group is the IDP-
  managed claim.

### "Delinea / Centrify migration"
- Zero direct discussion. Treat Boundary as a **greenfield** replacement:
  - Need command-level session recording? -> still need Centrify/
    Teleport or a third-party, or wait for HCP (thread 47835).
  - Need brokered *static* SSH keys? -> Vault SSH OTP is the staff-
    recommended interim (thread 30562).
  - Need full cert injection on-prem? -> OSS can't do it; HCP/
    Enterprise is required (threads 52447, 54074).

### "JIT access on Linux"
- **Native:** only session TTL exists; no grant TTL (thread 34938).
- **Recommended:** OIDC managed groups driven by an external approval
  workflow (Okta Access Requests, SailPoint, ServiceNow + the IDP) -
  thread 47454.

---

## Notable gaps / open questions the community flagged

1. **Dynamic host IP in Vault SSH POST body** - thread 26754: no
   resolution. Workaround is one credential library per host (anti-
   pattern for thousands of hosts). HCP/Enterprise with cert injection
   sidesteps it.
2. **Dynamic Linux user creation** - thread 66809: no HashiCorp
   answer; open feature ask.
3. **OSS command-level keystroke recording** - thread 47835: still
   missing; on-prem compliance use-cases have no Boundary-native
   solution.
4. **Vault username-template pass-through to DB / SSH roles** -
   thread 47283: `{{ .Account.Name }}` works on the *Boundary* side
   of the call, but Vault's own `username_template` doesn't natively
   see Boundary user metadata; you have to thread it via the POST body.
5. **Large host-set UI** - thread 76550: not fixed in 0.20.0 as of
   latest post.
6. **Database load under scale** - thread 54464: `session_connection`
   table growth is the hot spot; PR in flight at the time of the
   thread.

---

## Files saved during research

- `/tmp/srch_*.json`, `/tmp/srch2_*.json`, `/tmp/srch3_*.json` - raw
  search responses (16 searches total)
- `/tmp/bthreads/<id>.json` - full thread JSON for the 20 cited threads
- `/home/dan.rohan/boundary-vault-ssh-research.md` - this report
