# HashiCorp Boundary & Vault — SSH Credential Injection & Dynamic Credentials

Source documents fetched from developer.hashicorp.com and raw.githubusercontent.com
on 2026-06-03. All quotes are verbatim or near-verbatim from the live docs.

---

## 1. URL CORRECTIONS (paths the task asked for that 404)

Several URLs supplied in the task brief no longer exist at that exact path. The
correct, current paths are listed below — these are the URLs that actually
returned the documentation.

| Requested URL (404) | Correct URL (200) |
|---|---|
| `…/boundary/docs/hosts` | **https://developer.hashicorp.com/boundary/docs/hosts** OK |
| `…/boundary/docs/credentials` | **https://developer.hashicorp.com/boundary/docs/credentials** OK |
| `…/boundary/docs/configuration/credential-injection` | **https://developer.hashicorp.com/boundary/docs/credentials/configure-credential-injection** OK (path moved under `/credentials/`) |
| `…/boundary/docs/concepts/credential-injection` | **https://developer.hashicorp.com/boundary/docs/concepts/credential-management** OK (brokering + injection share one page; `…#credential-injection` is the anchor) |
| `…/vault/docs/secrets/ssh` | **https://developer.hashicorp.com/vault/docs/secrets/ssh** OK |
| `…/vault/docs/secrets/ssh/ssh-roles` | NO SUCH PAGE. The closest match is the `vault-ssh-certificate` credential library in Boundary, which consumes Vault SSH engine `roles/`. |
| `…/vault/docs/secrets/ssh` + "OTP" | **https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords** OK |
| `…/vault/docs/secrets/ssh` + "dynamic network" | The original "dynamic keys" feature of the Vault SSH engine was **REMOVED in Vault 1.13** (per the SSH engine's own index page; deprecation announced in Vault 1.12). The "dynamic" SSH path today is **Signed SSH certificates** at **https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates** OK |
| GitHub | **https://github.com/hashicorp/boundary** OK (current release: **v0.21.3**) |
| CHANGELOG | **https://raw.githubusercontent.com/hashicorp/boundary/main/CHANGELOG.md** OK |

---

## 2. BOUNDARY — TWO CREDENTIAL PARADIGMS

Source: https://developer.hashicorp.com/boundary/docs/concepts/credential-management
(v0.21.x as fetched; URL anchors: `#credential-brokering`, `#credential-injection`)

> "There are two credential management paradigms in Boundary, credential brokering
> and credential injection."

### 2.1 Credential brokering (open-source + Enterprise)

> "Credential brokering is the process by which credentials are fetched from a
> credential store, and then returned back to the user.
> The user must already be authorized to connect to a specific target to have
> credentials for that target brokered back to them. Credentials are brokered when
> the session is established."

Flow: user authenticates -> requests connection -> **controller fetches credentials
from the credential store and passes them to the user** -> user enters them.

> "You can attach brokered credentials to SSH, TCP, or RDP targets. Brokered
> credentials can take the form of a token, username password, username password
> domain, JSON blob, or an unstructured secret stored in Vault, for example."

> "Additionally, with Vault's dynamic secrets engine, an administrator could
> configure their environment such that secrets are essentially one-time
> passwords, as the credentials are revoked after the session is terminated."

### 2.2 Credential injection (Enterprise / HCP Boundary only)

The page carries an explicit "Enterprise" badge:

> "This feature requires HCP Boundary or Boundary Enterprise."

> "Credential injection is the process by which a credential is fetched from a
> credential store and then passed on to a worker for authentication to a remote
> machine. With credential injection, the user never sees the credential required
> to authenticate to the target. This provides a passwordless experience for the
> user, as the worker does both session establishment and authentication to the
> target on behalf of the user. This process differs from credential brokering,
> where credentials are returned to the user rather than injected into the
> session on worker nodes."

Flow: user authenticates -> requests connection -> **controller fetches credentials
from credential store** -> worker establishes session to target -> **controller
passes credentials to worker** -> worker authenticates -> user is now authenticated
to the target.

### 2.3 Target types & supported credential types

From `/boundary/docs/concepts/credential-management#target-types`:

> "Credential injection is required for the RDP and SSH target types.
>
> You can inject the following credential types when you access SSH targets:
> - SSH certificates
> - Usernames and passwords
> - Usernames and public keys
>
> Keyboard-interactive authentication is not supported for credential injection.
> When you use Username password credentials, ensure that your SSH server is
> configured to allow password authentication.
>
> You can inject username password domain credentials when you access RDP targets
> in Windows environments that use Active Directory or NTLMv2 for authentication.
>
> You can broker additional credentials to RDP or SSH targets after the session
> is established using injected credentials."

From `/boundary/docs/credentials#end-user-workflows`:

> "- **TCP targets** cannot have any injected application credentials
> - **SSH targets** must have at least one injected application credential to
>   establish the SSH connection
> - **RDP targets** must have at least one injected application credential to
>   establish the RDP connection"

### 2.4 Configuration requirements (verbatim from configure-credential-injection)

> "- This feature requires either HCP Boundary or Boundary Enterprise
> - You must have an existing target available that supports credential injection:
>   - **RDP targets**: Must be configured with at least one injected application credential
>   - **SSH targets**: Must be configured with at least one injected application credential
>   - **TCP targets**: Do not support credential injection
> - You must have configured either a static credential store or a Vault credential store
> - You must have a static credential saved in your static credential store or
>   Vault credential store. The credential must correspond to the target to which
>   you want to authenticate.
> - For SSH targets: **Keyboard-interactive authentication is not supported.**
>   When you use username-password credentials, ensure that your SSH server is
>   configured to allow password authentication."

CLI to attach a credential source to a target (the actual wire command):

```
$ boundary targets add-credential-sources \
  -id trdp_vO60a7TwpI \
  -injected-application-credential-source csvlt_Xqa6V6QwfM
```

> "If you are using a static credential store, `brokered-credential-source`
> refers to the ID of a **credential** in the static credential store. If you are
> using a Vault credential store, `brokered-credential-source` refers to the ID
> of a **credential library** in the Vault credential store."

### 2.5 Credential types Boundary supports (from `/boundary/docs/credentials#credential-types`)

> "Boundary supports several credential types to accommodate different authentication methods:
> - **Username password**: Basic username and password authentication
> - **Username password domain**: Username, password, and domain for Windows
>   environments that use Active Directory authentication
> - **SSH private key**: SSH private key authentication
> - **SSH certificate**: SSH certificate-based authentication
> - **JSON**: Flexible JSON-based credential storage"

### 2.6 Vault credential library subtypes (from /boundary/docs/credentials/static-cred-vault + CHANGELOG)

- `vault-generic` — generic KV/static secret read (subtype was renamed from
  `vault` in Boundary 0.13.0; `vault` still accepted but deprecated).
- `vault-ssh-certificate` — **new credential library that uses the Vault SSH
  secret engine to generate SSH private key and certificates** (added in
  Boundary **0.13.0**, PR #2860). Can be used as an injected application
  credential source for targets that support credential injection.

CLI to create one (with username_password credential type as example):

```
$ boundary credential-libraries create vault-generic \
    -name "vault-cred-lib-test" \
    -credential-store-id csvlt_Xqa6V6QwfM \
    -credential-type username_password \
    -vault-path "path/to/vault/credentials"
```

### 2.7 Static (Boundary-native) credential store (/boundary/docs/credentials/static-cred-boundary)

Boundary also ships its own static credential store (no Vault required). Same
five credential types as 2.5, stored directly in Boundary's database. These are
not "dynamic" — they are static secrets managed by Boundary, but the same target
can attach them as injected application credentials (subject to the same
Enterprise-only constraint).

---

## 3. VAULT — SSH SECRETS ENGINE

Source index: https://developer.hashicorp.com/vault/docs/secrets/ssh

> "The Vault SSH secrets engine provides secure authentication and authorization
> for access to machines via the SSH protocol. The Vault SSH secrets engine helps
> manage access to machine infrastructure, providing several ways to issue SSH
> credentials.
>
> The Vault SSH secrets engine supports the following modes. Each mode is
> individually documented on its own page.
> - Signed SSH Certificates
> - One-time SSH Passwords"

### 3.1 CRITICAL — "dynamic keys" feature was REMOVED in Vault 1.13

From the SSH engine index page (verbatim):

> "Removal of dynamic keys feature
>
> Per Vault 1.12's deprecation notice page, the dynamic keys functionality of
> this engine has been removed in Vault 1.13."

This means the historical "dynamic SSH keys" mode (Vault dynamically creating
ephemeral user accounts on the target host) **no longer exists in current Vault
versions**. The only two current modes are OTP and signed certificates.

### 3.2 One-time SSH Passwords (OTP) —
https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords

> "The One-Time SSH Password (OTP) SSH secrets engine type allows a Vault server
> to issue a one-time password every time a client wants to SSH into a remote
> host using a helper command on the remote host to perform verification.
>
> An authenticated client requests credentials from the Vault server and, if
> authorized, is issued an OTP. When the client establishes an SSH connection to
> the desired remote host, the OTP used during SSH authentication is received by
> the Vault helper, which then validates the OTP with the Vault server. The
> Vault server then deletes this OTP, ensuring that it is only used once.
>
> Since the Vault server is contacted during SSH connection establishment, every
> login attempt and the correlating Vault lease information is logged to the
> audit secrets engine."

> "Drawbacks: The main concern with the OTP secrets engine type is the remote
> host's connection to Vault; if compromised, an attacker could spoof the Vault
> server returning a successful request. This risk can be mitigated by using TLS
> for the connection to Vault and checking certificate validity; future
> enhancements to this secrets engine may allow for extra security on top of
> what TLS provides."

Quick-start (verbatim commands):
```
$ vault secrets enable ssh

$ vault write ssh/roles/otp_key_role \
    key_type=otp \
    default_user=username \
    cidr_list=x.x.x.x/y,m.m.m.m/n

$ vault write ssh/creds/otp_key_role ip=x.x.x.x
# returns: key (the OTP), port, username, ip, key_type=otp
# lease_duration 600, lease_renewable false

$ vault ssh -role otp_key_role -mode otp username@x.x.x.x
# requires sshpass to be installed for full automation
```

OTP roles are gated by `cidr_list`, so the same role is not usable from any
uncontrolled source IP.

### 3.3 Signed SSH certificates —
https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates

> "The signed SSH certificates is the simplest and most powerful in terms of
> setup complexity and in terms of being platform agnostic. By leveraging
> Vault's powerful CA capabilities and functionality built into OpenSSH,
> clients can SSH into target hosts using their own local SSH keys.
>
> When using the signed SSH certificates, an SSH CA signing key is generated or
> configured at the secrets engine's mount. This key will be used to sign other
> SSH keys."

This is the path used by the **Boundary `vault-ssh-certificate` credential
library** (added in Boundary 0.13.0) to inject an SSH certificate into a
session.

### 3.4 SSH secrets engine API
https://developer.hashicorp.com/vault/api-docs/secret/ssh

The two relevant credential paths in the current engine:
- `ssh/creds/<role>` -> returns an OTP lease
- `ssh/sign/<role>` -> returns a signed SSH certificate

---

## 4. VERSION NOTES (from the live Boundary CHANGELOG)

Source: https://raw.githubusercontent.com/hashicorp/boundary/main/CHANGELOG.md
(Latest release visible in file: **0.21.3**, 2026/04/28. Latest tag on GitHub:
v0.21.3.)

### 4.1 SSH + credential injection release history (chronological)

| Boundary version | Date | Change relevant to SSH / injection |
|---|---|---|
| **0.15.0** (2022) | Initial release | "**`ssh` Target Type With Credential Injection (HCP Boundary only):** Boundary has gained a new `ssh` target type. Using this type, username/password or SSH private key credentials can be sourced from `vault` credential libraries or `static` credentials and injected into the SSH session between a client and end host. This allows users to securely SSH to remote hosts while never being in possession of a valid credential for that target host." — This is the first SSH-injection support. |
| 0.15.0 | same | "**SSH Private Key Credentials:** There is now an `ssh_private_key` credential type that allows submitting a username/private key (and optional passphrase) to Boundary for use with credential injection or brokering workflows." |
| 0.15.0 | same | "`boundary connect ssh` Credential Brokering Enhancements: …the command will automatically pass the credentials to the `ssh` process" |
| **0.13.0** (2023/06/13) | 2023/06/13 | "**Vault SSH certificate credential library:** A new credential library that uses the vault ssh secret engine to generate ssh private key and certificates. The library can be used as an injected application credential source for targets that support credential injection. ([PR #2860])" — Adds signed-cert path via the SSH engine. |
| 0.13.0 | 2023/06/13 | "**SSH Session Recordings (Enterprise and HCP Boundary only):** SSH targets can now be configured to record sessions. Recordings are signed and stored in a Storage Bucket." |
| 0.18.0 | 2024 | "The `key_id` parameter within SSH Certificate Credential Libraries now accepts additional valid principals when creating a vault ssh signed cert credential" |
| 0.19.0 | 2024 | (Page ref): "Vault SSH Certificate credential library" (further enhancements) |
| **0.20.0** | 2025/09/25 | "**Added support for RDP targets and RDP credential injection** for connecting to Windows machines. RDP credential injection supports both NTLM and Kerberos authentication." **Added new credential type for username, password, and domain credentials.** |
| **0.21.0** | 2025/12/11 | "**Added support for host key verification when connecting to an SSH target by providing a `known_hosts` file.** ([PR #6263])" — This is a notable SSH-only security enhancement: Boundary worker now verifies target host key against a `known_hosts` file, not just blindly accepting. |
| 0.21.0 | same | "Vault LDAP has been added as a credential provider" |
| 0.21.0 | same | "Added new credential type for password." |

### 4.2 What is NOT supported (from explicit "not supported" calls in current docs, v0.21.x)

- **Keyboard-interactive authentication is not supported** for SSH credential
  injection. Server must allow password auth if username/password is used.
- **TCP targets** do not support credential injection (only SSH and RDP do).
- Public-key injection for SSH is listed as supported ("Usernames and public
  keys") but is bound to what the underlying SSH target supports.

---

## 5. INTEGRATION PICTURE (Boundary + Vault)

End-to-end SSH-credential-injection flow when a Vault credential store is
attached to an SSH target:

1. User runs `boundary connect ssh -target-id <id>` (or uses the Desktop client).
2. Boundary controller authorizes the user against the target.
3. Controller calls Vault to issue a credential from the configured
   `vault-ssh-certificate` library (or `vault-generic` for username/password):
   - For signed-cert path: Vault signs the user's public key (or issues a fresh
     key/cert pair) via the SSH engine.
   - For OTP path: Vault would issue an OTP — but **note that OTP is not how
     the Boundary `vault-ssh-certificate` library consumes the engine; that
     library specifically uses signed certificates**.
4. The credential is returned to the **worker** (never to the user).
5. Worker establishes the SSH session and authenticates on the user's behalf.
6. Optional (Enterprise): entire session is recorded (BSR / asciicast) and
   stored in an S3 storage bucket.
7. On session termination, the Vault lease is revoked (for dynamic / signed
   credentials), making the credential single-use.

---

## 6. FILES SAVED LOCALLY

- `/tmp/hashicorp-docs/*.html` — raw fetched HTML (10 docs)
- `/tmp/hashicorp-docs/md/*.md` — pandoc-converted Markdown
- `/home/dan.rohan/hashicorp-ssh-docs-report.md` — this report
