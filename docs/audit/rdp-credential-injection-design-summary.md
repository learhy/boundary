# RDP Credential Injection (AD) — Design Summary

Extracted from staff-eng task t_035ca404 completion summary.

**Linux**: `defaultExec()` returns `"xfreerdp"`; `buildArgs` passes `/u:<username> /p:<password> /v:<addr>` directly on the CLI. LookPath check in `handleExec` before running; install hint printed if not found.

**Windows**: `buildArgs` runs `cmdkey.exe /generic:<addr> /user:<username> /pass:<password>` before launching `mstsc.exe /v <addr>`. Cleanup registered: `cmdkey.exe /delete:<addr>`.

**Credential validation**: exactly 1 `UsernamePassword` consumed; `ssh_private_key` and other types error with clear message. 0 creds → proceed without injection (client prompts).

**Completion**: `rdpOptions` completion set expanded to include `"xfreerdp"`.

**Non-AD as non-goal**: the design accepts any `UsernamePassword` — AD vs non-AD distinction is not in the target model, and injection is harmless on non-AD targets (RDP server handles validation).

**Worker-hosted RDP**: explicitly out of scope — the design covers CLI-with-`-exec` (user-local client) only.
