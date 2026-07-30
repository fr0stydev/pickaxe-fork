# PowerPick-Fork (Adaptix)

Fork-and-run PowerShell for AdaptixC2 agents via Unmanaged Powershell.
Lab / authorized testing only.

This tree is separate from inline PowerPick (`powerpick-bof`). Operator commands
are the same (`powerpick`, `powerpick-load`, …) — **load only one** of the two
AxScripts at a time.

## OPSEC

Not built with OPSEC in mind, but just the basic theory.

The managed host applies a best-effort content-scan neutralize before SMA
execution (helps with AMSI script blocking). It does **not** defeat ETW,
script-block logging, or behavioral AV on `rundll32` / CLR load.

**Managed PE:** loaded from the named mapping via `AppDomain::Load_3` +
`EntryPoint`/`Invoke_3` (no managed EXE on disk). Hosted Havoc PowerPick-style.

**Host DLL:** preferred path reflectively maps the host into a suspended
`rundll32` (no host DLL on disk; imports resolved only inside the child).
Falls back to a short-lived temp DLL + classic `rundll32` export if reflect fails.


## Command

```text
powerpick [--imports] [--impersonate] [--spawnto PATH] <powershell>
powerpick-load /path/to/script.ps1 [name]
powerpick-loads
powerpick-unload <name|all>
```

Examples:

```text
powerpick "Get-Date"
powerpick ls
powerpick --spawnto rundll32.exe "Get-Date"
powerpick --impersonate whoami
powerpick --imports --impersonate Get-DomainComputer

powerpick-load ~/opt/PowerView.ps1
powerpick-load ~/opt/PowerView.ps1 recon
powerpick --imports Get-ComputerInfo
```

`powerpick-load` defaults the import name to the script basename
(`PowerView.ps1` → `powerview`). Pass a second argument to override. Reloading the
same name replaces the cached body.

`--imports` re-applies every session-loaded script into a **fresh** runspace in the
sacrificial process before the command. Script bodies are cached on the agent by
`powerpick-load`; `--imports` only sends import names on the wire.

`--impersonate` spawns the sacrificial process with
`CreateProcessWithTokenW` (falls back to `CreateProcessAsUser`) using the
agent thread’s current impersonation token (e.g. after `steal_token` /
`make_token`). Requires `SeImpersonatePrivilege` on the agent. Without the
flag, the child runs as the agent’s primary identity; if a thread token is
present it is temporarily reverted for the spawn so the agent does not crash.

`--spawnto` / `--imports` / `--impersonate` are parsed from the raw command line.
A bare spawnto image name is expanded under `C:\Windows\System32\`.
(`--spawnto` / `--impersonate` are fork-only.)

## Layout

```text
powerpick-fork/
  powerpick-fork.axs
  Makefile / Dockerfile
  NOTICE.md / LICENSE
  include/          # beacon.h, BOF decls, CLR COM headers
  native/           # agent BOF + sacrificial host DLL
  managed/          # PowerPickFork.exe (SMA exec host)
  _bin/             # build outputs
```

## Build

Requires MinGW-w64 (`x86_64-w64-mingw32-gcc`), Mono `mcs`, and a compile-only
reference to `System.Management.Automation.dll`:

```bash
export SMA_REF=/path/to/System.Management.Automation.dll
make all
```

Docker:

```bash
docker build -t powerpick-fork .
docker run --rm -v "$PWD":/src/powerpick-fork \
  -e SMA_REF=/src/powerpick-fork/SMA/System.Management.Automation.dll \
  powerpick-fork
```

Artifacts:

| File | Role |
|---|---|
| `_bin/powerpick-fork.x64.o` | Agent BOF |
| `_bin/PowerPickForkHost.dll` | rundll32-hosted CLR host |
| `_bin/PowerPickFork.exe` | Managed `exec <base64>` runner |
| `powerpick-fork.axs` | Operator commands (`powerpick` …) |

Load `powerpick-fork.axs` in Adaptix. Registered for beacon / gopher / kharon,
Windows x64.
