# PowerPick-Fork (Adaptix)

Fork-and-run PowerShell for AdaptixC2 agents. Runs the SMA host inside a
**sacrificial Microsoft-signed process** so a CLR / PowerShell crash does not
kill the agent.

This tree is separate from inline PowerPick (`powerpick-bof`).

## How it differs from inline PowerPick

| | Inline PowerPick | PowerPick-Fork |
|---|---|---|
| Where CLR runs | Inside the agent process | Sacrificial `rundll32` process |
| Crash impact | Can kill the agent | Sacrificial process dies; agent continues |
| Vessel | Agent image | Default `rundll32.exe` (configurable) |
| Session imports | `powerpick-load` / `--imports` | `powerpick-fork-load` / `--imports` |

## OPSEC

Not built with OPSEC in mind, but just the basic theory.

1. **Sacrificial host** = Microsoft-signed `rundll32.exe` (default
   `C:\Windows\System32\rundll32.exe`).
2. Host DLL is staged briefly under `%TEMP%` and started as
   `rundll32.exe "<dll>",PowerPickForkRun <mapName>` (normal export call — no
   suspended `CreateRemoteThread` inject). Inject-into-`RuntimeBroker` was
   dropped after consistent `0xC0000005` crashes under LoadLibrary-in-suspended-process.
3. **Do not** use `powershell.exe` / `cmd.exe` as the vessel.
4. **Output** returns over a randomly named **mailslot**. Managed PE + args live
   in a local file mapping whose name is passed on the rundll32 cmdline.
5. **PPID spoof** / true RuntimeBroker hollow-inject remain follow-ups.

Override the rundll32 path:

```text
powerpick-fork --spawnto C:\Windows\System32\rundll32.exe "Get-Date"
```

If `--spawnto` is not `rundll32.exe`, the BOF falls back to System32 `rundll32`
and prints a note.

Lab / authorized testing only.

## Command

```text
powerpick-fork [--imports] [--spawnto PATH] <powershell>
powerpick-fork-load /path/to/script.ps1 [name]
powerpick-fork-loads (Checks what scripts been loaded.)
powerpick-fork-unload <name|all>
```

Examples:

```text
powerpick-fork "Get-Date"
powerpick-fork ls
powerpick-fork --spawnto rundll32.exe "Get-Date"

powerpick-fork-load ~/opt/PowerView.ps1
powerpick-fork-load ~/opt/PowerView.ps1 recon
powerpick-fork --imports Get-ComputerInfo
```

`powerpick-fork-load` defaults the import name to the script basename
(`PowerView.ps1` → `powerview`). Pass a second argument to override. Reloading the
same name replaces the cached body.

`--imports` re-applies every session-loaded script into a **fresh** runspace in the
sacrificial process before the command. Script bodies are cached on the agent by
`powerpick-fork-load`; `--imports` only sends import names on the wire.

`--spawnto` / `--imports` are parsed from the raw command line. A bare spawnto
image name is expanded under `C:\Windows\System32\`.

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
| `powerpick-fork.axs` | Operator command |

Load `powerpick-fork.axs` in Adaptix. Registered for beacon / gopher / kharon,
Windows x64.
