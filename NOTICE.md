# Third-party notices

The native CLR host patterns are derived from:

- Adaptix-Framework/Extension-Kit
- `Execution-BOF/execute-assembly/inlineExecute-Assembly.c`
- `Execution-BOF/execute-assembly/inlineExecute-Assembly.h`

That project is licensed under GPL-3.0. Its license is included as `LICENSE`.

Section-map / remote-thread injection ideas are informed by Extension-Kit
`Injection-BOF/inject_sec` (also GPL-3.0).

The managed PowerShell host is written for this project. It uses the public
`System.Management.Automation` API but does not redistribute the Microsoft
assembly used as a build-time reference (`SMA_REF`).
