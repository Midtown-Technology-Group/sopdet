# Sopdet Device Inventory (read-only)

A single-file, read-only Windows inventory collector for assessment and
onboarding. It gathers hardware, operating system, software, security, and
network facts, packages them as a versioned JSON envelope, and either posts
them to your Bifrost ingest endpoint or writes them to a local file.

It does **not** install anything, start a service, create a scheduled task,
change configuration, or require administrator rights.

## Contents

```
Run-Me.cmd                     Double-click friendly launcher (writes last-run.json)
Invoke-SopdetInventory.ps1    The collector (Windows PowerShell 5.1+)
inventory.config.sample.json   Configuration template
inventory.schema.json          Machine-readable schema for review/validation
WHAT-IT-COLLECTS.md            Plain-language field list and guarantees
AUTHORIZATION.template.txt     Scope/consent template
samples/sample-output.json     Example output from a `-DryRun` run
MANIFEST.sha256                SHA-256 of every packaged file
tools/New-SignedPackage.ps1         Sign the collector and regenerate the manifest
tools/Invoke-SopdetFanout.ps1  Guarded, operator-driven deployment to a target list
```

## Requirements

- **Windows PowerShell 3.0+** — native on Windows 8 / Server 2012 and later;
  Windows 7 SP1 / Server 2008 R2 need WMF 3+ (WMF 5.1 recommended).
- No elevated rights for normal use.
- Compatibility is enforced by `powershell/analyzer-settings.psd1`
  (run `make compat-check`).
- Outbound HTTPS to your Bifrost endpoint (or none, in file-drop mode).
- Optional: a proxy, if the environment requires one.

## Quick start (no admin)

1. Copy this folder to the machine.
2. Double-click `Run-Me.cmd`, or run:

```powershell
Unblock-File .\Invoke-SopdetInventory.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SopdetInventory.ps1 -Profile quick -DryRun -OutputPath .\device.json
```

`-DryRun` collects and writes a local JSON file but sends nothing and changes
nothing on the machine.

## Delivery modes

- **Direct ingest**: set `endpoint` and `apiKey` in `inventory.config.json`.
  The collector gzips the envelope, splits it into chunks, POSTs each chunk
  with retries and exponential backoff, and spools anything undelivered to
  `%LOCALAPPDATA%\Sopdet\spool\` for the next run to drain.
- **File-drop**: leave `endpoint` empty and use `-DryRun -OutputPath <file>`.
  Nothing leaves the machine; return the file to your assessor. No key needed.

## Configuration

Copy `inventory.config.sample.json` to `inventory.config.json` (the collector
loads it automatically when present; a path can be given with `-Config`).
Explicit command-line arguments override the file.

| Key | Meaning | Default |
|---|---|---|
| `endpoint` | Bifrost ingest endpoint URL | none (file-drop) |
| `apiKey` | Per-engagement ingest key (`X-Bifrost-Key`) | none |
| `profile` | `minimal` \| `quick` \| `full` | `full` |
| `includeAppx` | Include Store/UWP packages (slower) | false |
| `includeProcesses` | Include running processes (PII-heavy) | false |
| `compress` | gzip+base64 the payload | false |
| `delta` | Send only changes after a baseline snapshot | false |
| `chunkBytes` | Max chunk size (base64 chars) | 900000 |
| `maxRetries` | Retry attempts per chunk | 4 |
| `maxListItems` | Cap per collection | 2000 |
| `proxy` | Explicit proxy URL | none |
| `statePath` | Delta state file | `%LOCALAPPDATA%\Sopdet\state.json` |
| `dryRun` | Collect only, write file, send nothing | false |

## Profiles

- `minimal`: identity, OS, hardware, virtualization, secure boot, UAC, AV,
  firewall, volumes, network. Fast.
- `quick`: minimal + BIOS, CPU, memory modules, GPU, TPM, software, patches,
  users, batteries, printers.
- `full`: everything, including services, startup items, drivers, physical
  disks, listening ports, monitors, USB devices.

## Integrity and signing

```powershell
Get-FileHash .\Invoke-SopdetInventory.ps1 -Algorithm SHA256   # compare to MANIFEST.sha256
```

To sign the collector and refresh the manifest with your code-signing cert:

```powershell
.\tools\New-SignedPackage.ps1 -CertificateThumbprint <THUMBPRINT>
```

## Privacy and scope

The payload contains device and user identifiers, installed software, network
configuration, and security posture. Treat it as personal data. Run it only on
assets covered by a signed authorization (`AUTHORIZATION.template.txt`) and per
your data-handling agreement. Delete `last-run.json`, `last-run.log`, and
`%LOCALAPPDATA%\Sopdet\` when the engagement closes.
