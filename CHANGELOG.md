# Changelog

All notable changes to Sopdet are documented here. The format is based on
Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- **Heartbeat `agent_version` + `SOPDET_DISABLE_HINTS`** (device control
  plane `Midtown-Technology-Group/bifrost#818`, poll-only drill `#852`):
  every heartbeat now carries the build version (`main.Version`, ldflag-
  overridden) as `agent_version`, sanitized (control characters stripped)
  and truncated to the platform's 64-wide column; an empty version omits
  the field instead of sending `""`, so the runbook's "agent_version set"
  check reflects a real build. New environment-only knob
  `SOPDET_DISABLE_HINTS` (`1`/`true`/`yes`/`on`, case-insensitive) resolves
  `ServeConfig.EnableHints` to false, so the WebSocket hint channel does
  not start and the agent claims over the HTTP poll alone for the M6.3
  poll-only drill. Hints remain enabled by default.
- **Serve orchestration loop** (`internal/agent/loop.go`, M3.5 #842):
  `sopdet -serve` now actually serves — WS hint or timed claim poll (server
  poll hint honoured), **max one concurrent job**, heartbeat every 30s that
  renews activity, drains the spool, and observes the cooperative-cancel
  flag. Job outcomes follow the frozen rules: real-spawn `running` report
  before logs, timeout/failed/succeeded results, **fenced rejections
  accepted with no local re-run**, shutdown mid-job leaves `running` for
  the server's `lost` policy (nothing posted), cooperative cancel kills the
  local tree and posts `cancelled`. Startup sweeps stale spool files. The
  `-serve` placeholder is replaced by the real loop; integration-tested
  against a mock Bifrost lifecycle (httptest).
- **WebSocket hint loop** (`internal/agent/ws.go`, M3.3 #840): derives
  `wss(s)://<base>/ws/connect` with **`Authorization: Bearer` header only**
  (no query credential, ever), explicitly subscribes to `device:{id}`,
  dispatches `device_job_available` hints to a callback (HTTP claim stays
  authoritative), and reconnects with capped exponential backoff + jitter
  honouring context cancellation. When the socket is down the heartbeat's
  poll interval is the fallback — hint and poll both reach claim. New
  dependency: `github.com/coder/websocket`.
- **Device protocol HTTP client + durable result/log spool**
  (`internal/agent/client.go`, M3.2 #839): `Heartbeat` (poll hint +
  cooperative-cancel flag), `Claim` (frozen claim-response shape; 204 =
  idle), `ReportRunning` (additive spawn-report route from Bifrost #874 —
  feedback #1), fenced `PostLogs` (idempotent seq batches) and
  `ReportResult`, all with retry/backoff on network/5xx errors (4xx never
  retried), `X-Bifrost-Key` on every call, and structured error envelopes.
  Fence/terminal rejections surface as `ErrFenced` — the agent accepts the
  server verdict and **never re-runs locally**. Transient failures spool
  payloads to disk (mode `0600`; installer DACL on Windows) with
  `DrainSpool` on reconnect (fenced records are dropped, never replayed
  against a terminal job) and `SweepSpool` enforcing the M0 7-day
  retention window.
- `scripts/Deploy-Sopdet.ps1`: Windows deployment entry point that installs the
  agent from the GitHub release, verifies SHA-256 against `MANIFEST.sha256`, and
  runs a one-shot scan or serve mode. Secrets read from `SOPDET_*` env vars so
  NinjaOne need not pass them on the command line. Verified end-to-end on a
  Server 2019 host (checksum match, scan delivered).
- Resident **serve mode scaffold** (`-serve`) for the Bifrost device control
  plane (MTG Bifrost epic #818 / sopdet M3.1): `-bifrost-url`, `-device-key`
  (env `SOPDET_DEVICE_KEY`), `-enroll-token` (env `SOPDET_ENROLLMENT_TOKEN`),
  `-serve-state`, `-poll-interval`, `-work-dir`, and optional `-serve-config`
  JSON (flags > env > file). First run exchanges a single-use `bfen_`
  enrollment token at `POST /api/devices/enroll` for the `bfdk_` device key
  and persists it (mode `0600`; installer DACL on Windows). Serve refuses to
  start without a URL plus a key or enrollment token. Secrets never appear in
  logs or errors. The claim/run loop arrives with M3.5; inventory mode is
  unchanged.
- **PowerShell runner** (`internal/agent.Runner`, M3.4): temp script file with
  UTF-8 BOM, `powershell.exe -NoProfile -NonInteractive -File`, context
  timeout with process-tree kill (taskkill `/T /F` on Windows), combined
  stdout/stderr byte cap with truncation, size/interval log batching
  (32 KiB / 500 ms), a globally monotonic log `seq`, and a **spawn-ordered
  running notification** — `onStart` fires exactly once after a real
  `cmd.Start` and before any log entry, so the platform can distinguish
  safe reclaim from `lost` (feedback #1). Standalone-testable without
  network; inventory mode unchanged.
- Rolling unsigned download channel: every push to `main` republishes the public
  tier to a stable `unsigned-latest` GitHub release, giving permanent
  `/releases/latest/download/<asset>` URLs (no SAS expiry). See the README
  "Download (unsigned)" section.
- Provisioned Azure Artifact Signing: Basic-SKU account `mtg-sopdet-signing`
  (`eastus`, endpoint `https://eus.codesigning.azure.net/`) in
  `rg-sopdet-signing`, with the signed-in user granted the Artifact Signing
  Identity Verifier role. Identity validation and certificate-profile creation
  remain (portal). See [docs/signing.md](docs/signing.md).
- Progress and branding: every run now emits a shared event stream rendered by
  a branded terminal reporter (banner, live progress meter, per-collector lines,
  summary; plain-log fallback when not a TTY or with `-quiet`) and, with `-ui`,
  by a loopback-only web page. The page is token-gated, needs no external
  runtime, streams over Server-Sent Events, and replays the run for late
  connections.
- PowerShell collector now targets **Windows PowerShell 3.0** (Windows 7 SP1 /
  Server 2008 R2 with WMF 3+ through Windows 11): .NET 4.0-safe GZip constructor,
  registry firewall-profile fallback when `Get-NetFirewallProfile` is absent, and
  a PSScriptAnalyzer compatibility gate (`make compat-check`).
- Fix: legacy PowerShell 3.0/4.0 `ConvertTo-Json` throws on string values ending
  in a backslash (Windows paths). The pretty payload now falls back to the
  compressed form, which is unaffected; validated on Server 2012 R2 (PS 4.0) and
  Server 2012 (PS 3.0).
- Fix: legacy PowerShell 3.0 ignores a `Content-Type` supplied via
  `-Headers` on `Invoke-RestMethod`, so the ingest POST was rejected and chunks
  were spooled. The request now sets the `-ContentType` parameter, restoring
  direct ingest from Server 2012 (PS 3.0) — 21 entities delivered.

- Release workflow (`.github/workflows/release.yml`): tag `v*` builds all
  platforms, optionally signs the Windows binaries with Azure Artifact Signing
  (Public + Private Trust) when Azure OIDC secrets are configured, publishes the
  public tier as a GitHub Release, and keeps the private tier as a workflow
  artifact.
- Windows collector parity: volume encryption (BitLocker), monitor EDID detail
  with Win32_DesktopMonitor fallback, antivirus threat detections, running
  processes (gated by `-include-processes`), and RAID/SCSI controllers.
- Linux collectors: DMI BIOS, virtualization, Secure Boot, TPM, local users,
  listening ports, and multi-distro software (dpkg, rpm, pacman, apk).
- macOS collectors: hardware/serial/UUID (system_profiler + ioreg), BIOS/firmware,
  virtualization, installed applications, and graphics.

## [0.1.0] - 2026-09-20

### Added

- Go agent (`cmd/sopdet`) emitting the schema v2 inventory envelope:
  - cross-platform collectors via gopsutil (host, os, hardware, volumes, network)
  - Windows collectors via registry and WMI (os, hardware, virtualization,
    secure boot, UAC, firewall profiles, processors, memory modules, graphics,
    BIOS/board/chassis, TPM, OS patches, local users, logged-on users, printers,
    batteries, antivirus, services, drivers, physical disks, listening ports,
    USB devices, startup items, monitors, AppX packages)
  - delta mode with per-device fingerprint state (`sha256-canonical-json/v1`)
  - gzip + entity-boundary chunking + retry/backoff + durable spool ingest
  - payload size budgeting with `summarized`/`omitted` provenance
- PowerShell assessment package (`powershell/`): no-admin single-file collector,
  config file, launcher, schema, consent template, guarded one-hop fan-out, and
  signing tooling (PSScriptAnalyzer clean).
- Shared contract `schema/inventory.schema.json`, validated in tests.
- Distribution tooling: Azure Artifact Signing provisioning, Public/Private
  trust signing, publish tiers, and a supplemental App Control policy builder.
