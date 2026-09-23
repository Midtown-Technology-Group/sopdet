# Sopdet

Read-only device inventory for assessment and fleet reporting, in two
implementations that share one JSON contract:

- **Go agent** (this directory) — a single static binary for Windows, Linux, and
  macOS that collects a schema-validated envelope and delivers it to a Bifrost
  ingest endpoint (gzip + chunking + retry + durable spool) or to a local file.
- **PowerShell package** ([`powershell/`](powershell/README.md)) — a single-file,
  no-admin collector and prospect-ready assessment package (launcher, config,
  schema, consent template, signing/fan-out tooling). PSScriptAnalyzer clean.

The Go agent also has an optional resident **[`-serve` mode](#serve-mode-device-control-plane)**
for the Bifrost device control plane: it holds a per-device key and (once the
job loop lands) runs operator-authorized ad-hoc PowerShell. Inventory collection
stays read-only; serve mode is a documented privilege change — see
[Trust boundary](#trust-boundary).

Named for **Sopdet**, the Egyptian star whose heliacal rising was the observed
signal that timed the Nile flood — *read the signal, record the state.*

## Layout

```
cmd/sopdet/                 Go CLI entry point
internal/agent/             serve mode: config, enrollment, runner (device control plane)
internal/schema/            envelope types, canonical fingerprints, entity builder
internal/collect/           collector interface, gopsutil base collectors,
                            Windows WMI + registry, Linux dpkg
internal/state/             delta fingerprints (key -> hash)
internal/ingest/            gzip, entity-boundary chunking, retry/backoff, spool
internal/config/            config file
internal/app/               orchestration
schema/inventory.schema.json    the shared contract
testdata/                   schema-validation fixture (synthetic)
powershell/                 PowerShell assessment package
scripts/                    signing + publish tooling
Makefile, .github/workflows/ci.yml
```

## Build

```sh
make build      # bin/sopdet (host)
make cross      # windows/linux/darwin, amd64+arm64
make test       # unit + schema-validation tests
make vet
```

## Run (Go agent)

```sh
./bin/sopdet -profile minimal -dry-run -out device.json
./bin/sopdet -config inventory.config.json
./bin/sopdet -endpoint https://bifrost.example.com/api/endpoints/<id> \
    -api-key <key> -profile quick -compress -delta
```

Flags override the config file; a missing `inventory.config.json` next to the
binary is loaded automatically.

| Flag | Meaning |
|---|---|
| `-config` | config file path |
| `-profile` | `minimal` \| `quick` \| `full` |
| `-endpoint` / `-api-key` | Bifrost ingest endpoint and key |
| `-out` | write the envelope to a file |
| `-compress` | gzip+base64 the payload |
| `-delta` | send only changes after a baseline snapshot |
| `-dry-run` | collect only; never post |
| `-proxy`, `-state` | proxy URL, delta state file |
| `-include-appx`, `-include-processes` | extra entities |
| `-ui` | serve a local branded progress page for this run |
| `-ui-port` | fixed port for the page (default: random) |
| `-no-browser` | do not auto-open the page |
| `-quiet` | suppress the banner and per-entity progress |

### Progress and branding

Every run reports progress on the terminal: a branded banner, a live progress
meter, one line per collector, and a completion summary. When stdout is not a
terminal (or with `-quiet`) it degrades to plain log lines, so CI and captured
output stay readable.

`-ui` additionally serves a local web page with the same branding and a live
collector view:

```sh
./bin/sopdet -profile quick -ui -dry-run
```

The page is bound to `127.0.0.1` on a random port and gated behind a one-time
token in the URL; nothing is exposed off-host and no external runtime is
required (no WebView2). Progress streams over Server-Sent Events, and late
connections replay the run from the start, so opening the page after a scan
still shows the full result. The page stays up briefly after the run so the
summary can be read.

![Sopdet progress page](docs/ui.png)

## Serve mode (device control plane)

`sopdet -serve` prepares the resident agent identity for the Bifrost device
control plane (ad-hoc PowerShell over a WebSocket-connected agent; platform
contract: [`device-control-plane.md`](https://github.com/Midtown-Technology-Group/bifrost/blob/main/docs/architecture/device-control-plane.md)).
**Current state:** config, single-use enrollment, and device-key persistence
(M3.1); the claim/run loop arrives with M3.5.

```sh
# First run: mint a one-time enrollment token in Bifrost, then:
sopdet -serve -bifrost-url https://bifrost.example.com -enroll-token bfen_<id>_<secret>

# Subsequent runs reuse the persisted device key:
sopdet -serve -bifrost-url https://bifrost.example.com
```

| Flag | Meaning |
|---|---|
| `-serve` | resident serve mode (skips inventory collection) |
| `-bifrost-url` | Bifrost base URL (env `SOPDET_BIFROST_URL`); **https**, http only on loopback |
| `-device-key` | raw device key (env `SOPDET_DEVICE_KEY`); secret — never logged |
| `-enroll-token` | one-time `bfen_` enrollment token (env `SOPDET_ENROLLMENT_TOKEN`) |
| `-serve-state` | device-state path (env `SOPDET_SERVE_STATE`; default under the user config dir) |
| `-poll-interval` | HTTP claim poll interval while WS is down (env `SOPDET_POLL_INTERVAL`, default 10s) |
| `-work-dir` | working directory for per-job script temp files (env `SOPDET_WORK_DIR`) |
| `-serve-config` | optional JSON config (flags > env > file) |

Serve refuses to start without a URL plus either a device key or an enrollment
token. The one-time token is exchanged at `POST /api/devices/enroll`; the raw
device key is returned once and persisted mode `0600` (the M5 installer adds a
SYSTEM/Administrators DACL on Windows). Keys and tokens never appear in logs or
error messages.

### Trust boundary

Inventory mode remains **read-only, no elevation** (see
[`WHAT-IT-COLLECTS.md`](WHAT-IT-COLLECTS.md)). Serve mode changes the trust
boundary: the agent becomes a **resident runner for operator-authorized
PowerShell** on the device.

- **Service identity:** LocalSystem by default on Windows (v1 has no alternate
  identity and no `run_as` impersonation).
- **Install / update / uninstall:** delivered and updated only via the M5 Ninja
  bootstrap (pinned, checksum-verified binary); uninstall removes
  binary/service/config/spool and leaves no key material. No in-agent
  auto-update.
- **Signing tiers:** [Private Trust](#distribution-tiers) for the managed
  fleet and any hardened/WDAC endpoint; **unsigned + manifest is canary-only**
  — a binary and a manifest from the same source are not authenticity proof.
  See [`docs/signing.md`](docs/signing.md) and
  [`docs/appcontrol.md`](docs/appcontrol.md).
- **Data handling:** device key hashed at rest server-side, stored client-side
  at `0600`/DACL; agent spool is `0600`/DACL and cleared after successful post;
  script bodies and logs are never written to sopdet's own logs.

## Platform support

| Platform | Agent |
|---|---|
| Windows 10 / Server 2016+ | Go agent (cross-compiled) |
| Windows 7 SP1 / Server 2008 R2 – Server 2012 R2 | PowerShell package (PowerShell 3.0+, WMF 3+) |
| Linux | Go agent |
| macOS | Go agent |

The Go toolchain requires Windows 10/Server 2016+ (Go 1.21+ dropped older
Windows); the PowerShell package covers legacy endpoints down to PowerShell 3.0
and shares the same contract, so `device_inventory` remains uniform.

## Contract

One envelope per scan. Every entity record carries a stable `key`, a content
`fingerprint`, and `observed_at`. Sections that cannot be read are reported in
`entity_errors` (with `gated: true` for access-denied) rather than guessed. See
[`schema/inventory.schema.json`](schema/inventory.schema.json) and
[`WHAT-IT-COLLECTS.md`](WHAT-IT-COLLECTS.md).

Modes: `action=snapshot` (full), `action=delta` (added/changed/removed after a
baseline), per-entity transport chunks (`chunk`), and `-MaxPayloadBytes` size
budgeting with `summarized`/`omitted`.

**Fingerprint parity:** Go uses `sha256-canonical-json/v1` and is *not*
byte-identical to the PowerShell agent's canonicalization, so delta state is not
shared across implementations — run the first Go scan as a fresh baseline.

## Distribution tiers

| Tier | Signature | Audience |
|---|---|---|
| `publish-public` | unsigned **and** Public Trust | prospects / assessment |
| `publish-private` | Private Trust | managed fleet |

### Download (unsigned)

Every push to `main` republishes the public tier to the rolling
[`unsigned-latest`](https://github.com/Midtown-Technology-Group/sopdet/releases/tag/unsigned-latest)
release, so these URLs are stable:

| Platform | Asset |
|---|---|
| Windows x64 | `sopdet-windows-amd64.exe` |
| Windows arm64 | `sopdet-windows-arm64.exe` |
| Linux x64 | `sopdet-linux-amd64` |
| Linux arm64 | `sopdet-linux-arm64` |
| macOS arm64 | `sopdet-darwin-arm64` |

```text
https://github.com/Midtown-Technology-Group/sopdet/releases/latest/download/<asset>
https://github.com/Midtown-Technology-Group/sopdet/releases/download/unsigned-latest/<asset>
```

Checksums ship alongside as `MANIFEST.sha256`. These binaries are **unsigned**:
Windows SmartScreen and some AV engines will warn, and WDAC-enforced hosts
additionally need the supplemental policy in [docs/appcontrol.md](docs/appcontrol.md).

```sh
make sign-public      # Windows signing host -> dist/signed-public
make sign-private     # Windows signing host -> dist/signed-private
make publish-public   # stage dist/public
make publish-private  # stage dist/private
```

Provisioning: `bash scripts/artifact-signing-setup.sh` creates the Basic Artifact
Signing account and prints the identity-validation + certificate-profile steps;
fill `scripts/artifact-signing.env` (from `artifact-signing.env.example`).
Signing itself uses Azure Artifact Signing. See [docs/signing.md](docs/signing.md)
for the provisioning status and the portal steps that remain.
Every staged tier ships `MANIFEST.sha256`, the schema, and `WHAT-IT-COLLECTS.md`.
Note: running on a WDAC-enforced endpoint additionally requires a supplemental
App Control policy (or Managed Installer) that trusts the publisher — see
[docs/appcontrol.md](docs/appcontrol.md) and `scripts/New-AppControlPolicy.ps1`.

## License

AGPL-3.0. See [LICENSE](LICENSE).
