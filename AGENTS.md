# AGENTS.md

Guidance for AI agents and humans working in `Midtown-Technology-Group/sopdet`.

Sopdet is a **read-only device inventory** tool with two implementations that
share one JSON contract, plus an optional resident **serve mode** (device
control plane) documented in the trust boundary below. Read `README.md`,
`codex-swarm.hints.json`, and `schema/inventory.schema.json` before changing
behavior.

## Non-negotiables

1. **The schema is the contract.** `schema/inventory.schema.json` (Go) and
   `powershell/inventory.schema.json` (PowerShell) are the same document and must
   stay **byte-identical** (`make schema-check`). Changing the envelope or entity
   shape means updating both, the schema file, and `testdata/`.
2. **Read-only — inventory mode.** Collectors must not modify the target
   machine. No registry or configuration writes; no installs; no elevation
   required. A skipped or access-denied section is reported in `entity_errors`
   (with `gated: true`), never guessed. **Serve mode is the deliberate
   exception** (see trust boundary): it executes operator-authorized
   ad-hoc PowerShell and must never be pulled into inventory code paths.
3. **Never commit secrets or real device data.** No ingest keys, device keys,
   enrollment tokens, SAS URLs, subscription IDs, or output containing real
   hostnames, users, serials, MACs, or GUIDs. Samples must be synthetic.
   `scripts/artifact-signing.env` is gitignored; use the `.example` file.
   Device keys/tokens must never be logged or interpolated into error strings.
4. **Fingerprint parity is per-implementation.** Go uses
   `sha256-canonical-json/v1` and is not byte-identical to the PowerShell agent's
   canonicalization. Never share delta state across implementations; a Go first
   scan is a fresh baseline.
5. **Signing and WDAC.** Signed distribution is required for hardened endpoints.
   Signing is necessary but not sufficient under App Control — see
   `docs/appcontrol.md`. Do not weaken a fleet's policy to make Sopdet run; add a
   scoped supplemental policy or use a managed installer.

## Trust boundary (serve mode)

`internal/agent` implements the resident runner for the Bifrost device control
plane (epic `Midtown-Technology-Group/bifrost#818`; platform contract:
`docs/architecture/device-control-plane.md` in that repo). Inventory promises
above apply to collectors; serve mode additionally:

- Runs as **LocalSystem** by default on Windows (installed by the M5 Ninja
  bootstrap; no alternate identity, no impersonation in v1).
- Holds a per-device key persisted `0600`/DACL; exchanges one-time `bfen_`
  enrollment tokens at `POST /api/devices/enroll`; refuses to serve without a
  URL plus a key or token.
- Reports `running` **only after a real process spawn** and never re-runs a job
  locally after an uncertain outcome or a fenced rejection (server `lost`
  policy owns that decision).
- Uses `Authorization: Bearer` for WebSocket and `X-Bifrost-Key` for HTTP —
  never `?device_key=` query credentials.
- Is delivered/updated only via the pinned bootstrap binary; **unsigned +
  manifest builds are canary-only**, private-trust signed builds are the
  managed-fleet tier (`docs/signing.md`, `docs/appcontrol.md`).

## Surfaces

| Surface | Canonical for |
|---|---|
| `internal/schema/` | envelope types, fingerprints, entity building |
| `internal/collect/` | collectors; `windows_wmi.go` is Windows-only |
| `internal/ingest/` | gzip, chunking, retry, spool |
| `internal/state/` | delta state |
| `internal/agent/` | serve mode: config, enrollment, state, PowerShell runner |
| `schema/` + `powershell/inventory.schema.json` | the shared contract |
| `powershell/` | the no-admin assessment package and prospect tooling |
| `scripts/` | signing, publish, App Control policy tooling |

## Verification

Run `make check` before opening a PR. It is the single gate: `gofmt`, `go vet`,
`go test ./...`, schema parity, and PSScriptAnalyzer (skipped if `pwsh` is
absent). CI additionally runs `make cross`, a PowerShell job, `govulncheck`, and
the CodeQL workflow.

For collector changes, test on a real Windows host (`-dry-run`) and validate the
output against the schema; compile-only is not enough for WMI work.

## Working conventions

- Keep changes small and independently reviewable; one concern per PR.
- Preserve public behavior unless the change is deliberate and documented.
- Prefer depth: small interfaces over meaningful behavior; do not add
  pass-through layers.
- Update `CHANGELOG.md` for user-visible changes.
- Coordination state (claims, spool, state files) stays out of the repo.
