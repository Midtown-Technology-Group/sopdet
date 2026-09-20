# Contributing

Sopdet is maintained by Midtown Technology Group. Contributions are welcome via
pull requests; open an issue first for anything non-trivial.

## Workflow

1. Branch from `main` (one concern per branch).
2. Run `make check` before opening a PR — it is the same gate CI enforces
   (`gofmt`, `go vet`, `go test ./...`, schema parity, PSScriptAnalyzer).
3. Keep the shared contract in sync: if the envelope or an entity changes,
   update `schema/inventory.schema.json`, `powershell/inventory.schema.json`
   (identical), and `testdata/`.
4. For collector changes, validate on a real Windows host with `-dry-run` and
   confirm the output passes the schema; compile-only is not sufficient.
5. Update `CHANGELOG.md` for user-visible changes.

## Rules

- Read-only: no target-machine writes, no installs, no elevation requirement.
- Never commit secrets, signing configuration, SAS URLs, or real device data.
  Samples must be synthetic.
- Preserve public behavior unless the change is deliberate and documented.

## Signing and WDAC

Signed distribution and the App Control supplemental policy are documented in
`docs/appcontrol.md`. Do not weaken an endpoint's policy to make Sopdet run.

## License

Contributions are accepted under AGPL-3.0.
