# Changelog

All notable changes to Sopdet are documented here. The format is based on
Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

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
