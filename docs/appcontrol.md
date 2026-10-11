# App Control (WDAC) and Sopdet

Hardened Windows endpoints commonly enforce **App Control for Business**
(WDAC). On such a device an unsigned third-party executable is denied by
policy — Sopdet included. Signing is necessary but not always sufficient: the
active policy must also **trust the signer**.

On a representative synthetic lab fixture, multiple active base and
supplemental policies reported enforced through
`Win32_DeviceGuard.CodeIntegrityPolicyEnforcementStatus`, and an unsigned
`sopdet.exe` was denied at launch. Keep real endpoint names, customer numbers,
policy identifiers, and device-group membership in the management system, not
this runbook.

## What is required

1. **Sign** Sopdet with Azure Artifact Signing:
   - `PublicTrust` profile → prospect-facing assessment binaries.
   - `PrivateTrust` profile → internal fleet binaries.
2. **Trust** the signer on the endpoint, by one of:
   - a **supplemental App Control policy** that allows the MTG publisher
     (this is what `scripts/New-AppControlPolicy.ps1` builds), deployed via
     Intune; and/or
   - a **Managed Installer** rule (deploy Sopdet as an Intune/SCCM app), noting
     that self-updating apps lose the managed-installer origin claim; and/or
   - the **Intelligent Security Graph (ISG)** option, if the base policy enables
     it and the publisher has accrued reputation.

A `PrivateTrust` binary is only trusted where the private CA is trusted, so it
is for managed fleets — not for public distribution. The public tier therefore
also ships unsigned binaries plus a `PublicTrust`-signed build for prospects who
enforce App Control.

## Build the supplemental policy

On a Windows machine with the ConfigCI tooling and the signed binaries:

```powershell
$BasePolicyId = Read-Host 'Base policy GUID from the approved deployment record'
./scripts/New-AppControlPolicy.ps1 `
    -SignedPath dist/signed-private `
    -BasePolicyId $BasePolicyId `
    -OutFile sopdet-supplemental.xml
```

This creates a **publisher + fallback-hash** rule scoped to Sopdet, bound to the
base policy via `SupplementsBasePolicyID`.

## Deploy

- **Intune:** Devices → Configuration → *App Control for Business* profile
  (supplemental policy), assign to the target group; or a custom OMA-URI policy
  at `./Vendor/MSFT/ApplicationControl/CiPolicies/<name>`.
- **Group Policy / local:** `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`
  (testing only).

## Practical notes

- Publish every Sopdet update through the same signing identity, or its hash
  changes and the fallback hash rule will not match.
- If third-party security tooling also governs application control, add the MTG
  publisher there through that product's approved change process.
- After deploying, confirm with `Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational`
  and re-run `sopdet.exe` on the endpoint.
