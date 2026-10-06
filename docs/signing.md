# Signing runbook (Azure Artifact Signing)

Sopdet signs Windows binaries so App Control (WDAC)-enforced endpoints accept
them. This is the provisioning state and the steps that remain.

## Provisioned

| Item | Value |
|---|---|
| Subscription | `Microsoft Azure Sponsorship` (`a1d63b24-1202-4bfa-9086-cf32d1d352fc`) |
| Resource group | `rg-sopdet-signing` |
| Region | `eastus` |
| Account | `mtg-sopdet-signing` (Basic SKU, $9.99/mo) |
| Endpoint | `https://eus.codesigning.azure.net/` |
| Resource provider | `Microsoft.CodeSigning` — Registered |
| RBAC | `thomas@midtowntg.com` = Artifact Signing Identity Verifier on the account |

Created 2026-09-21. To recreate: `bash scripts/artifact-signing-setup.sh`.

## Remaining steps

Identity validation **can only be completed in the Azure portal** (the CLI has
no command for it), and it gates certificate-profile creation.

1. Open the account:
   <https://portal.azure.com/#resource/subscriptions/a1d63b24-1202-4bfa-9086-cf32d1d352fc/resourceGroups/rg-sopdet-signing/providers/Microsoft.CodeSigning/codeSigningAccounts/mtg-sopdet-signing>
2. **Objects > Identity validations > New Identity.**
   - **Organization + Public** → for the Public Trust profile (assessment tier).
     Requires the legal entity to be in the US, Canada, the EU, the UK,
     Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway,
     or Israel. Expect **1–20 business days**.
   - **Organization + Private** → for the Private Trust profile (managed fleet).
     Not subject to the geographic restriction; organization name defaults to
     the Entra tenant name.
3. Complete **separate Public and Private organization validations**. Once each
   is completed, copy its **Identity validation Id** from the matching record.
   Public validation applies to Public Trust, Public Trust Test, and VBS
   Enclave profiles; Private validation applies to Private Trust and Private
   Trust CI Policy profiles. Do not reuse one ID across the two trust types.
   See Microsoft's [Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart#create-an-identity-validation-request).

   Profile creation below is a later authorized provisioning step:

   ```sh
   PUBLIC_IV=<completed-public-organization-validation-id>
   PRIVATE_IV=<completed-private-organization-validation-id>
   az artifact-signing certificate-profile create -g rg-sopdet-signing \
       --account mtg-sopdet-signing --name sopdet-public \
       --profile-type PublicTrust --identity-validation-id "$PUBLIC_IV"
   az artifact-signing certificate-profile create -g rg-sopdet-signing \
       --account mtg-sopdet-signing --name sopdet-private \
       --profile-type PrivateTrust --identity-validation-id "$PRIVATE_IV"
   ```

4. Confirm and record the profile names in `scripts/artifact-signing.env`
   (copy from `scripts/artifact-signing.env.example`; do not commit it).

Preparation does not complete onboarding. The 2026-10-06 read-only account
inspection found no organization identity validations or certificate profiles,
and updated terms dated 2026-05-04 await human acceptance. An authorized human
must resolve terms and identity validation before later profile provisioning
and signing; do not treat the commands below as completed steps.

## Signing

On a Windows signing host with the Windows SDK and the Artifact Signing client
tools (`Azure.CodeSigning.Dlib.dll`), and an Azure credential
(`az login`, or `AZURE_*` service-principal env vars):

```sh
make sign-public     # -> dist/signed-public  (Public Trust)
make sign-private    # -> dist/signed-private (Private Trust)
make publish-public  # stage the public tier
make publish-private # stage the private tier
```

`scripts/sign-artifacts.ps1` copies each binary, signs via `signtool /dlib`,
then verifies with `signtool verify /pa`.

Each endpoint, account, certificate-profile, and dlib setting resolves from a
nonempty explicit parameter, then its `ARTIFACT_SIGNING_*` environment variable,
then `scripts/artifact-signing.env`. The selected trust tier chooses
`ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC` or `ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE`.
`-CertificateProfileName` overrides that selection.

For multiple files in PowerShell, use one array-valued parameter:

```powershell
./scripts/sign-artifacts.ps1 -Profile Public -OutDir dist/signed-public `
    -File 'bin/sopdet-windows-amd64.exe','bin/sopdet-windows-arm64.exe'
```

Make uses `pwsh -Command` because native `pwsh -File` does not bind array
arguments ([PowerShell CLI documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh#-file---f)).
Run `make signing-test` (or `pwsh -NoProfile -File scripts/test-sign-artifacts.ps1`)
to exercise configuration and both release/Make call sites with synthetic files
and a fake signtool. These checks make no signing requests and do not prove live
certificate trust, WDAC acceptance, or preservation of Ninja-delivered script
signatures; those remain later acceptance checks.

CI also runs the suite with `-CoveragePath signing-coverage.xml`. PowerShell
debugger breakpoints record actual line hits in the suite and the byte-identical
copy of the signing helper. The report is imported through Sonar's generic
coverage format alongside Go coverage; no coverage exclusions or gate thresholds
are changed.

## CI signing identity (planned)

For GitHub Actions, create a service principal and grant it only the signing
role, scoped to the account:

```sh
az ad sp create-for-rbac -n sopdet-signing --skip-assignment
az role assignment create --assignee <sp-app-id> \
    --role "Artifact Signing Certificate Profile Signer" \
    --scope /subscriptions/a1d63b24-1202-4bfa-9086-cf32d1d352fc/resourceGroups/rg-sopdet-signing/providers/Microsoft.CodeSigning/codeSigningAccounts/mtg-sopdet-signing
```

Prefer federated credentials (OIDC) over a client secret for the release
workflow.

## WDAC-enforced endpoints

Signing alone is not enough where App Control policies are active (for example
LT002/device 3124, and clients 46/193/422). Those hosts need a supplemental
App Control policy or Managed Installer rule that trusts the Sopdet publisher.
See [appcontrol.md](appcontrol.md) and `scripts/New-AppControlPolicy.ps1`.
