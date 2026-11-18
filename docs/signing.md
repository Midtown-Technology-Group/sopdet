# Signing runbook (Azure Artifact Signing)

Sopdet signs Windows binaries so App Control (WDAC)-enforced endpoints accept
them. This is the provisioning state and the steps that remain.

## Environment-specific inputs

| Item | Value |
|---|---|
| Subscription | `SIGNING_SUBSCRIPTION_ID` — keep the real value outside the repository |
| Resource group | `SIGNING_RESOURCE_GROUP` — operator-selected name |
| Region | `SIGNING_REGION` — selected deployment region |
| Account | `SIGNING_ACCOUNT` — operator-selected Artifact Signing account |
| Endpoint | `SIGNING_ENDPOINT` — endpoint returned for that account |
| Resource provider | `Microsoft.CodeSigning` — must be registered |
| RBAC | Grant Artifact Signing Identity Verifier to the approved operator group, not a named person in this runbook |

Supply those provisioning values through the protected operator environment.
(`scripts/artifact-signing.env` is the separate gitignored configuration used
later by the signing commands.) The setup script accepts `RG`, `ACCOUNT`, `LOC`,
and `SUBSCRIPTION`; map the protected names explicitly before running it:

```sh
: "${SIGNING_RESOURCE_GROUP:?set the protected resource-group value}"
: "${SIGNING_ACCOUNT:?set the protected account value}"
export RG="$SIGNING_RESOURCE_GROUP"
export ACCOUNT="$SIGNING_ACCOUNT"
export LOC="${SIGNING_REGION:-eastus}"
export SUBSCRIPTION="${SIGNING_SUBSCRIPTION_ID:-}"
bash scripts/artifact-signing-setup.sh
```

Retain its output in the approved secret/configuration system, not this
repository.

## Remaining steps

Identity validation **can only be completed in the Azure portal** (the CLI has
no command for it), and it gates certificate-profile creation.

1. Open the Artifact Signing account in the Azure portal using the subscription,
   resource group, and account values from the protected operator environment.
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
   : "${SIGNING_RESOURCE_GROUP:?set the protected resource-group value}"
   : "${SIGNING_ACCOUNT:?set the protected account value}"
   : "${SIGNING_PUBLIC_PROFILE:?set the public profile name}"
   : "${SIGNING_PRIVATE_PROFILE:?set the private profile name}"
   : "${PUBLIC_IDENTITY_VALIDATION_ID:?copy the completed Public organization validation ID}"
   : "${PRIVATE_IDENTITY_VALIDATION_ID:?copy the completed Private organization validation ID}"
   az artifact-signing certificate-profile create -g "$SIGNING_RESOURCE_GROUP" \
       --account "$SIGNING_ACCOUNT" --name "$SIGNING_PUBLIC_PROFILE" \
       --profile-type PublicTrust --identity-validation-id "$PUBLIC_IDENTITY_VALIDATION_ID"
   az artifact-signing certificate-profile create -g "$SIGNING_RESOURCE_GROUP" \
       --account "$SIGNING_ACCOUNT" --name "$SIGNING_PRIVATE_PROFILE" \
       --profile-type PrivateTrust --identity-validation-id "$PRIVATE_IDENTITY_VALIDATION_ID"
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

For GitHub Actions, use a dedicated service principal with reviewed OIDC
federation already configured for the release workflow. Obtain its approved
**service-principal object ID** from the Enterprise applications entry and
confirm the tenant and identity against the protected deployment record.
Keep that object ID and the exact signing-account scope in the protected
workflow environment.

Run the account-scoped role assignment through the reviewed Azure deployment
workflow using the explicit object ID. This step does not create an identity or
password credential, or select an identity by display name:

```sh
: "${SIGNING_SERVICE_PRINCIPAL_OBJECT_ID:?set the approved CI service-principal object ID}"
: "${SIGNING_ACCOUNT_SCOPE:?set the exact Artifact Signing account resource ID}"
az role assignment create \
    --assignee-object-id "$SIGNING_SERVICE_PRINCIPAL_OBJECT_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "Artifact Signing Certificate Profile Signer" \
    --scope "$SIGNING_ACCOUNT_SCOPE"
```

Identity provisioning and OIDC federation require their own approved deployment
change before this assignment. Follow the [Azure RBAC service-principal
guidance](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli)
for the object-ID and principal-type parameters.

## WDAC-enforced endpoints

Signing alone is not enough where App Control policies are active. Validate on
a synthetic lab fixture first, then deploy to an approved pilot group whose
device and customer identifiers remain in the management system rather than
this repository. Those hosts need a supplemental App Control policy or Managed
Installer rule that trusts the Sopdet publisher.
See [appcontrol.md](appcontrol.md) and `scripts/New-AppControlPolicy.ps1`.
