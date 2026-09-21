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
3. Copy the **Identity validation Id**, then create the two profiles:

   ```sh
   IV=<identity-validation-id>
   az artifact-signing certificate-profile create -g rg-sopdet-signing \
       --account mtg-sopdet-signing --name sopdet-public \
       --profile-type PublicTrust --identity-validation-id "$IV"
   az artifact-signing certificate-profile create -g rg-sopdet-signing \
       --account mtg-sopdet-signing --name sopdet-private \
       --profile-type PrivateTrust --identity-validation-id "$IV"
   ```

4. Confirm and record the profile names in `scripts/artifact-signing.env`
   (already staged; do not commit it).

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
