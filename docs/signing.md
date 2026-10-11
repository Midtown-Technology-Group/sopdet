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

Supply those values through the protected operator environment or
`scripts/artifact-signing.env` (gitignored). To provision or recreate the
resources, run `bash scripts/artifact-signing-setup.sh` and retain its output in
the approved secret/configuration system, not this repository.

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
3. Copy the **Identity validation Id**, then create the two profiles:

   ```sh
   : "${SIGNING_RESOURCE_GROUP:?set the protected resource-group value}"
   : "${SIGNING_ACCOUNT:?set the protected account value}"
   : "${SIGNING_PUBLIC_PROFILE:?set the public profile name}"
   : "${SIGNING_PRIVATE_PROFILE:?set the private profile name}"
   : "${IDENTITY_VALIDATION_ID:?copy the approved identity-validation ID}"
   az artifact-signing certificate-profile create -g "$SIGNING_RESOURCE_GROUP" \
       --account "$SIGNING_ACCOUNT" --name "$SIGNING_PUBLIC_PROFILE" \
       --profile-type PublicTrust --identity-validation-id "$IDENTITY_VALIDATION_ID"
   az artifact-signing certificate-profile create -g "$SIGNING_RESOURCE_GROUP" \
       --account "$SIGNING_ACCOUNT" --name "$SIGNING_PRIVATE_PROFILE" \
       --profile-type PrivateTrust --identity-validation-id "$IDENTITY_VALIDATION_ID"
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
: "${SIGNING_SERVICE_PRINCIPAL_NAME:?set the approved CI identity name}"
: "${SIGNING_SERVICE_PRINCIPAL_ID:?set the approved CI application ID}"
: "${SIGNING_ACCOUNT_SCOPE:?set the exact Artifact Signing account resource ID}"
az ad sp create-for-rbac -n "$SIGNING_SERVICE_PRINCIPAL_NAME" --skip-assignment
az role assignment create --assignee "$SIGNING_SERVICE_PRINCIPAL_ID" \
    --role "Artifact Signing Certificate Profile Signer" \
    --scope "$SIGNING_ACCOUNT_SCOPE"
```

Prefer federated credentials (OIDC) over a client secret for the release
workflow.

## WDAC-enforced endpoints

Signing alone is not enough where App Control policies are active. Validate on
a synthetic lab fixture first, then deploy to an approved pilot group whose
device and customer identifiers remain in the management system rather than
this repository. Those hosts need a supplemental App Control policy or Managed
Installer rule that trusts the Sopdet publisher.
See [appcontrol.md](appcontrol.md) and `scripts/New-AppControlPolicy.ps1`.
