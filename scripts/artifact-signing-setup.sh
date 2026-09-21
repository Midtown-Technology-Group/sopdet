#!/usr/bin/env bash
# Scaffold Azure Artifact Signing (formerly Trusted Signing) for Sopdet.
#
# Creates the resource provider registration, a resource group, a Basic-SKU
# Artifact Signing account, and grants the signed-in user the Identity Verifier
# role. Identity validation and certificate-profile creation are printed as next
# steps (identity validation is completed in the portal only).
#
# Requires: az CLI with the artifact-signing extension
#   az extension add -n artifact-signing
#
# Regions that support Artifact Signing (eastus2 is NOT one of them):
#   brazilsouth centralus eastus japaneast koreacentral northcentralus
#   northeurope polandcentral southcentralus switzerlandnorth westcentralus
#   westeurope westus westus2 westus3
set -euo pipefail

RG="${RG:-rg-sopdet-signing}"
LOC="${LOC:-eastus}"
ACCOUNT="${ACCOUNT:-mtg-sopdet-signing}"
SUBSCRIPTION="${SUBSCRIPTION:-}"

az_args=()
if [ -n "$SUBSCRIPTION" ]; then
  az_args+=(--subscription "$SUBSCRIPTION")
fi

echo "Registering Microsoft.CodeSigning provider..."
az provider register --namespace Microsoft.CodeSigning --wait "${az_args[@]}" >/dev/null

echo "Creating resource group $RG in $LOC..."
az group create -n "$RG" -l "$LOC" "${az_args[@]}" -o none

echo "Creating Artifact Signing account $ACCOUNT (Basic)..."
az artifact-signing create -g "$RG" -n "$ACCOUNT" --sku Basic -l "$LOC" "${az_args[@]}" -o table

ACCOUNT_ID="$(az artifact-signing show -g "$RG" -n "$ACCOUNT" "${az_args[@]}" --query id -o tsv)"
ENDPOINT="$(az artifact-signing show -g "$RG" -n "$ACCOUNT" "${az_args[@]}" --query accountUri -o tsv 2>/dev/null || true)"

echo "Granting 'Artifact Signing Identity Verifier' to the signed-in user..."
PRINCIPAL="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
if [ -n "$PRINCIPAL" ]; then
  az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type User \
    --role "Artifact Signing Identity Verifier" --scope "$ACCOUNT_ID" "${az_args[@]}" -o none \
    || echo "  (role may already be assigned)"
else
  echo "  could not resolve signed-in user; assign the role manually in the portal"
fi

PORTAL="https://portal.azure.com/#resource${ACCOUNT_ID}"
echo
echo "Account endpoint: ${ENDPOINT:-<see portal; e.g. https://eus.codesigning.azure.net/>}"
echo "Portal: $PORTAL"
echo
echo "Next steps"
echo "  1. Complete IDENTITY VALIDATION in the portal (CLI cannot do this):"
echo "     $PORTAL > Objects > Identity validations > New Identity."
echo "     - Organization + Public  -> for the Public Trust profile (assessment tier)."
echo "     - Organization + Private -> for the Private Trust profile (managed fleets)."
echo "     Public Trust requires the legal entity to be in the US, Canada, the EU, the UK,"
echo "     Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway, or Israel."
echo "     Processing takes 1-20 business days."
echo "  2. Copy the Identity validation Id, then create the two certificate profiles:"
echo "       az artifact-signing certificate-profile create -g $RG --account $ACCOUNT \\"
echo "           --name sopdet-public  --profile-type PublicTrust  --identity-validation-id \"\$IV\""
echo "       az artifact-signing certificate-profile create -g $RG --account $ACCOUNT \\"
echo "           --name sopdet-private --profile-type PrivateTrust --identity-validation-id \"\$IV\""
echo "  3. Fill scripts/artifact-signing.env (copy of artifact-signing.env.example)."
echo "  4. On a Windows signing host: make sign-public / make sign-private."
echo "  5. For WDAC-enforced fleets: build and deploy the supplemental policy (see docs/appcontrol.md)."
