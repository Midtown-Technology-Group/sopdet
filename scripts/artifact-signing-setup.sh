#!/usr/bin/env bash
# Scaffold Azure Artifact Signing (formerly Trusted Signing) for Sopdet.
#
# Creates the resource provider registration, a resource group, and a Basic-SKU
# Artifact Signing account. Identity validation and certificate-profile creation
# are printed as next steps (identity validation is completed in the portal).
#
# Requires: az CLI with the artifact-signing extension
#   az extension add -n artifact-signing
set -euo pipefail

RG="${RG:-rg-sopdet-signing}"
LOC="${LOC:-eastus2}"
ACCOUNT="${ACCOUNT:-mtg-sopdet-signing}"
SUBSCRIPTION="${SUBSCRIPTION:-}"

az_args=()
if [ -n "$SUBSCRIPTION" ]; then
  az_args+=(--subscription "$SUBSCRIPTION")
fi

echo "Registering Microsoft.CodeSigning provider..."
az provider register --namespace Microsoft.CodeSigning "${az_args[@]}" >/dev/null

echo "Creating resource group $RG in $LOC..."
az group create -n "$RG" -l "$LOC" "${az_args[@]}" -o none

echo "Creating Artifact Signing account $ACCOUNT (Basic)..."
az artifact-signing create -g "$RG" -n "$ACCOUNT" --sku Basic -l "$LOC" "${az_args[@]}" -o table

ENDPOINT="$(az artifact-signing show -g "$RG" -n "$ACCOUNT" "${az_args[@]}" --query accountUri -o tsv 2>/dev/null || true)"
echo
echo "Account endpoint: ${ENDPOINT:-<see portal; e.g. https://eus.codesigning.azure.net/>}"
echo
echo "Next steps"
echo "  1. Complete IDENTITY VALIDATION in the portal:"
echo "     Artifact Signing > $ACCOUNT > Identity validation > New > Organization (MTG legal entity)."
echo "  2. Create the two certificate profiles using the resulting identity validation id (IV):"
echo "       az artifact-signing certificate-profile create -g $RG --account $ACCOUNT \\"
echo "           --name sopdet-public  --profile-type PublicTrust  --identity-validation-id \"\$IV\""
echo "       az artifact-signing certificate-profile create -g $RG --account $ACCOUNT \\"
echo "           --name sopdet-private --profile-type PrivateTrust --identity-validation-id \"\$IV\""
echo "  3. Fill scripts/artifact-signing.env (copy of artifact-signing.env.example)."
echo "  4. On a Windows signing host: make sign-public / make sign-private."
echo "  5. For WDAC-enforced fleets: build and deploy the supplemental policy (see docs/appcontrol.md)."
