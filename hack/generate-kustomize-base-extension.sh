#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

# Parse the arguments
for i in "$@"; do
    case $i in
    --name=*)
        NAME="${i#*=}"
        shift
        ;;
    --provider-type=*)
        PROVIDER_TYPE="${i#*=}"
        shift
        ;;
    --extension-oci-repository=*)
        OCI_REPO="${i#*=}"
        shift
        ;;
    --destination=*)
        DESTINATION="${i#*=}"
        shift
        ;;
    --component-name=*)
        COMPONENT_NAME="${i#*=}"
        shift
        ;;
    esac
done

if [ -z "${NAME:-}" ] || [ -z "${PROVIDER_TYPE:-}" ] || [ -z "${OCI_REPO:-}" ] || [ -z "${DESTINATION:-}" ] || [ -z "${COMPONENT_NAME:-}" ]; then
  echo "One or more parameters are missing."
  exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
COMPONENT_PATH="${SCRIPT_DIR}/../example/extensions/components/${COMPONENT_NAME}"

if [ ! -d "${COMPONENT_PATH}" ]; then
  echo "Unknown component name"
  exit 1
fi

# Find number of resources requiring patches.
NUMBER_OF_RESOURCES=$(kustomize build "${COMPONENT_PATH}" | yq -r '.spec.resources | length')

# Add patch for extension name
PATCHES="  - op: replace
    path: /metadata/name
    value: $NAME
"

# Create type patches.
for ((i = 0; i < $NUMBER_OF_RESOURCES; i++)); do
    PATCHES+="  - op: replace
    path: /spec/resources/$i/type
    value: $PROVIDER_TYPE
"
done

# Add the patch for oci repository.
PATCHES+="  - op: replace
    path: /spec/deployment/extension/helm/ociRepository
    value: $OCI_REPO
"

# Construct the Kustomization file
cat <<EOF >$DESTINATION/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- ../base

components:
- ../components/provider-extension

patches:
- target:
    version: v1alpha1
    group: operator.gardener.cloud
    kind: Extension
    name: $NAME
  patch: |-
$PATCHES
EOF
