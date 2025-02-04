#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

function usage {
    cat <<EOM
Usage:
generate-kustomize-base-extension [options]

This script generates a kustomization.yaml file for building an Extension (operator.gardener.cloud) manifest.

    -h, --help                              Display this help and exit.
    --name                                  Name is the name of the extension.
    --provider-type                         Type of the provider.
    --component-name                        Name of the Kustomize component, one of {provider-extension, network, containerruntime, extension}
    --destination                           The path the kustomization.yaml is written to.
    --extension-oci-repository              URL to OCI image containing the extension chart.
    --admission-runtime-oci-repository      OPTIONAL: URL to OCI image containing the admission runtime chart.
    --admission-application-oci-repository  OPTIONAL: URL to OCI image containing the admission application chart.
    --version                               OPTIONAL: Version of Gardener containing example files.
    --resources-path                        OPTIONAL: Path to Gardener repository. Upstream https://github.com/gardener/gardener will be used if not defined.
EOM
    exit 0
}

# Parse the arguments
for i in "$@"; do
    case $i in
    -h|--help)
        usage
        ;;
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
    --resources-path=*)
        RESOURCES_PATH="${i#*=}"
        shift
        ;;
    --admission-runtime-oci-repository=*)
        ADMISSION_RUNTIME_OCI_REPO="${i#*=}"
        shift
        ;;
    --admission-application-oci-repository=*)
        ADMISSION_APP_OCI_REPO="${i#*=}"
        shift
        ;;
    --version=*)
        VERSION="${i#*=}"
        shift
        ;;
    esac
done

( [[ -z "${NAME:-}" ]] || [[ -z "${PROVIDER_TYPE:-}" ]] || [[ -z "${OCI_REPO:-}" ]] || [[ -z "${DESTINATION:-}" ]] || [[ -z "${COMPONENT_NAME:-}" ]] ) && usage

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
COMPONENT_PATH="${SCRIPT_DIR}/../example/extensions/components/${COMPONENT_NAME}"

if [ ! -d "${COMPONENT_PATH}" ]; then
  echo "Unknown component name"
  exit 1
fi

if [[ -n $VERSION ]]; then
  VERSION_REF="?ref=${VERSION}"
fi

# Kustomization file
KUSTOMIZATION_YAML="apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- ${RESOURCES_PATH:="https://github.com/gardener/gardener/"}/example/extensions/base/${VERSION_REF:-""}

components:
- ${RESOURCES_PATH}/example/extensions/components/${COMPONENT_NAME}/${VERSION_REF:-""}

patches:
- target:
    version: v1alpha1
    group: operator.gardener.cloud
    kind: Extension
    name: example-extension
  patch: |-
    - op: replace
      path: /metadata/name
      value: $NAME
    - op: replace
      path: /spec/deployment/extension/helm/ociRepository
      value: $OCI_REPO
"

# Add admission component.
if [[ -n $ADMISSION_RUNTIME_OCI_REPO ]] && [[ -n $ADMISSION_APP_OCI_REPO ]]; then
  KUSTOMIZATION_YAML=$(printf "$KUSTOMIZATION_YAML" | yq ".components += \"${RESOURCES_PATH}/example/extensions/components/admission/${VERSION_REF:-""}\"")

  KUSTOMIZATION_YAML=$(printf "$KUSTOMIZATION_YAML" | yq ".patches[0].patch +=\"
- op: replace
  path: /spec/deployment/admission/runtimeCluster/helm/ociRepository
  value: ${ADMISSION_RUNTIME_OCI_REPO}
- op: replace
  path: /spec/deployment/admission/virtualCluster/helm/ociRepository
  value: ${ADMISSION_APP_OCI_REPO}
\"")
fi

# Create extension type patches.
NUMBER_OF_RESOURCES=$(yq -r '.spec.resources | length' "${COMPONENT_PATH}/extension.yaml")

for ((i = 0; i < $NUMBER_OF_RESOURCES; i++)); do
    KUSTOMIZATION_YAML=$(printf "$KUSTOMIZATION_YAML" | yq ".patches[0].patch +=\"
- op: replace
  path: /spec/resources/${i}/type
  value: ${PROVIDER_TYPE}
\"")
done

# Write result to destination.
printf "$KUSTOMIZATION_YAML" > $DESTINATION/kustomization.yaml
