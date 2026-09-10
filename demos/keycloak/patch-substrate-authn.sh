#!/usr/bin/env bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit -o nounset -o pipefail

KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_ISSUER="https://keycloak.${KEYCLOAK_NAMESPACE}.svc.cluster.local:8443/realms/substrate"
KEYCLOAK_AUDIENCE="substrate"
ATE_NAMESPACE="ate-system"
CONFIGMAP_NAME="ate-api-authentication"
WORK_DIR="$(mktemp -d)"

trap 'rm -rf "${WORK_DIR}"' EXIT

echo "==> Checking for Keycloak TLS secret in namespace '${KEYCLOAK_NAMESPACE}'..."
if ! kubectl -n "${KEYCLOAK_NAMESPACE}" get secret keycloak-tls >/dev/null 2>&1; then
  echo "Error: Secret 'keycloak-tls' not found in namespace '${KEYCLOAK_NAMESPACE}'." >&2
  echo "Keycloak's certificates must be generated first. Please run:" >&2
  echo "  ./demos/keycloak/generate-certs.sh" >&2
  exit 1
fi

echo "==> Retrieving Keycloak CA certificate from secret '${KEYCLOAK_NAMESPACE}/keycloak-tls'..."
kubectl -n "${KEYCLOAK_NAMESPACE}" get secret keycloak-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "${WORK_DIR}/keycloak-ca.crt"

echo "==> Retrieving existing ${CONFIGMAP_NAME} in namespace ${ATE_NAMESPACE}..."
if kubectl -n "${ATE_NAMESPACE}" get configmap "${CONFIGMAP_NAME}" -o jsonpath='{.data.authentication\.yaml}' > "${WORK_DIR}/current-authn.yaml" 2>/dev/null; then
  echo "Found existing authentication.yaml."
else
  echo "ConfigMap '${CONFIGMAP_NAME}' not found in namespace '${ATE_NAMESPACE}'."
  echo "Auto-detecting cluster's Kubernetes token issuer..."
  K8S_ISSUER=$(kubectl get --raw /.well-known/openid-configuration 2>/dev/null | grep -o '"issuer":"[^"]*' | sed 's/"issuer":"//' || true)
  if [ -z "${K8S_ISSUER}" ]; then
    K8S_ISSUER="https://kubernetes.default.svc.cluster.local"
  fi
  echo "Using Kubernetes issuer: ${K8S_ISSUER}"
  cat <<EOF > "${WORK_DIR}/current-authn.yaml"
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: ${K8S_ISSUER}
  audiences:
  - api.ate-system.svc
  certificateAuthorityFile: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  discoveryTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
EOF
fi

echo "==> Merging Keycloak JWT provider into authentication.yaml..."
python3 - <<EOF
import yaml

with open("${WORK_DIR}/current-authn.yaml", "r") as f:
    cfg = yaml.safe_load(f) or {}

if "jwtProviders" not in cfg or not isinstance(cfg["jwtProviders"], list):
    cfg["jwtProviders"] = []

# Update or add Keycloak provider
keycloak_provider = {
    "name": "keycloak",
    "issuer": "${KEYCLOAK_ISSUER}",
    "audiences": ["${KEYCLOAK_AUDIENCE}"],
    "certificateAuthorityFile": "/etc/ateapi/authentication/keycloak-ca.crt",
}

found = False
for idx, p in enumerate(cfg["jwtProviders"]):
    if p.get("name") == "keycloak":
        cfg["jwtProviders"][idx] = keycloak_provider
        found = True
        break

if not found:
    cfg["jwtProviders"].append(keycloak_provider)

if "actorIdentityJWTProvider" not in cfg or not cfg["actorIdentityJWTProvider"]:
    cfg["actorIdentityJWTProvider"] = "kubernetes"

with open("${WORK_DIR}/new-authn.yaml", "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
EOF

echo "==> Applying updated ConfigMap ${CONFIGMAP_NAME}..."
kubectl -n "${ATE_NAMESPACE}" create configmap "${CONFIGMAP_NAME}" \
  --from-file=authentication.yaml="${WORK_DIR}/new-authn.yaml" \
  --from-file=keycloak-ca.crt="${WORK_DIR}/keycloak-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Restarting deployment ate-api-server..."
kubectl -n "${ATE_NAMESPACE}" rollout restart deployment/ate-api-server

echo "==> Waiting for ate-api-server rollout to finish..."
kubectl -n "${ATE_NAMESPACE}" rollout status deployment/ate-api-server --timeout=120s

echo "==> Keycloak JWT provider successfully configured in Substrate!"
