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

NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_SERVICE="keycloak"
CERT_DIR="$(mktemp -d)"

trap 'rm -rf "${CERT_DIR}"' EXIT

echo "==> Ensuring namespace ${NAMESPACE} exists..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Generating CA key and certificate..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" \
  -subj "/CN=Keycloak Demo CA/O=Agent Substrate"

echo "==> Generating Keycloak server key and CSR..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/tls.key" \
  -out "${CERT_DIR}/tls.csr" \
  -subj "/CN=${KEYCLOAK_SERVICE}.${NAMESPACE}.svc.cluster.local/O=Agent Substrate"

cat <<EOF > "${CERT_DIR}/san.cnf"
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${KEYCLOAK_SERVICE}
DNS.2 = ${KEYCLOAK_SERVICE}.${NAMESPACE}
DNS.3 = ${KEYCLOAK_SERVICE}.${NAMESPACE}.svc
DNS.4 = ${KEYCLOAK_SERVICE}.${NAMESPACE}.svc.cluster.local
DNS.5 = localhost
IP.1 = 127.0.0.1
EOF

echo "==> Signing Keycloak server certificate with CA..."
openssl x509 -req -sha256 -days 365 \
  -in "${CERT_DIR}/tls.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/tls.crt" \
  -extfile "${CERT_DIR}/san.cnf" \
  -extensions v3_req

echo "==> Creating or updating Kubernetes secret '${KEYCLOAK_SERVICE}-tls' in namespace '${NAMESPACE}'..."
kubectl -n "${NAMESPACE}" create secret generic "${KEYCLOAK_SERVICE}-tls" \
  --from-file=tls.crt="${CERT_DIR}/tls.crt" \
  --from-file=tls.key="${CERT_DIR}/tls.key" \
  --from-file=ca.crt="${CERT_DIR}/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> TLS certificates created successfully in secret '${NAMESPACE}/${KEYCLOAK_SERVICE}-tls'."
