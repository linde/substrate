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

USERNAME="${1:-alice}"
PASSWORD="${2:-${USERNAME}password}"
OUTPUT_FILE="${3:-}"

KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"
REALM="substrate"
CLIENT_ID="substrate-cli"

TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

RESPONSE=$(curl -k -s -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid")

if echo "${RESPONSE}" | grep -q '"error"'; then
  echo "Error authenticating user '${USERNAME}':" >&2
  echo "${RESPONSE}" | jq . >&2 || echo "${RESPONSE}" >&2
  exit 1
fi

ACCESS_TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token')

if [ -z "${ACCESS_TOKEN}" ] || [ "${ACCESS_TOKEN}" = "null" ]; then
  echo "Failed to retrieve access token:" >&2
  echo "${RESPONSE}" >&2
  exit 1
fi

if [ -n "${OUTPUT_FILE}" ]; then
  echo "${ACCESS_TOKEN}" > "${OUTPUT_FILE}"
  echo "Token for ${USERNAME} saved to ${OUTPUT_FILE}"
else
  # Check if output is redirected / piped
  if [ -t 1 ]; then
    echo "Successfully retrieved token for '${USERNAME}':"
    echo ""
    echo "--- Decoded Payload Claims ---"
    echo "${ACCESS_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq . || true
    echo ""
    echo "--- Raw Access Token ---"
    echo "${ACCESS_TOKEN}"
  else
    echo "${ACCESS_TOKEN}"
  fi
fi
