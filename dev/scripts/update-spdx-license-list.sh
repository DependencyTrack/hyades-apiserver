#!/usr/bin/env bash

# This file is part of Dependency-Track.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
RESOURCES_DIR="$(cd -P -- "${SCRIPT_DIR}/../../apiserver/src/main/resources" && pwd -P)"
TMP_DOWNLOAD_FILE="$(mktemp)"
TMP_WORK_DIR="$(mktemp -d)"

echo "[+] Downloading license list v$1"
gh -R spdx/license-list-data release download "v$1" \
  --archive tar.gz --clobber --output "${TMP_DOWNLOAD_FILE}"

echo "[+] Extracting license list contents to ${TMP_WORK_DIR}"
tar -xvzf "${TMP_DOWNLOAD_FILE}" \
  --strip-components "1" \
  --directory "${TMP_WORK_DIR}" \
  "license-list-data-$1/json"

echo '[+] Preprocessing license list'
jq --slurp --sort-keys '. | map({
  id: .licenseId // .licenseExceptionId,
  name,
  header: .standardLicenseHeader,
  text: .licenseText // .licenseExceptionText,
  template: .standardLicenseTemplate,
  isDeprecatedLicenseId,
  isFsfLibre,
  isOsiApproved,
  comments: .licenseComments,
  seeAlso,
}) | sort_by(.id)' $TMP_WORK_DIR/json/*/*.json > "${RESOURCES_DIR}/spdx-license-list.json"

echo "[+] Removing temporary files"
rm -r "${TMP_DOWNLOAD_FILE}" "${TMP_WORK_DIR}"