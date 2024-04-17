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

NIST_DIR="$HOME/.dependency-track/nist"

function printHelp() {
  echo "Purges and re-populates the local NVD mirror directory with dummy data."
  echo ""
  echo "The dummy data will cause Dependency-Track to NOT download the actual"
  echo "feeds from NIST when it starts. Exception is the 'modified' feed, which"
  echo "is negligible in size."
  echo "Skipping NVD mirroring can be desirable for local testing."
  echo ""
  echo "The local NVD mirror directory is located at $NIST_DIR"
  echo ""
  echo "Usage: $0"
  echo ""
}

while getopts ":h" opt; do
  case $opt in
    h)
      printHelp
      exit
      ;;
    *)
      ;;
  esac
done

rm -rf "$NIST_DIR"
mkdir -p "$NIST_DIR"

for feed in $(seq "2023" "2002"); do
  touch "$NIST_DIR/nvdcve-1.1-$feed.json.gz"
  echo "9999999999999" > "$NIST_DIR/nvdcve-1.1-$feed.json.gz.ts"
done