#!/bin/sh

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

work_dir="$(mktemp -d)"

# Module dependencies that jdeps fails to detect.
#   jdk.crypto.ec: Required for TLS connections that use elliptic curve cryptography.
#   jdk.zipfs:     Required by code that reads files from JAR files at runtime.
static_module_deps='jdk.crypto.ec,jdk.zipfs'

echo "[+] extracting $(basename $1) to ${work_dir}"
unzip -qq $1 -d "${work_dir}"

echo '[+] detecting module dependencies'
jdeps \
  --class-path "${work_dir}:${work_dir}/WEB-INF/lib/*" \
  --print-module-deps \
  --ignore-missing-deps \
  --multi-release 21 \
  "${work_dir}/WEB-INF/classes" \
  > "${work_dir}/module-deps.txt"

module_deps="$(cat "${work_dir}/module-deps.txt"),${static_module_deps}"
echo "[+] identified module dependencies: ${module_deps}"

echo "[+] creating jre at $2"
jlink \
  --compress zip-6 \
  --strip-debug \
  --no-header-files \
  --no-man-pages \
  --add-modules "${module_deps}" \
  --output $2

echo "[+] removing ${work_dir}"
rm -rf "${work_dir}"