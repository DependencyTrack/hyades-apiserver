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
ROOT_DIR="$(cd -P -- "${SCRIPT_DIR}/../../" && pwd -P)"
MIGRATION_DIR="$(cd -P -- "${ROOT_DIR}/persistence-migration" && pwd -P)"
CONTAINER_ID="$(docker run -d --rm -e 'POSTGRES_DB=dtrack' -e 'POSTGRES_USER=dtrack' -e 'POSTGRES_PASSWORD=dtrack' -p '5432' postgres:17-alpine)"
CONTAINER_PORT="$(docker port "${CONTAINER_ID}" "5432/tcp" | cut -d ':' -f 2)"
TMP_LIQUIBASE_CONFIG_FILE="$(mktemp -p "${MIGRATION_DIR}")"

while ! docker exec "${CONTAINER_ID}" pg_isready -U dtrack -d dtrack; do echo 'Waiting for Postgres readiness...'; sleep 1; done

cat << EOF > "${TMP_LIQUIBASE_CONFIG_FILE}"
changeLogFile=migration/changelog-main.xml
url=jdbc:postgresql://localhost:${CONTAINER_PORT}/dtrack
username=dtrack
password=dtrack
EOF

mvn -pl persistence-migration liquibase:update \
  -Dliquibase.analytics.enabled=false \
  -Dliquibase.propertyFile="$(basename "${TMP_LIQUIBASE_CONFIG_FILE}")"; \
  docker exec "${CONTAINER_ID}" pg_dump -Udtrack --schema-only --no-owner --no-privileges dtrack | sed -e '/^--/d' | cat -s > "${ROOT_DIR}/schema.sql"; \
  docker stop "${CONTAINER_ID}"; \
  rm "${TMP_LIQUIBASE_CONFIG_FILE}"
