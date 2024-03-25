#!/usr/bin/env bash

set -euox pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
ROOT_DIR="$(cd -P -- "${SCRIPT_DIR}/../../" && pwd -P)"
CONTAINER_ID="$(docker run -d --rm -e 'POSTGRES_DB=dtrack' -e 'POSTGRES_USER=dtrack' -e 'POSTGRES_PASSWORD=dtrack' -p '5432' postgres:11-alpine)"
CONTAINER_PORT="$(docker port "${CONTAINER_ID}" "5432/tcp" | cut -d ':' -f 2)"
TMP_LIQUIBASE_CONFIG_FILE="$(mktemp -p "${ROOT_DIR}")"

cat << EOF > "${TMP_LIQUIBASE_CONFIG_FILE}"
changeLogFile=migration/changelog-main.xml
url=jdbc:postgresql://localhost:${CONTAINER_PORT}/dtrack
username=dtrack
password=dtrack
EOF

mvn liquibase:updateSQL -Dliquibase.propertyFile="$(basename "${TMP_LIQUIBASE_CONFIG_FILE}")"; \
  docker stop "${CONTAINER_ID}"; \
  rm "${TMP_LIQUIBASE_CONFIG_FILE}"
