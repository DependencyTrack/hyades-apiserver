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

# Arguments that can be passed at build time
# Directory names must end with / to avoid errors when COPYing
ARG COMMIT_SHA=unknown
ARG APP_VERSION=0.0.0
ARG APP_DIR=/opt/owasp/dependency-track/
ARG DATA_DIR=/data/
ARG UID=1000
ARG GID=1000

FROM eclipse-temurin:21.0.7_6-jdk-alpine@sha256:2f2f553ce09d25e2d2f0f521ab94cd73f70c9b21327a29149c23a2b63b8e29a0 AS jre-build

WORKDIR /work

COPY --chmod=755 ./src/main/docker/create-jre.sh ./
COPY ./target/dependency-track-apiserver.jar ./

RUN ./create-jre.sh -i ./dependency-track-apiserver.jar -o ./jre

FROM alpine:3.22@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715

ARG COMMIT_SHA
ARG APP_VERSION
ARG APP_DIR
ARG DATA_DIR
ARG UID
ARG GID

ENV TZ=Etc/UTC \
    # Dependency-Track's default logging level
    LOGGING_LEVEL=INFO \
    # JVM Options that are passed at runtime by default
    JAVA_OPTIONS="-XX:+UseG1GC -XX:+UseStringDeduplication -XX:MaxGCPauseMillis=250 -XX:MaxRAMPercentage=80.0" \
    # JVM Options that can be passed at runtime, while maintaining also those set in JAVA_OPTIONS.
    # e.g. EXTRA_JAVA_OPTIONS="-Dlogback.configurationFile=logback-json.xml"
    EXTRA_JAVA_OPTIONS="" \
    # The web context defaults to the root. To override, supply an alternative context which starts with a / but does not end with one
    # Example: /dtrack
    CONTEXT="/" \
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    LANG=C.UTF-8 \
    # Ensure user home is always set to DATA_DIR, even for arbitrary UIDs (such as used by OpenShift)
    HOME=${DATA_DIR} \
    # Default notification publisher templates override environment variables
    DEFAULT_TEMPLATES_OVERRIDE_ENABLED=false \
    DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY=${DATA_DIR}

# Create the directories where the WAR will be deployed to (${APP_DIR}) and Dependency-Track will store its data (${DATA_DIR})
# Create a user and assign home directory to a ${DATA_DIR}
# Ensure UID 1000 & GID 1000 own all the needed directories
RUN mkdir -p ${APP_DIR} ${DATA_DIR} \
    && addgroup -S -g ${GID} dtrack || true \
    && adduser -S -D -G dtrack -H -h ${DATA_DIR} -g "dtrack user" -s /bin/false -u ${UID} dtrack || true \
    && chown -R dtrack:0 ${DATA_DIR} ${APP_DIR} \
    && chmod -R g=u ${DATA_DIR} ${APP_DIR} \
    && apk add --no-cache tzdata

COPY --from=jre-build /work/jre ${JAVA_HOME}
COPY ./target/dependency-track-apiserver.jar ./src/main/docker/logback-json.xml ${APP_DIR}/

# Specify the user to run as (in numeric format for compatibility with Kubernetes/OpenShift's SCC)
USER ${UID}

# Specify the container working directory
WORKDIR ${APP_DIR}

# Launch Dependency-Track
CMD exec java ${JAVA_OPTIONS} ${EXTRA_JAVA_OPTIONS} --add-opens java.base/java.util.concurrent=ALL-UNNAMED -DdependencyTrack.logging.level=${LOGGING_LEVEL} -jar dependency-track-apiserver.jar -context ${CONTEXT}

# Specify which port Dependency-Track listens on
EXPOSE 8080

# Add a healthcheck using the Dependency-Track version API
HEALTHCHECK --interval=30s --start-period=60s --timeout=3s CMD wget -t 1 -T 3 --proxy off -q -O /dev/null http://127.0.0.1:8080${CONTEXT}health || exit 1

# metadata labels
LABEL \
    org.opencontainers.image.vendor="OWASP" \
    org.opencontainers.image.title="Official Dependency-Track Container image" \
    org.opencontainers.image.description="Dependency-Track is an intelligent Component Analysis platform" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.url="https://dependencytrack.org/" \
    org.opencontainers.image.source="https://github.com/DependencyTrack/dependency-track" \
    org.opencontainers.image.revision="${COMMIT_SHA}" \
    org.opencontainers.image.licenses="Apache-2.0" \
    maintainer="steve.springett@owasp.org"
