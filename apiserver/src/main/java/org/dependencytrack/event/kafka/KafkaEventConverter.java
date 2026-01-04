/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event.kafka;

import alpine.event.framework.Event;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisCommand;
import org.dependencytrack.proto.vulnanalysis.v1.Component;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Utility class to convert {@link Event}s to {@link KafkaEvent}s.
 */
public final class KafkaEventConverter {

    private KafkaEventConverter() {
    }

    static KafkaEvent<?, ?> convert(final Event event) {
        return switch (event) {
            case ComponentRepositoryMetaAnalysisEvent e -> convert(e);
            case ComponentVulnerabilityAnalysisEvent e -> convert(e);
            default -> throw new IllegalArgumentException("Unable to convert event " + event);
        };
    }

    static KafkaEvent<ScanKey, ScanCommand> convert(final ComponentVulnerabilityAnalysisEvent event) {
        final var componentBuilder = Component.newBuilder()
                .setUuid(event.uuid().toString());
        Optional.ofNullable(event.cpe()).ifPresent(componentBuilder::setCpe);
        Optional.ofNullable(event.purl()).ifPresent(componentBuilder::setPurl);
        Optional.ofNullable(event.swidTagId()).ifPresent(componentBuilder::setSwidTagId);
        Optional.ofNullable(event.internal()).ifPresent(componentBuilder::setInternal);

        final var scanKey = ScanKey.newBuilder()
                .setScanToken(event.token().toString())
                .setComponentUuid(event.uuid().toString())
                .build();

        final var scanCommand = ScanCommand.newBuilder()
                .setComponent(componentBuilder)
                .build();

        return new KafkaEvent<>(
                KafkaTopics.VULN_ANALYSIS_COMMAND,
                scanKey, scanCommand,
                Map.of(KafkaEventHeaders.VULN_ANALYSIS_LEVEL, event.level().name(),
                        KafkaEventHeaders.IS_NEW_COMPONENT, String.valueOf(event.isNewComponent()))
        );
    }

    static KafkaEvent<String, AnalysisCommand> convert(final ComponentRepositoryMetaAnalysisEvent event) {
        if (event == null || event.purlCoordinates() == null) {
            return null;
        }

        final var componentBuilder = org.dependencytrack.proto.repometaanalysis.v1.Component.newBuilder()
                .setPurl(event.purlCoordinates());
        Optional.ofNullable(event.internal()).ifPresent(componentBuilder::setInternal);
        Optional.ofNullable(event.componentUuid()).map(UUID::toString).ifPresent(componentBuilder::setUuid);

        final var analysisCommand = AnalysisCommand.newBuilder()
                .setComponent(componentBuilder)
                .setFetchMeta(event.fetchMeta())
                .build();

        return new KafkaEvent<>(KafkaTopics.REPO_META_ANALYSIS_COMMAND, event.purlCoordinates(), analysisCommand, null);
    }

}
