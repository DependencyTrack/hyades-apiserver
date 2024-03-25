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
package org.dependencytrack.health;

import org.apache.kafka.streams.KafkaStreams;
import org.dependencytrack.event.kafka.streams.KafkaStreamsInitializer;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * A {@link HealthCheck} for Kafka Streams.
 * <p>
 * This code has been copied and slightly modified from Quarkus' Kafka Streams extension.
 *
 * @see <a href="https://github.com/quarkusio/quarkus/blob/2.16.5.Final/extensions/kafka-streams/runtime/src/main/java/io/quarkus/kafka/streams/runtime/health/KafkaStreamsStateHealthCheck.java">Quarkus Kafka Streams Health Check</a>
 */
@Liveness
class KafkaStreamsHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        final var responseBuilder = HealthCheckResponse.named("kafka-streams");

        final KafkaStreams kafkaStreams = KafkaStreamsInitializer.getKafkaStreams();
        if (kafkaStreams == null) {
            return responseBuilder.down().build();
        }

        try {
            final KafkaStreams.State state = kafkaStreams.state();
            responseBuilder.status(state.isRunningOrRebalancing())
                    .withData("state", state.name());
        } catch (Exception e) {
            responseBuilder.down()
                    .withData("exception_message", e.getMessage());
        }

        return responseBuilder.build();
    }

}
