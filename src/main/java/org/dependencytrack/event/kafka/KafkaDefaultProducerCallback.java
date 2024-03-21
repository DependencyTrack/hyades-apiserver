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

import alpine.common.logging.Logger;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.RecordMetadata;

/**
 * A Kafka producer {@link Callback} that simply logs any errors.
 * <p>
 * It is used by {@link KafkaEventDispatcher} when no other {@link Callback} is provided.
 */
class KafkaDefaultProducerCallback implements Callback {

    private final Logger logger;
    private final String topic;
    private final Object key;

    KafkaDefaultProducerCallback(final Logger logger, final String topic, final Object key) {
        this.logger = logger;
        this.topic = topic;
        this.key = key;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onCompletion(final RecordMetadata metadata, final Exception exception) {
        if (exception != null) {
            logger.error("Failed to produce record with key %s to topic %s".formatted(key, topic), exception);
        }
    }

}
