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
package org.dependencytrack.notification.publishing.kafka;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.PublishContext;
import org.dependencytrack.proto.notification.v1.Notification;

import java.util.concurrent.ExecutionException;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisher implements NotificationPublisher {

    private final KafkaProducer<String, byte[]> kafkaProducer;

    KafkaNotificationPublisher(final KafkaProducer<String, byte[]> kafkaProducer) {
        this.kafkaProducer = kafkaProducer;
    }

    @Override
    public void publish(final PublishContext ctx, final Notification notification) {
        final String topicName = ctx.destination();
        if (topicName == null || topicName.isEmpty()) {
            throw new IllegalStateException("No destination (topic name) configured");
        }

        final byte[] notificationContent;
        if (ctx.templateRenderer() != null) {
            notificationContent = ctx.templateRenderer().render(notification);
        } else {
            notificationContent = notification.toByteArray();
        }

        // TODO: Extract key from notification.
        final var producerRecord = new ProducerRecord<>(
                topicName, "TODO", notificationContent);

        try {
            kafkaProducer.send(producerRecord).get();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to send record", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while sending record", e);
        }
    }

}
