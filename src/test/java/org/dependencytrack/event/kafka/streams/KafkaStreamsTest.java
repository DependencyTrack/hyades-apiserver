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
package org.dependencytrack.event.kafka.streams;

import net.mguenther.kafka.junit.ExternalKafkaCluster;
import net.mguenther.kafka.junit.TopicConfig;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.proto.notification.v1.Notification;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.testcontainers.redpanda.RedpandaContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

abstract class KafkaStreamsTest extends PersistenceCapableTest {

    @Rule
    public RedpandaContainer container = new RedpandaContainer(DockerImageName
            .parse("docker.redpanda.com/vectorized/redpanda:v23.3.11"));

    KafkaStreams kafkaStreams;
    ExternalKafkaCluster kafka;
    private final Supplier<Topology> topologySupplier;
    private Path kafkaStreamsStateDirectory;

    protected KafkaStreamsTest() {
        this(new KafkaStreamsTopologyFactory()::createTopology);
    }

    protected KafkaStreamsTest(final Supplier<Topology> topologySupplier) {
        this.topologySupplier = topologySupplier;
    }

    @Before
    public void before() throws Exception {
        super.before();

        kafka = ExternalKafkaCluster.at(container.getBootstrapServers());

        kafka.createTopic(TopicConfig
                .withName(KafkaTopics.VULN_ANALYSIS_COMMAND.name())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopics.VULN_ANALYSIS_RESULT.name())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopics.REPO_META_ANALYSIS_RESULT.name())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopics.NEW_VULNERABILITY.name())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));
        kafka.createTopic(TopicConfig
                .withName(KafkaTopics.NEW_EPSS.name())
                .withNumberOfPartitions(3)
                .withNumberOfReplicas(1));

        kafkaStreamsStateDirectory = Files.createTempDirectory(getClass().getSimpleName());

        final var streamsConfig = KafkaStreamsInitializer.getDefaultProperties();
        streamsConfig.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, container.getBootstrapServers());
        streamsConfig.put(StreamsConfig.APPLICATION_ID_CONFIG, getClass().getSimpleName());
        streamsConfig.put(StreamsConfig.STATE_DIR_CONFIG, kafkaStreamsStateDirectory.toString());
        streamsConfig.put(StreamsConfig.NUM_STREAM_THREADS_CONFIG, "3");

        kafkaStreams = new KafkaStreams(topologySupplier.get(), streamsConfig);
        kafkaStreams.start();

        await("Kafka Streams Readiness")
                .atMost(Duration.ofSeconds(15))
                .failFast(() -> assertThat(kafkaStreams.state()).isNotIn(
                        KafkaStreams.State.ERROR,
                        KafkaStreams.State.PENDING_ERROR,
                        KafkaStreams.State.PENDING_SHUTDOWN
                ))
                .untilAsserted(() -> assertThat(kafkaStreams.state()).isEqualTo(KafkaStreams.State.RUNNING));
    }

    @After
    public void after() {
        if (kafkaStreams != null) {
            kafkaStreams.close();
        }
        if (kafkaStreamsStateDirectory != null) {
            kafkaStreamsStateDirectory.toFile().delete();
        }

        super.after();
    }

    public static class NotificationDeserializer extends KafkaProtobufDeserializer<Notification> {

        public NotificationDeserializer() {
            super(Notification.parser());
        }

    }

}
