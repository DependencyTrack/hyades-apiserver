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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.binder.kafka.KafkaStreamsMetrics;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.streams.exception.KafkaStreamsDeserializationExceptionHandler;
import org.dependencytrack.event.kafka.streams.exception.KafkaStreamsProductionExceptionHandler;
import org.dependencytrack.event.kafka.streams.exception.KafkaStreamsUncaughtExceptionHandler;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KafkaStreamsInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsInitializer.class);
    private static final Duration DRAIN_TIMEOUT_DURATION;
    private static final Pattern CONSUMER_PREFIX_PATTERN;
    private static final Pattern PRODUCER_PREFIX_PATTERN;

    static {
        DRAIN_TIMEOUT_DURATION = Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_DRAIN_TIMEOUT_DURATION));

        CONSUMER_PREFIX_PATTERN = Pattern.compile("^(%s|%s|%s)".formatted(
                Pattern.quote(StreamsConfig.CONSUMER_PREFIX),
                Pattern.quote(StreamsConfig.GLOBAL_CONSUMER_PREFIX),
                Pattern.quote(StreamsConfig.MAIN_CONSUMER_PREFIX)
        ));

        PRODUCER_PREFIX_PATTERN = Pattern.compile("^" + Pattern.quote(StreamsConfig.PRODUCER_PREFIX));
    }

    private static KafkaStreams STREAMS;
    private static KafkaStreamsMetrics STREAMS_METRICS;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka streams");

        STREAMS = new KafkaStreams(new KafkaStreamsTopologyFactory().createTopology(), new StreamsConfig(getDefaultProperties()));
        STREAMS.setUncaughtExceptionHandler(new KafkaStreamsUncaughtExceptionHandler());

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            LOGGER.info("Registering Kafka streams metrics");
            STREAMS_METRICS = new KafkaStreamsMetrics(STREAMS);
            STREAMS_METRICS.bindTo(Metrics.getRegistry());
        }

        STREAMS.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (STREAMS != null) {
            LOGGER.info("Closing Kafka streams");

            // Close streams, but wait for a configurable amount of time
            // for it to process any polled events.
            STREAMS.close(DRAIN_TIMEOUT_DURATION);

            if (STREAMS_METRICS != null) {
                STREAMS_METRICS.close();
            }
        }
    }

    public static KafkaStreams getKafkaStreams() {
        return STREAMS;
    }

    static Properties getDefaultProperties() {
        final var properties = new Properties();
        properties.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_BOOTSTRAP_SERVERS));
        StringBuilder applicationName = new StringBuilder(Config.getInstance().getProperty(ConfigKey.KAFKA_TOPIC_PREFIX)).append(Config.getInstance().getProperty(ConfigKey.APPLICATION_ID));
        properties.put(StreamsConfig.APPLICATION_ID_CONFIG, applicationName.toString());

        properties.put(StreamsConfig.DEFAULT_DESERIALIZATION_EXCEPTION_HANDLER_CLASS_CONFIG, KafkaStreamsDeserializationExceptionHandler.class);
        properties.put(StreamsConfig.DEFAULT_PRODUCTION_EXCEPTION_HANDLER_CLASS_CONFIG, KafkaStreamsProductionExceptionHandler.class);

        properties.put(StreamsConfig.NUM_STREAM_THREADS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_NUM_STREAM_THREADS));
        properties.put(StreamsConfig.STATE_DIR_CONFIG, Paths.get(Config.getInstance().getDataDirectorty().getAbsolutePath(), "kafka-streams").toString());
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_AUTO_OFFSET_RESET));
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_TLS_ENABLED)) {
            properties.put(StreamsConfig.SECURITY_PROTOCOL_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_TLS_PROTOCOL));
            properties.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PATH));
            properties.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PASSWORD));
            if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_MTLS_ENABLED)) {
                properties.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PATH));
                properties.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PASSWORD));
            }
        }
        properties.put(StreamsConfig.METRICS_RECORDING_LEVEL_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_METRICS_RECORDING_LEVEL));
        properties.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG, "1000");
        properties.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name);
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        properties.put(ProducerConfig.ACKS_CONFIG, "all");

        final Map<String, String> passThroughProperties = Config.getInstance().getPassThroughProperties("kafka.streams");
        for (final Map.Entry<String, String> passThroughProperty : passThroughProperties.entrySet()) {
            final String key = passThroughProperty.getKey().replaceFirst("^kafka\\.streams\\.", "");
            if (StreamsConfig.configDef().names().contains(key)) {
                properties.put(key, passThroughProperty.getValue());
            } else {
                final Matcher consumerPrefixMatcher = CONSUMER_PREFIX_PATTERN.matcher(key);
                final Matcher producerPrefixMatcher = PRODUCER_PREFIX_PATTERN.matcher(key);

                final boolean isValidConsumerProperty = ConsumerConfig.configNames().contains(key)
                        || (consumerPrefixMatcher.find() && ConsumerConfig.configNames().contains(consumerPrefixMatcher.replaceFirst("")));
                final boolean isValidProducerProperty = ProducerConfig.configNames().contains(key)
                        || (producerPrefixMatcher.find() && ProducerConfig.configNames().contains(producerPrefixMatcher.replaceFirst("")));
                if (isValidConsumerProperty || isValidProducerProperty) {
                    properties.put(key, passThroughProperty.getValue());
                } else {
                    LOGGER.warn("%s is not a known Streams, Consumer, or Producer property; Ignoring".formatted(key));
                }
            }
        }

        return properties;
    }

}
