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
package org.dependencytrack.event.kafka.processor.api;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.confluent.parallelconsumer.ParallelConsumerOptions;
import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;
import io.confluent.parallelconsumer.ParallelEoSStreamProcessor;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsOptions;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.dependencytrack.util.ConfigUtil;
import org.eclipse.microprofile.health.HealthCheckResponse;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.SECURITY_PROTOCOL_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_MAX_BATCH_SIZE;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_MAX_BATCH_SIZE_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_MAX_CONCURRENCY;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_MAX_CONCURRENCY_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_PROCESSING_ORDER;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_PROCESSING_ORDER_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_INITIAL_DELAY_MS;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_INITIAL_DELAY_MS_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_MAX_DELAY_MS;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_MAX_DELAY_MS_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_MULTIPLIER;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_MULTIPLIER_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_RANDOMIZATION_FACTOR;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_SHUTDOWN_TIMEOUT_MS;
import static org.dependencytrack.event.kafka.processor.api.ProcessorProperties.PROPERTY_SHUTDOWN_TIMEOUT_MS_DEFAULT;

public class ProcessorManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(ProcessorManager.class);
    private static final Pattern PROCESSOR_NAME_PATTERN = Pattern.compile("^[a-z.]+$");

    private final Map<String, ManagedProcessor> managedProcessors = new LinkedHashMap<>();
    private final UUID instanceId;
    private final Config config;
    private AdminClient adminClient;

    public ProcessorManager() {
        this.instanceId = UUID.randomUUID();
        this.config = Config.getInstance();
    }

    /**
     * Register a new {@link Processor}.
     *
     * @param name      Name of the processor to register
     * @param processor The processor to register
     * @param topic     The topic to have the processor subscribe to
     * @param <K>       Type of record keys in the topic
     * @param <V>       Type of record values in the topic
     */
    public <K, V> void registerProcessor(final String name, final Topic<K, V> topic, final Processor<K, V> processor) {
        requireValidProcessorName(name);
        final var processingStrategy = new SingleRecordProcessingStrategy<>(processor, topic.keySerde(), topic.valueSerde());
        final ParallelStreamProcessor<byte[], byte[]> parallelConsumer = createParallelConsumer(name, topic, false);
        managedProcessors.put(name, new ManagedProcessor(parallelConsumer, processingStrategy, topic.name()));
    }

    /**
     * Register a new {@link BatchProcessor}.
     *
     * @param name      Name of the processor to register
     * @param processor The processor to register
     * @param topic     The topic to have the processor subscribe to
     * @param <K>       Type of record keys in the topic
     * @param <V>       Type of record values in the topic
     */
    public <K, V> void registerBatchProcessor(final String name, final Topic<K, V> topic, final BatchProcessor<K, V> processor) {
        requireValidProcessorName(name);
        final var processingStrategy = new BatchProcessingStrategy<>(processor, topic.keySerde(), topic.valueSerde());
        final ParallelStreamProcessor<byte[], byte[]> parallelConsumer = createParallelConsumer(name, topic, true);
        managedProcessors.put(name, new ManagedProcessor(parallelConsumer, processingStrategy, topic.name()));
    }

    @SuppressWarnings("resource")
    public void startAll() {
        ensureTopicsExist();

        for (final Map.Entry<String, ManagedProcessor> entry : managedProcessors.entrySet()) {
            final String processorName = entry.getKey();
            final ManagedProcessor managedProcessor = entry.getValue();

            LOGGER.info("Starting processor %s to consume from topic %s".formatted(processorName, managedProcessor.topic()));
            managedProcessor.parallelConsumer().subscribe(List.of(managedProcessor.topic()));
            managedProcessor.parallelConsumer().poll(pollCtx -> {
                // NB: Unless batching is enabled, the below list only ever contains a single record.
                final List<ConsumerRecord<byte[], byte[]>> polledRecords = pollCtx.getConsumerRecordsFlattened();
                managedProcessor.processingStrategy().processRecords(polledRecords);
            });
        }
    }

    public HealthCheckResponse probeHealth() {
        final var responseBuilder = HealthCheckResponse.named("kafka-processors");

        boolean isUp = true;
        for (final Map.Entry<String, ManagedProcessor> entry : managedProcessors.entrySet()) {
            final String processorName = entry.getKey();
            final ParallelStreamProcessor<?, ?> parallelConsumer = entry.getValue().parallelConsumer();
            final boolean isProcessorUp = !parallelConsumer.isClosedOrFailed();

            responseBuilder.withData(processorName, isProcessorUp
                    ? HealthCheckResponse.Status.UP.name()
                    : HealthCheckResponse.Status.DOWN.name());
            if (isProcessorUp
                    && parallelConsumer instanceof final ParallelEoSStreamProcessor<?, ?> concreteParallelConsumer
                    && concreteParallelConsumer.getFailureCause() != null) {
                responseBuilder.withData("%s_failure_reason".formatted(processorName),
                        concreteParallelConsumer.getFailureCause().getMessage());
            }

            isUp &= isProcessorUp;
        }

        return responseBuilder.status(isUp).build();
    }

    @Override
    @SuppressWarnings("resource")
    public void close() {
        if (adminClient != null) {
            LOGGER.debug("Closing admin client");
            adminClient.close();
        }

        for (final Map.Entry<String, ManagedProcessor> entry : managedProcessors.entrySet()) {
            final String processorName = entry.getKey();
            final ManagedProcessor managedProcessor = entry.getValue();

            LOGGER.info("Stopping processor %s".formatted(processorName));
            managedProcessor.parallelConsumer().closeDontDrainFirst();
        }
    }

    private void ensureTopicsExist() {
        final List<String> topicNames = managedProcessors.values().stream().map(ManagedProcessor::topic).toList();
        LOGGER.info("Verifying existence of subscribed topics: %s".formatted(topicNames));

        final DescribeTopicsResult topicsResult = adminClient().describeTopics(topicNames, new DescribeTopicsOptions().timeoutMs(3_000));
        final var exceptionsByTopicName = new HashMap<String, Throwable>();
        for (final Map.Entry<String, KafkaFuture<TopicDescription>> entry : topicsResult.topicNameValues().entrySet()) {
            final String topicName = entry.getKey();
            try {
                entry.getValue().get();
            } catch (ExecutionException e) {
                exceptionsByTopicName.put(topicName, e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("""
                        Thread was interrupted while waiting for broker response. \
                        The existence of topic %s can not be determined.""".formatted(topicName), e);
            }
        }

        if (!exceptionsByTopicName.isEmpty()) {
            final String exceptionSummary = exceptionsByTopicName.entrySet().stream()
                    .map(entry -> "{topic=%s, error=%s}".formatted(entry.getKey(), entry.getValue()))
                    .collect(Collectors.joining(", ", "[", "]"));
            throw new IllegalStateException("Existence of %d topic(s) could not be verified: %s"
                    .formatted(exceptionsByTopicName.size(), exceptionSummary));
        }
    }

    private int getTopicPartitionCount(final String topicName) {
        LOGGER.debug("Determining partition count of topic %s".formatted(topicName));
        final DescribeTopicsResult topicsResult = adminClient().describeTopics(List.of(topicName), new DescribeTopicsOptions().timeoutMs(3_000));
        final KafkaFuture<TopicDescription> topicDescriptionFuture = topicsResult.topicNameValues().get(topicName);

        try {
            final TopicDescription topicDescription = topicDescriptionFuture.get();
            return topicDescription.partitions().size();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to determine partition count of topic %s".formatted(topicName), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("""
                    Thread was interrupted while waiting for broker response. \
                    The partition count of topic %s can not be determined.""".formatted(topicName), e);
        }
    }

    private ParallelStreamProcessor<byte[], byte[]> createParallelConsumer(final String processorName, final Topic<?, ?> topic, final boolean isBatch) {
        final var optionsBuilder = ParallelConsumerOptions.<byte[], byte[]>builder()
                .consumer(createConsumer(processorName))
                .ignoreReflectiveAccessExceptionsForAutoCommitDisabledCheck(true);

        final Map<String, String> properties = getPassThroughProperties(processorName.toLowerCase());

        final ProcessingOrder processingOrder = Optional.ofNullable(properties.get(PROPERTY_PROCESSING_ORDER))
                .map(String::toUpperCase)
                .map(ProcessingOrder::valueOf)
                .orElse(PROPERTY_PROCESSING_ORDER_DEFAULT);
        optionsBuilder.ordering(processingOrder);

        final int maxConcurrency = Optional.ofNullable(properties.get(PROPERTY_MAX_CONCURRENCY))
                .map(Integer::parseInt)
                .orElse(PROPERTY_MAX_CONCURRENCY_DEFAULT);
        if (maxConcurrency == -1) {
            final int numTopicPartitions = getTopicPartitionCount(topic.name());
            LOGGER.debug("""
                    Max concurrency of processor %s is configured to match the partition count of topic %s (%d)\
                    """.formatted(processorName, topic.name(), numTopicPartitions));
            optionsBuilder.maxConcurrency(numTopicPartitions);
        } else {
            optionsBuilder.maxConcurrency(maxConcurrency);
        }

        final Optional<String> optionalMaxBatchSizeProperty = Optional.ofNullable(properties.get(PROPERTY_MAX_BATCH_SIZE));
        if (isBatch) {
            if (processingOrder == ProcessingOrder.PARTITION) {
                LOGGER.warn("""
                        Processor %s is configured to use batching with processing order %s; \
                        Batch sizes are limited by the number of partitions in the topic, \
                        and may thus not yield the desired effect \
                        (https://github.com/confluentinc/parallel-consumer/issues/551)\
                        """.formatted(processorName, processingOrder));
            }

            final int maxBatchSize = optionalMaxBatchSizeProperty
                    .map(Integer::parseInt)
                    .orElse(PROPERTY_MAX_BATCH_SIZE_DEFAULT);
            optionsBuilder.batchSize(maxBatchSize);
        } else if (optionalMaxBatchSizeProperty.isPresent()) {
            LOGGER.warn("Processor %s is configured with %s, but it is not a batch processor; Ignoring property"
                    .formatted(processorName, PROPERTY_MAX_BATCH_SIZE));
        }

        final IntervalFunction retryIntervalFunction = getRetryIntervalFunction(properties);
        optionsBuilder.retryDelayProvider(recordCtx -> {
            final long delayMillis = retryIntervalFunction.apply(recordCtx.getNumberOfFailedAttempts());
            return Duration.ofMillis(delayMillis);
        });

        final long shutdownTimeoutMs = Optional.ofNullable(properties.get(PROPERTY_SHUTDOWN_TIMEOUT_MS))
                .map(Long::parseLong)
                .orElse(PROPERTY_SHUTDOWN_TIMEOUT_MS_DEFAULT);
        optionsBuilder.shutdownTimeout(Duration.ofMillis(shutdownTimeoutMs));

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            optionsBuilder
                    .meterRegistry(Metrics.getRegistry())
                    .pcInstanceTag(processorName);
        }

        final ParallelConsumerOptions<byte[], byte[]> options = optionsBuilder.build();
        LOGGER.debug("Creating parallel consumer for processor %s with options %s".formatted(processorName, options));
        return ParallelStreamProcessor.createEosStreamProcessor(options);
    }

    private Consumer<byte[], byte[]> createConsumer(final String processorName) {
        final var consumerConfig = new HashMap<String, Object>();
        consumerConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        consumerConfig.put(CLIENT_ID_CONFIG, "%s-%s-consumer".formatted(instanceId, processorName));
        consumerConfig.put(GROUP_ID_CONFIG, processorName);
        consumerConfig.putAll(getGlobalTlsConfig());

        final String propertyPrefix = "%s.consumer".formatted(processorName.toLowerCase());
        final Map<String, String> properties = getPassThroughProperties(propertyPrefix);
        for (final Map.Entry<String, String> property : properties.entrySet()) {
            if (!ConsumerConfig.configNames().contains(property.getKey())) {
                LOGGER.warn("Consumer property %s was set for processor %s, but is unknown; Ignoring"
                        .formatted(property.getKey(), processorName));
                continue;
            }

            consumerConfig.put(property.getKey(), property.getValue());
        }

        // Properties that MUST NOT be overwritten under any circumstance have to be applied
        // AFTER pass-through properties.
        consumerConfig.put(KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(ENABLE_AUTO_COMMIT_CONFIG, false); // Commits are managed by parallel consumer

        LOGGER.debug("Creating consumer for processor %s with options %s".formatted(processorName, consumerConfig));
        final var consumer = new KafkaConsumer<byte[], byte[]>(consumerConfig);

        if (config.getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new KafkaClientMetrics(consumer).bindTo(Metrics.getRegistry());
        }

        return consumer;
    }

    private AdminClient adminClient() {
        if (adminClient != null) {
            return adminClient;
        }

        final var adminClientConfig = new HashMap<String, Object>();
        adminClientConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        adminClientConfig.put(CLIENT_ID_CONFIG, "%s-admin-client".formatted(instanceId));
        adminClientConfig.putAll(getGlobalTlsConfig());

        LOGGER.debug("Creating admin client with options %s".formatted(adminClientConfig));
        adminClient = AdminClient.create(adminClientConfig);
        return adminClient;
    }

    private Map<String, Object> getGlobalTlsConfig() {
        if (!config.getPropertyAsBoolean(ConfigKey.KAFKA_TLS_ENABLED)) {
            return Collections.emptyMap();
        }

        final var tlsConfig = new HashMap<String, Object>();
        tlsConfig.put(SECURITY_PROTOCOL_CONFIG, config.getProperty(ConfigKey.KAFKA_TLS_PROTOCOL));
        tlsConfig.put(SSL_TRUSTSTORE_LOCATION_CONFIG, config.getProperty(ConfigKey.KAFKA_TRUST_STORE_PATH));
        tlsConfig.put(SSL_TRUSTSTORE_PASSWORD_CONFIG, config.getProperty(ConfigKey.KAFKA_TRUST_STORE_PASSWORD));

        if (config.getPropertyAsBoolean(ConfigKey.KAFKA_MTLS_ENABLED)) {
            tlsConfig.put(SSL_KEYSTORE_LOCATION_CONFIG, config.getProperty(ConfigKey.KAFKA_KEY_STORE_PATH));
            tlsConfig.put(SSL_KEYSTORE_PASSWORD_CONFIG, config.getProperty(ConfigKey.KAFKA_KEY_STORE_PASSWORD));
        }

        return tlsConfig;
    }

    private Map<String, String> getPassThroughProperties(final String prefix) {
        final String fullPrefix = "kafka.processor.%s".formatted(prefix);
        final Pattern fullPrefixPattern = Pattern.compile(Pattern.quote("%s.".formatted(fullPrefix)));

        final Map<String, String> properties = ConfigUtil.getPassThroughProperties(config, fullPrefix);
        if (properties.isEmpty()) {
            return properties;
        }

        final var trimmedProperties = new HashMap<String, String>(properties.size());
        for (final Map.Entry<String, String> property : properties.entrySet()) {
            final String trimmedKey = fullPrefixPattern.matcher(property.getKey()).replaceFirst("");
            trimmedProperties.put(trimmedKey, property.getValue());
        }

        return trimmedProperties;
    }

    /**
     * Validate a given {@link Processor} name.
     * <p>
     * Due to how Alpine's {@link Config} is resolved, {@link Processor} names must have a specific
     * format in order to be able to resolve properties for them.
     *
     * @param name The {@link Processor} name to validate.
     */
    private static void requireValidProcessorName(final String name) {
        if (name == null) {
            throw new IllegalArgumentException("name must not be null");
        }
        if (!PROCESSOR_NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException("name is invalid; names must match the regular expression %s"
                    .formatted(PROCESSOR_NAME_PATTERN.pattern()));
        }
    }

    private static IntervalFunction getRetryIntervalFunction(final Map<String, String> properties) {
        final long initialDelayMs = Optional.ofNullable(properties.get(PROPERTY_RETRY_INITIAL_DELAY_MS))
                .map(Long::parseLong)
                .orElse(PROPERTY_RETRY_INITIAL_DELAY_MS_DEFAULT);
        final long maxDelayMs = Optional.ofNullable(properties.get(PROPERTY_RETRY_MAX_DELAY_MS))
                .map(Long::parseLong)
                .orElse(PROPERTY_RETRY_MAX_DELAY_MS_DEFAULT);
        final int multiplier = Optional.ofNullable(properties.get(PROPERTY_RETRY_MULTIPLIER))
                .map(Integer::parseInt)
                .orElse(PROPERTY_RETRY_MULTIPLIER_DEFAULT);
        final double randomizationFactor = Optional.ofNullable(properties.get(PROPERTY_RETRY_RANDOMIZATION_FACTOR))
                .map(Double::parseDouble)
                .orElse(PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT);

        return IntervalFunction.ofExponentialRandomBackoff(Duration.ofMillis(initialDelayMs),
                multiplier, randomizationFactor, Duration.ofMillis(maxDelayMs));
    }

    private record ManagedProcessor(ParallelStreamProcessor<byte[], byte[]> parallelConsumer,
                                    ProcessingStrategy processingStrategy, String topic) {
    }

}
