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
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;
import org.eclipse.microprofile.health.HealthCheckResponse;

import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

public class RecordProcessorManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(RecordProcessorManager.class);
    private static final Pattern PROCESSOR_NAME_PATTERN = Pattern.compile("^[a-z.]+$");

    private static final String PROPERTY_MAX_BATCH_SIZE = "max.batch.size";
    private static final int PROPERTY_MAX_BATCH_SIZE_DEFAULT = 10;
    private static final String PROPERTY_MAX_CONCURRENCY = "max.concurrency";
    private static final int PROPERTY_MAX_CONCURRENCY_DEFAULT = 1;
    private static final String PROPERTY_PROCESSING_ORDER = "processing.order";
    private static final ProcessingOrder PROPERTY_PROCESSING_ORDER_DEFAULT = ProcessingOrder.PARTITION;
    private static final String PROPERTY_RETRY_INITIAL_DELAY_MS = "retry.initial.delay.ms";
    private static final long PROPERTY_RETRY_INITIAL_DELAY_MS_DEFAULT = 1000; // 1s
    private static final String PROPERTY_RETRY_MULTIPLIER = "retry.multiplier";
    private static final int PROPERTY_RETRY_MULTIPLIER_DEFAULT = 1;
    private static final String PROPERTY_RETRY_RANDOMIZATION_FACTOR = "retry.randomization.factor";
    private static final double PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT = 0.3;
    private static final String PROPERTY_RETRY_MAX_DELAY_MS = "retry.max.delay.ms";
    private static final long PROPERTY_RETRY_MAX_DELAY_MS_DEFAULT = 60 * 1000; // 60s

    private final Map<String, ManagedProcessor> managedProcessors = new LinkedHashMap<>();
    private final Config config;

    public RecordProcessorManager() {
        this(Config.getInstance());
    }

    public RecordProcessorManager(final Config config) {
        this.config = config;
    }

    /**
     * Register a new {@link SingleRecordProcessor}.
     *
     * @param name      Name of the processor to register
     * @param processor The processor to register
     * @param topic     The topic to have the processor subscribe to
     * @param <K>       Type of record keys in the topic
     * @param <V>       Type of record values in the topic
     */
    public <K, V> void registerProcessor(final String name, final SingleRecordProcessor<K, V> processor, final Topic<K, V> topic) {
        requireValidProcessorName(name);
        final var processingStrategy = new SingleRecordProcessingStrategy<>(processor, topic.keySerde(), topic.valueSerde());
        final ParallelStreamProcessor<byte[], byte[]> parallelConsumer = createParallelConsumer(name, false);
        managedProcessors.put(name, new ManagedProcessor(parallelConsumer, processingStrategy, topic.name()));
    }

    /**
     * Register a new {@link BatchRecordProcessor}.
     *
     * @param name      Name of the processor to register
     * @param processor The processor to register
     * @param topic     The topic to have the processor subscribe to
     * @param <K>       Type of record keys in the topic
     * @param <V>       Type of record values in the topic
     */
    public <K, V> void registerBatchProcessor(final String name, final BatchRecordProcessor<K, V> processor, final Topic<K, V> topic) {
        requireValidProcessorName(name);
        final var processingStrategy = new BatchRecordProcessingStrategy<>(processor, topic.keySerde(), topic.valueSerde());
        final ParallelStreamProcessor<byte[], byte[]> parallelConsumer = createParallelConsumer(name, true);
        managedProcessors.put(name, new ManagedProcessor(parallelConsumer, processingStrategy, topic.name()));
    }

    @SuppressWarnings("resource")
    public void startAll() {
        for (final Map.Entry<String, ManagedProcessor> entry : managedProcessors.entrySet()) {
            final String processorName = entry.getKey();
            final ManagedProcessor managedProcessor = entry.getValue();

            LOGGER.info("Starting processor %s".formatted(processorName));
            managedProcessor.parallelConsumer().subscribe(List.of(managedProcessor.topic()));
            managedProcessor.parallelConsumer().poll(pollCtx -> {
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
        final Iterator<Map.Entry<String, ManagedProcessor>> entryIterator = managedProcessors.entrySet().iterator();
        while (entryIterator.hasNext()) {
            final Map.Entry<String, ManagedProcessor> entry = entryIterator.next();
            final String processorName = entry.getKey();
            final ManagedProcessor managedProcessor = entry.getValue();

            LOGGER.info("Stopping processor %s".formatted(processorName));
            managedProcessor.parallelConsumer().closeDontDrainFirst();
            entryIterator.remove();
        }
    }

    private ParallelStreamProcessor<byte[], byte[]> createParallelConsumer(final String processorName, final boolean isBatch) {
        final var optionsBuilder = ParallelConsumerOptions.<byte[], byte[]>builder()
                .consumer(createConsumer(processorName));

        final Map<String, String> properties = getPassThroughProperties(processorName.toLowerCase());

        final ProcessingOrder processingOrder = Optional.ofNullable(properties.get(PROPERTY_PROCESSING_ORDER))
                .map(String::toUpperCase)
                .map(ProcessingOrder::valueOf)
                .orElse(PROPERTY_PROCESSING_ORDER_DEFAULT);
        optionsBuilder.ordering(processingOrder);

        final int maxConcurrency = Optional.ofNullable(properties.get(PROPERTY_MAX_CONCURRENCY))
                .map(Integer::parseInt)
                .orElse(PROPERTY_MAX_CONCURRENCY_DEFAULT);
        optionsBuilder.maxConcurrency(maxConcurrency);

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
        consumerConfig.put(CLIENT_ID_CONFIG, "%s-consumer".formatted(processorName));
        consumerConfig.put(GROUP_ID_CONFIG, processorName);

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

    private Map<String, String> getPassThroughProperties(final String prefix) {
        final String fullPrefix = "kafka.processor.%s".formatted(prefix);
        final Pattern fullPrefixPattern = Pattern.compile(Pattern.quote("%s.".formatted(fullPrefix)));

        final Map<String, String> properties = config.getPassThroughProperties(fullPrefix);
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
                                    RecordProcessingStrategy processingStrategy,
                                    String topic) {
    }

}
