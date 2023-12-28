package org.dependencytrack.event.kafka.processor.api;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.confluent.parallelconsumer.ParallelConsumerOptions;
import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;

import java.time.Duration;
import java.util.HashMap;
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

    private static final String PROPERTY_MAX_BATCH_SIZE = "max.batch.size";
    private static final int PROPERTY_MAX_BATCH_SIZE_DEFAULT = 10;
    private static final String PROPERTY_MAX_CONCURRENCY = "max.concurrency";
    private static final int PROPERTY_MAX_CONCURRENCY_DEFAULT = 3;
    private static final String PROPERTY_PROCESSING_ORDER = "processing.order";
    private static final ProcessingOrder PROPERTY_PROCESSING_ORDER_DEFAULT = ProcessingOrder.KEY;
    private static final String PROPERTY_RETRY_INITIAL_DELAY = "retry.initial.delay";
    private static final Duration PROPERTY_RETRY_INITIAL_DELAY_DEFAULT = Duration.ofSeconds(1);
    private static final String PROPERTY_RETRY_MULTIPLIER = "retry.multiplier";
    private static final int PROPERTY_RETRY_MULTIPLIER_DEFAULT = 1;
    private static final String PROPERTY_RETRY_RANDOMIZATION_FACTOR = "retry.randomization.factor";
    private static final double PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT = 0.3;
    private static final String PROPERTY_RETRY_MAX_DELAY = "retry.max.delay";
    private static final Duration PROPERTY_RETRY_MAX_DELAY_DEFAULT = Duration.ofMinutes(1);

    private final Map<String, ManagedRecordProcessor> managedProcessors = new LinkedHashMap<>();
    private final Config config;

    public RecordProcessorManager() {
        this(Config.getInstance());
    }

    RecordProcessorManager(final Config config) {
        this.config = config;
    }

    public <K, V> void register(final String name, final SingleRecordProcessor<K, V> recordProcessor, final Topic<K, V> topic) {
        final var processingStrategy = new SingleRecordProcessingStrategy<>(recordProcessor, topic.keySerde(), topic.valueSerde());
        final var parallelConsumer = createParallelConsumer(name, false);
        managedProcessors.put(name, new ManagedRecordProcessor(parallelConsumer, processingStrategy, topic));
    }

    public <K, V> void register(final String name, final BatchRecordProcessor<K, V> recordProcessor, final Topic<K, V> topic) {
        final var processingStrategy = new BatchRecordProcessingStrategy<>(recordProcessor, topic.keySerde(), topic.valueSerde());
        final var parallelConsumer = createParallelConsumer(name, true);
        managedProcessors.put(name, new ManagedRecordProcessor(parallelConsumer, processingStrategy, topic));
    }

    public void startAll() {
        for (final Map.Entry<String, ManagedRecordProcessor> managedProcessorEntry : managedProcessors.entrySet()) {
            final String processorName = managedProcessorEntry.getKey();
            final ManagedRecordProcessor managedProcessor = managedProcessorEntry.getValue();

            LOGGER.info("Starting processor %s".formatted(processorName));
            managedProcessor.parallelConsumer().subscribe(List.of(managedProcessor.topic().name()));
            managedProcessor.parallelConsumer().poll(pollCtx -> {
                final List<ConsumerRecord<byte[], byte[]>> polledRecords = pollCtx.getConsumerRecordsFlattened();
                managedProcessor.processingStrategy().processRecords(polledRecords);
            });
        }
    }

    @Override
    public void close() {
        for (final Map.Entry<String, ManagedRecordProcessor> managedProcessorEntry : managedProcessors.entrySet()) {
            final String processorName = managedProcessorEntry.getKey();
            final ManagedRecordProcessor managedProcessor = managedProcessorEntry.getValue();

            LOGGER.info("Stopping processor %s".formatted(processorName));
            managedProcessor.parallelConsumer().closeDrainFirst();
        }
    }

    private ParallelStreamProcessor<byte[], byte[]> createParallelConsumer(final String processorName, final boolean isBatch) {
        final var optionsBuilder = ParallelConsumerOptions.<byte[], byte[]>builder()
                .consumer(createConsumer(processorName));

        final Map<String, String> properties = getPassThroughProperties(processorName);

        final ProcessingOrder processingOrder = Optional.ofNullable(properties.get(PROPERTY_PROCESSING_ORDER))
                .map(String::toUpperCase)
                .map(ProcessingOrder::valueOf)
                .orElse(PROPERTY_PROCESSING_ORDER_DEFAULT);
        optionsBuilder.ordering(processingOrder);

        final int maxConcurrency = Optional.ofNullable(properties.get(PROPERTY_MAX_CONCURRENCY))
                .map(Integer::parseInt)
                .orElse(PROPERTY_MAX_CONCURRENCY_DEFAULT);
        optionsBuilder.maxConcurrency(maxConcurrency);

        if (isBatch) {
            if (processingOrder == ProcessingOrder.PARTITION) {
                LOGGER.warn("""
                        Processor %s is configured to use batching with processing order %s;
                        Batch sizes are limited by the number of partitions in the topic,
                        and may thus not yield the desired effect \
                        (https://github.com/confluentinc/parallel-consumer/issues/551)\
                        """.formatted(processorName, processingOrder));
            }

            final int maxBatchSize = Optional.ofNullable(properties.get(PROPERTY_MAX_BATCH_SIZE))
                    .map(Integer::parseInt)
                    .orElse(PROPERTY_MAX_BATCH_SIZE_DEFAULT);
            optionsBuilder.batchSize(maxBatchSize);
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
        consumerConfig.put(KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(ENABLE_AUTO_COMMIT_CONFIG, false);

        final Map<String, String> properties = getPassThroughProperties("%s.consumer".formatted(processorName));
        for (final Map.Entry<String, String> property : properties.entrySet()) {
            if (!ConsumerConfig.configNames().contains(property.getKey())) {
                LOGGER.warn("Consumer property %s was set for processor %s, but is unknown; Ignoring"
                        .formatted(property.getKey(), processorName));
                continue;
            }

            consumerConfig.put(property.getKey(), property.getValue());
        }

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

    private static IntervalFunction getRetryIntervalFunction(final Map<String, String> properties) {
        final Duration initialDelay = Optional.ofNullable(properties.get(PROPERTY_RETRY_INITIAL_DELAY))
                .map(Duration::parse)
                .orElse(PROPERTY_RETRY_INITIAL_DELAY_DEFAULT);
        final Duration maxDelay = Optional.ofNullable(properties.get(PROPERTY_RETRY_MAX_DELAY))
                .map(Duration::parse)
                .orElse(PROPERTY_RETRY_MAX_DELAY_DEFAULT);
        final int multiplier = Optional.of(properties.get(PROPERTY_RETRY_MULTIPLIER))
                .map(Integer::parseInt)
                .orElse(PROPERTY_RETRY_MULTIPLIER_DEFAULT);
        final double randomizationFactor = Optional.of(properties.get(PROPERTY_RETRY_RANDOMIZATION_FACTOR))
                .map(Double::parseDouble)
                .orElse(PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT);

        return IntervalFunction.ofExponentialRandomBackoff(initialDelay, multiplier, randomizationFactor, maxDelay);
    }

    private record ManagedRecordProcessor(ParallelStreamProcessor<byte[], byte[]> parallelConsumer,
                                          RecordProcessingStrategy processingStrategy,
                                          Topic<?, ?> topic) {
    }

}
