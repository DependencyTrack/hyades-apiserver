package org.dependencytrack.event.kafka.processor.api;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.confluent.parallelconsumer.ParallelConsumerOptions;
import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.dependencytrack.event.kafka.KafkaTopics.Topic;

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

        final Map<String, String> properties = passThroughProperties(processorName);

        final ProcessingOrder processingOrder = Optional.ofNullable(properties.get("processing.order"))
                .map(String::toUpperCase)
                .map(ProcessingOrder::valueOf)
                .orElse(ProcessingOrder.KEY);
        optionsBuilder.ordering(processingOrder);

        final int maxConcurrency = Optional.ofNullable(properties.get("max.concurrency"))
                .map(Integer::parseInt)
                .orElse(3);
        optionsBuilder.maxConcurrency(maxConcurrency);

        if (isBatch) {
            if (processingOrder == ProcessingOrder.PARTITION) {
                LOGGER.warn("""
                        Processor %s is configured to use batching with processing order %s;
                        Batch sizes are limited by the number of partitions in the topic,
                        and may not yield the desired effect \
                        (https://github.com/confluentinc/parallel-consumer/issues/551)\
                        """.formatted(processorName, processingOrder));
            }

            final int maxBatchSize = Optional.ofNullable(properties.get("max.batch.size"))
                    .map(Integer::parseInt)
                    .orElse(10);
            optionsBuilder.batchSize(maxBatchSize);
        }

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

        final Map<String, String> properties = passThroughProperties("%s.consumer".formatted(processorName));
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

    private Map<String, String> passThroughProperties(final String prefix) {
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

    private record ManagedRecordProcessor(ParallelStreamProcessor<byte[], byte[]> parallelConsumer,
                                          RecordProcessingStrategy processingStrategy,
                                          Topic<?, ?> topic) {
    }

}
