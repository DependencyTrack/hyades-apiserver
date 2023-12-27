package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.confluent.parallelconsumer.ParallelConsumerOptions;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.common.serialization.VoidDeserializer;
import org.apache.kafka.common.serialization.VoidSerializer;
import org.cyclonedx.proto.v1_4.Bom;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static alpine.Config.AlpineKey.METRICS_ENABLED;
import static io.confluent.parallelconsumer.ParallelStreamProcessor.createEosStreamProcessor;
import static java.util.Map.entry;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.reflect.MethodUtils.getMethodsListWithAnnotation;
import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

public class KafkaProcessorManager implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(KafkaProcessorManager.class);
    private static final Map<String, Serializer<?>> SERIALIZERS = Map.ofEntries(
            entry("void", new VoidSerializer()),
            entry(String.class.getTypeName(), new StringSerializer()),
            entry(ScanKey.class.getTypeName(), new KafkaProtobufSerializer<>()),
            entry(ScanResult.class.getTypeName(), new KafkaProtobufSerializer<>())
    );
    private static final Map<String, Deserializer<?>> DESERIALIZERS = Map.ofEntries(
            entry("void", new VoidDeserializer()),
            entry(String.class.getTypeName(), new StringDeserializer()),
            entry(Bom.class.getTypeName(), new KafkaProtobufDeserializer<>(Bom.parser())),
            entry(ScanKey.class.getTypeName(), new KafkaProtobufDeserializer<>(ScanKey.parser())),
            entry(ScanResult.class.getTypeName(), new KafkaProtobufDeserializer<>(ScanResult.parser()))
    );

    private final UUID instanceId = UUID.randomUUID();
    private final Map<String, ParallelStreamProcessor<byte[], byte[]>> processors = new HashMap<>();

    private final Config config;

    KafkaProcessorManager(final Config config) {
        this.config = config;
    }

    public void registerHandler(final Object handler) {
        requireNonNull(handler);

        final List<KafkaProcessorConfig> processorConfigs =
                getMethodsListWithAnnotation(handler.getClass(), KafkaRecordHandler.class).stream()
                        .map(method -> processHandlerMethod(handler, method))
                        .toList();
        if (processorConfigs.isEmpty()) {
            throw new IllegalArgumentException("");
        }

        for (final KafkaProcessorConfig processorConfig : processorConfigs) {
            final ParallelStreamProcessor<byte[], byte[]> processor =
                    processors.computeIfAbsent(processorConfig.name(), ignored -> createProcessor(processorConfig));
            processor.poll(pollCtx -> {

            });
        }
    }

    public UUID getInstanceId() {
        return instanceId;
    }

    public Map<String, ParallelStreamProcessor<byte[], byte[]>> processors() {
        return Collections.unmodifiableMap(processors);
    }

    @Override
    public void close() {
        processors.forEach((processorName, processor) -> {
            LOGGER.info("Closing processor %s".formatted(processorName));
            processor.closeDontDrainFirst();
        });
    }

    private KafkaProcessorConfig processHandlerMethod(final Object instance, final Method method) {
        final Type[] parameterTypes = method.getGenericParameterTypes();
        if (parameterTypes.length != 1) {
            throw new IllegalArgumentException("Handler methods must accepts exactly one parameter, but %s is expecting %d"
                    .formatted(method.getName(), parameterTypes.length));
        }

        final Type parameterType = parameterTypes[0];
        if (!isConsumerRecord(parameterType) && !isConsumerRecordList(parameterType)) {
            throw new IllegalArgumentException("""
                    Handler methods must accept one or multiple %ss, but %s is expecting %s instead\
                    """.formatted(ConsumerRecord.class.getTypeName(), method.getName(), parameterType.getTypeName()));
        }

        final Type returnType = method.getGenericReturnType();
        if (!isVoid(returnType) && !isProducerRecord(returnType) && !isProducerRecordList(returnType)) {
            throw new IllegalArgumentException("""
                    Handler methods must return either %s, or one or multiple %ss, but %s is returning %s instead\
                    """.formatted(Void.TYPE.getTypeName(), ProducerRecord.class.getTypeName(), method.getName(), returnType.getTypeName()));
        }

        final Map.Entry<Type, Type> consumerKeyValueTypes;
        if (isConsumerRecord(parameterType)) {
            final var paramType = (ParameterizedType) parameterType;
            consumerKeyValueTypes = Map.entry(paramType.getActualTypeArguments()[0], paramType.getActualTypeArguments()[1]);
        } else if (isConsumerRecordList(parameterType)) {
            final var listParamType = (ParameterizedType) parameterType;
            final var recordParamType = (ParameterizedType) listParamType.getActualTypeArguments()[0];
            consumerKeyValueTypes = Map.entry(recordParamType.getActualTypeArguments()[0], recordParamType.getActualTypeArguments()[1]);
        } else {
            throw new IllegalStateException("");
        }

        if (!DESERIALIZERS.containsKey(consumerKeyValueTypes.getKey().getTypeName())) {
            throw new IllegalStateException("No deserializer known for key type %s"
                    .formatted(consumerKeyValueTypes.getKey().getTypeName()));
        }
        if (!DESERIALIZERS.containsKey(consumerKeyValueTypes.getValue().getTypeName())) {
            throw new IllegalStateException("No deserializer known for value type %s"
                    .formatted(consumerKeyValueTypes.getValue().getTypeName()));
        }

        final KafkaRecordHandler annotation = method.getAnnotation(KafkaRecordHandler.class);
        return new KafkaProcessorConfig()
                .setName(annotation.name())
                .setTopics(Arrays.asList(annotation.topics()))
                .setHandlerInstance(instance)
                .setHandlerMethod(method)
                .setMaxBatchSize(annotation.maxBatchSize())
                .setMaxConcurrency(annotation.maxConcurrency());
    }

    private ParallelStreamProcessor<byte[], byte[]> createProcessor(final KafkaProcessorConfig processorConfig) {
        final var optionsBuilder = ParallelConsumerOptions.<byte[], byte[]>builder()
                .consumer(createConsumer(processorConfig.name()))
                .maxConcurrency(processorConfig.maxConcurrency())
                .ordering(processorConfig.ordering());

        if (processorConfig.isBatch()) {
            optionsBuilder.batchSize(processorConfig.maxBatchSize());
        }

        if (config.getPropertyAsBoolean(METRICS_ENABLED)) {
            optionsBuilder
                    .meterRegistry(Metrics.getRegistry())
                    .pcInstanceTag(processorConfig.name());
        }

        final ParallelStreamProcessor<byte[], byte[]> processor = createEosStreamProcessor(optionsBuilder.build());
        processor.subscribe(processorConfig.topics());

        return processor;
    }

    private Consumer<byte[], byte[]> createConsumer(final String name) {
        final var consumerConfig = new HashMap<String, Object>();
        consumerConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        consumerConfig.put(CLIENT_ID_CONFIG, "%s-consumer-%s".formatted(name, instanceId));
        consumerConfig.put(GROUP_ID_CONFIG, name);
        consumerConfig.put(KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(AUTO_OFFSET_RESET_CONFIG, "latest");
        consumerConfig.put(ENABLE_AUTO_COMMIT_CONFIG, false);

        final var propertyPrefix = "kafka.processor.%s.consumer".formatted(name);
        final Map<String, String> extraProperties = config.getPassThroughProperties(propertyPrefix);
        for (final Map.Entry<String, String> property : extraProperties.entrySet()) {
            final String propertyName = property.getKey().replaceFirst(propertyPrefix, "");
            if (!ConsumerConfig.configNames().contains(propertyName)) {
                LOGGER.warn("Provided property %s is not a known consumer config; Skipping".formatted(propertyName));
                continue;
            }

            consumerConfig.put(propertyName, property.getValue());
        }

        final var consumer = new KafkaConsumer<byte[], byte[]>(consumerConfig);
        if (config.getPropertyAsBoolean(METRICS_ENABLED)) {
            new KafkaClientMetrics(consumer).bindTo(Metrics.getRegistry());
        }

        return consumer;
    }

    private Producer<byte[], byte[]> createProducer(final String name) {
        final var producerConfig = new HashMap<String, Object>();
        producerConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        producerConfig.put(CLIENT_ID_CONFIG, "%s-producer-%s".formatted(name, instanceId));
        producerConfig.put(KEY_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        producerConfig.put(VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

        final var propertyPrefix = "kafka.processor.%s.producer".formatted(name);
        final Map<String, String> extraProperties = config.getPassThroughProperties(propertyPrefix);
        for (final Map.Entry<String, String> property : extraProperties.entrySet()) {
            final String propertyName = property.getKey().replaceFirst(propertyPrefix, "");
            if (!ProducerConfig.configNames().contains(propertyName)) {
                LOGGER.warn("Provided property %s is not a known producer config; Skipping".formatted(propertyName));
                continue;
            }

            producerConfig.put(propertyName, property.getValue());
        }

        final var producer = new KafkaProducer<byte[], byte[]>(producerConfig);
        if (config.getPropertyAsBoolean(METRICS_ENABLED)) {
            new KafkaClientMetrics(producer).bindTo(Metrics.getRegistry());
        }

        return producer;
    }

    private static boolean isConsumerRecord(final Type type) {
        // ConsumerRecord<K, V>
        return type instanceof final ParameterizedType paramType
                && ConsumerRecord.class.getTypeName().equals(paramType.getRawType().getTypeName())
                && paramType.getActualTypeArguments().length == 2;
    }

    private static boolean isConsumerRecordList(final Type type) {
        // List<ConsumerRecord<K, V>>
        return type instanceof final ParameterizedType paramType
                && List.class.getTypeName().equals(paramType.getRawType().getTypeName())
                && paramType.getActualTypeArguments().length == 1
                && isConsumerRecord(paramType.getActualTypeArguments()[0]);
    }

    private static boolean isProducerRecord(final Type type) {
        // ProducerRecord<K, V>
        return type instanceof final ParameterizedType paramType
                && ProducerRecord.class.getTypeName().equals(paramType.getRawType().getTypeName())
                && paramType.getActualTypeArguments().length == 2;
    }

    private static boolean isProducerRecordList(final Type type) {
        // List<ProducerRecord<K, V>>
        return type instanceof final ParameterizedType paramType
                && List.class.getTypeName().equals(paramType.getRawType().getTypeName())
                && paramType.getActualTypeArguments().length == 1
                && isProducerRecord(paramType.getActualTypeArguments()[0]);
    }

    private static boolean isVoid(final Type type) {
        return Void.TYPE.getTypeName().equals(type.getTypeName());
    }

}
