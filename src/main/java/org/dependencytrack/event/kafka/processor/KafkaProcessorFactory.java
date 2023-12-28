package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import alpine.common.logging.Logger;
import io.confluent.parallelconsumer.ParallelConsumerOptions;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.common.serialization.VoidDeserializer;
import org.apache.kafka.common.serialization.VoidSerializer;
import org.cyclonedx.proto.v1_4.Bom;
import org.dependencytrack.event.kafka.processor.api.RecordBatchConsumer;
import org.dependencytrack.event.kafka.processor.api.RecordBatchProcessor;
import org.dependencytrack.event.kafka.processor.api.RecordConsumer;
import org.dependencytrack.event.kafka.processor.api.RecordProcessor;
import org.dependencytrack.event.kafka.processor.api.SingleRecordProcessingStrategy;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ACKS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

public class KafkaProcessorFactory {

    private static final Logger LOGGER = Logger.getLogger(KafkaProcessorFactory.class);
    private static final Map<String, Deserializer<?>> DESERIALIZERS = Map.ofEntries(
            Map.entry(Void.TYPE.getTypeName(), new VoidDeserializer()),
            Map.entry(String.class.getTypeName(), new StringDeserializer()),
            Map.entry(AnalysisResult.class.getTypeName(), new KafkaProtobufDeserializer<>(AnalysisResult.parser())),
            Map.entry(Bom.class.getTypeName(), new KafkaProtobufDeserializer<>(Bom.parser())),
            Map.entry(ScanKey.class.getTypeName(), new KafkaProtobufDeserializer<>(ScanKey.parser())),
            Map.entry(ScanResult.class.getTypeName(), new KafkaProtobufDeserializer<>(ScanResult.parser()))
    );
    private static final Map<String, Serializer<?>> SERIALIZERS = Map.ofEntries(
            Map.entry(Void.TYPE.getTypeName(), new VoidSerializer()),
            Map.entry(String.class.getTypeName(), new StringSerializer()),
            Map.entry(AnalysisResult.class.getTypeName(), new KafkaProtobufSerializer<>()),
            Map.entry(Bom.class.getTypeName(), new KafkaProtobufSerializer<>()),
            Map.entry(ScanKey.class.getTypeName(), new KafkaProtobufSerializer<>()),
            Map.entry(ScanResult.class.getTypeName(), new KafkaProtobufSerializer<>())
    );

    private final Config config;

    public KafkaProcessorFactory() {
        this(Config.getInstance());
    }

    KafkaProcessorFactory(final Config config) {
        this.config = config;
    }

    public <CK, CV, PK, PV> KafkaProcessor createProcessor(final RecordProcessor<CK, CV, PK, PV> recordProcessor) {
        final ParallelStreamProcessor<byte[], byte[]> streamProcessor = createStreamProcessor(recordProcessor);
        final Map.Entry<Deserializer<CK>, Deserializer<CV>> keyValueDeserializers = keyValueDeserializers(recordProcessor.getClass());
        final Map.Entry<Serializer<PK>, Serializer<PV>> keyValueSerializers = keyValueSerializers(recordProcessor.getClass());
        return new KafkaProcessor(streamProcessor, new SingleRecordProcessingStrategy<>(recordProcessor,
                keyValueDeserializers.getKey(), keyValueDeserializers.getValue(),
                keyValueSerializers.getKey(), keyValueSerializers.getValue()));
    }

    public <CK, CV, PK, PV> KafkaProcessor createBatchProcessor(final RecordBatchProcessor<CK, CV, PK, PV> batchRecordProcessor) {
        return null;
    }

    public <K, V> KafkaProcessor createConsumer(final RecordConsumer<K, V> recordConsumer,
                                                final Deserializer<K> keyDeserializer, final Deserializer<V> valueDeserializer) {
        final ParallelStreamProcessor<byte[], byte[]> streamProcessor = createStreamProcessor(recordConsumer);
        final var recordPollingStrategy = new SingleRecordProcessingStrategy<>(recordConsumer,
                keyDeserializer, valueDeserializer, new VoidSerializer(), new VoidSerializer());
        return new KafkaProcessor(streamProcessor, recordPollingStrategy);
    }

    public <K, V> KafkaProcessor createBatchConsumer(final RecordBatchConsumer<K, V> batchRecordConsumer) {
        return null;
    }

    private ParallelStreamProcessor<byte[], byte[]> createStreamProcessor(final Object recordProcessor) {
        final var optionsBuilder = ParallelConsumerOptions.<byte[], byte[]>builder()
                .consumer(createConsumer());

        // TODO: How to best pass (customizable) configuration here?

        if (!isRecordConsumer(recordProcessor)) {
            optionsBuilder.producer(createProducer());
        }

        return ParallelStreamProcessor.createEosStreamProcessor(optionsBuilder.build());
    }

    private Consumer<byte[], byte[]> createConsumer() {
        final var consumerConfig = new HashMap<String, Object>();
        consumerConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        consumerConfig.put(CLIENT_ID_CONFIG, "foo-consumer");
        consumerConfig.put(GROUP_ID_CONFIG, "foo-consumer");
        consumerConfig.put(KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        consumerConfig.put(ENABLE_AUTO_COMMIT_CONFIG, false);

        final var psPropertyPrefix = "kafka.processor.%s.consumer".formatted("foo");
        final var psPropertyPrefixPattern = Pattern.compile(Pattern.quote("%s.".formatted(psPropertyPrefix)));
        final Map<String, String> psProperties = config.getPassThroughProperties(psPropertyPrefix);
        for (final Map.Entry<String, String> psProperty : psProperties.entrySet()) {
            final String propertyName = psPropertyPrefixPattern.matcher(psProperty.getKey()).replaceFirst("");
            if (!ConsumerConfig.configNames().contains(propertyName)) {
                LOGGER.warn("%s is not a known consumer config; Ignoring".formatted(propertyName));
                continue;
            }

            consumerConfig.put(propertyName, psProperty.getValue());
        }

        return new KafkaConsumer<>(consumerConfig);
    }

    private Producer<byte[], byte[]> createProducer() {
        final var producerConfig = new HashMap<String, Object>();
        producerConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        producerConfig.put(CLIENT_ID_CONFIG, "foo-producer");
        producerConfig.put(KEY_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        producerConfig.put(VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        producerConfig.put(ENABLE_IDEMPOTENCE_CONFIG, true);
        producerConfig.put(ACKS_CONFIG, "all");

        final var psPropertyPrefix = "kafka.processor.%s.producer".formatted("foo");
        final var psPropertyPrefixPattern = Pattern.compile(Pattern.quote("%s.".formatted(psPropertyPrefix)));
        final Map<String, String> psProperties = config.getPassThroughProperties(psPropertyPrefix);
        for (final Map.Entry<String, String> psProperty : psProperties.entrySet()) {
            final String propertyName = psPropertyPrefixPattern.matcher(psProperty.getKey()).replaceFirst("");
            if (!ProducerConfig.configNames().contains(propertyName)) {
                LOGGER.warn("%s is not a known producer config; Ignoring".formatted(propertyName));
                continue;
            }

            producerConfig.put(propertyName, psProperty.getValue());
        }

        return new KafkaProducer<>(producerConfig);
    }

    private static boolean isRecordConsumer(final Object object) {
        return RecordConsumer.class.isAssignableFrom(object.getClass())
                || RecordBatchConsumer.class.isAssignableFrom(object.getClass());
    }

    @SuppressWarnings("unchecked")
    private static <K, V> Map.Entry<Deserializer<K>, Deserializer<V>> keyValueDeserializers(final Type processorType) {
        final Map.Entry<Type, Type> keyValueTypes = consumerKeyValueTypes(processorType);
        return Map.entry(
                (Deserializer<K>) DESERIALIZERS.get(keyValueTypes.getKey().getTypeName()),
                (Deserializer<V>) DESERIALIZERS.get(keyValueTypes.getValue().getTypeName())
        );
    }

    @SuppressWarnings("unchecked")
    private static <K, V> Map.Entry<Serializer<K>, Serializer<V>> keyValueSerializers(final Type processorType) {
        final Map.Entry<Type, Type> keyValueTypes = producerKeyValueTypes(processorType);
        return Map.entry(
                (Serializer<K>) SERIALIZERS.get(keyValueTypes.getKey().getTypeName()),
                (Serializer<V>) SERIALIZERS.get(keyValueTypes.getValue().getTypeName())
        );
    }

    private static Map.Entry<Type, Type> consumerKeyValueTypes(final Type processorType) {
        if (!(processorType instanceof final ParameterizedType paramType)) {
            throw new IllegalArgumentException("");
        }
        if (paramType.getActualTypeArguments().length < 2) {
            throw new IllegalArgumentException();
        }

        return Map.entry(paramType.getActualTypeArguments()[0], paramType.getActualTypeArguments()[1]);
    }

    private static Map.Entry<Type, Type> producerKeyValueTypes(final Type type) {
        if (!(type instanceof final ParameterizedType paramType)) {
            throw new IllegalArgumentException("");
        }
        if (paramType.getActualTypeArguments().length < 4) {
            throw new IllegalArgumentException();
        }

        return Map.entry(paramType.getActualTypeArguments()[2], paramType.getActualTypeArguments()[3]);
    }

}
