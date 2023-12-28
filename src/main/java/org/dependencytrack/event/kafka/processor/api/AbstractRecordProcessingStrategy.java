package org.dependencytrack.event.kafka.processor.api;

import alpine.common.logging.Logger;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An abstract {@link RecordProcessingStrategy} that provides various shared functionality.
 *
 * @param <CK> Type of the {@link ConsumerRecord} key
 * @param <CV> Type of the {@link ConsumerRecord} value
 * @param <PK> Type of the {@link ProducerRecord} key
 * @param <PV> Type of the {@link ProducerRecord} value
 */
abstract class AbstractRecordProcessingStrategy<CK, CV, PK, PV> implements RecordProcessingStrategy {

    private final Deserializer<CK> keyDeserializer;
    private final Deserializer<CV> valueDeserializer;
    private final Serializer<PK> keySerializer;
    private final Serializer<PV> valueSerializer;
    private final Logger logger;

    AbstractRecordProcessingStrategy(final Deserializer<CK> keyDeserializer, final Deserializer<CV> valueDeserializer,
                                     final Serializer<PK> keySerializer, final Serializer<PV> valueSerializer) {
        this.keyDeserializer = keyDeserializer;
        this.valueDeserializer = valueDeserializer;
        this.keySerializer = keySerializer;
        this.valueSerializer = valueSerializer;
        this.logger = Logger.getLogger(getClass());
    }

    /**
     * @param record The {@link ConsumerRecord} to deserialize key and value of
     * @return A {@link ConsumerRecord} with deserialized key and value
     * @throws SerializationException When deserializing the {@link ConsumerRecord} failed
     */
    ConsumerRecord<CK, CV> deserialize(final ConsumerRecord<byte[], byte[]> record) {
        final CK deserializedKey;
        final CV deserializedValue;
        try {
            deserializedKey = keyDeserializer.deserialize(record.topic(), record.key());
            deserializedValue = valueDeserializer.deserialize(record.topic(), record.value());
        } catch (RuntimeException e) {
            if (e instanceof SerializationException) {
                throw e;
            }

            throw new SerializationException(e);
        }

        return new ConsumerRecord<>(record.topic(), record.partition(), record.offset(),
                record.timestamp(), record.timestampType(), record.serializedKeySize(), record.serializedValueSize(),
                deserializedKey, deserializedValue, record.headers(), record.leaderEpoch());
    }

    /**
     * @param record The {@link ProducerRecord} to serialize key and value of
     * @return A {@link ProducerRecord} with serialized key and value
     * @throws SerializationException When serializing the {@link ProducerRecord} failed
     */
    ProducerRecord<byte[], byte[]> serialize(final ProducerRecord<PK, PV> record) {
        final byte[] serializedKey;
        final byte[] serializedValue;
        try {
            serializedKey = keySerializer.serialize(record.topic(), record.key());
            serializedValue = valueSerializer.serialize(record.topic(), record.value());
        } catch (RuntimeException e) {
            if (e instanceof SerializationException) {
                throw e;
            }

            throw new SerializationException(e);
        }

        return new ProducerRecord<>(record.topic(), record.partition(), record.timestamp(),
                serializedKey, serializedValue, record.headers());
    }

    List<ProducerRecord<byte[], byte[]>> maybeSerializeAll(final List<ProducerRecord<PK, PV>> records) {
        if (records == null || records.isEmpty()) {
            return Collections.emptyList();
        }

        final var serializedRecords = new ArrayList<ProducerRecord<byte[], byte[]>>(records.size());
        for (final ProducerRecord<PK, PV> producerRecord : records) {
            try {
                serializedRecords.add(serialize(producerRecord));
            } catch (SerializationException e) {
                logger.warn("Failed to serialize producer record %s".formatted(producerRecord), e);
            }
        }

        return serializedRecords;
    }

}
